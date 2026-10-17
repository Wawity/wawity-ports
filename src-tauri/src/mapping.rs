use crate::{
    lease, now, router, save,
    udp::{self, Transport},
    Journal, RouterIntent,
};
use std::net::{Ipv4Addr, SocketAddrV4};

pub fn saved_method(intent: &RouterIntent) -> Option<&str> {
    intent
        .method
        .as_deref()
        .or_else(|| intent.gateway.as_ref().map(|_| "UPnP"))
}

pub fn open(
    id: &str,
    port: u16,
    proto: &str,
    journal: &mut Journal,
    allow_nat: bool,
) -> Result<String, String> {
    let previous = journal.get(id).cloned().unwrap_or_default();
    if previous.state == "conflict" && previous.gateway.is_none() {
        return Err("Saved foreign mapping conflict must be explicitly resolved; no protocol fallback or mutation.".into());
    }
       if previous.gateway.is_some() && saved_method(&previous).is_some() {
        return match saved_method(&previous).unwrap() {
            "UPnP" => router::open(&router::from_intent(&previous)?, id, port, proto, journal),
            "PCP" | "NAT-PMP" => {
                if saved_method(&previous) == Some("NAT-PMP") && !allow_nat {
                    return Err(udp::NAT_RISK.into());
                }
                if !previous.confirmed || previous.expires_at.is_none_or(|end| end <= now()) {
                    return Err("Saved UDP mapping is ambiguous or expired; no overwrite or method fallback. Close/resolve the saved intent first.".into());
                }
                renew(id, port, proto, journal)
            }
            _ => Err("Unknown saved method; no mutation or fallback.".into()),
        };
    }
    let lan = router::physical_lans()?
        .into_iter()
        .next()
        .ok_or("No physical LAN")?;
    let mut errors = Vec::new();
    match router::discover_on(lan.clone()) {
        Ok(gateway) => match router::open(&gateway, id, port, proto, journal) {
            Ok(note) => return Ok(note),
            Err(e) => {
                if journal
                    .get(id)
                    .is_some_and(|i| i.mutation_attempted || i.state == "conflict")
                {
                    return Err(e);
                }
                errors.push(format!("UPnP preflight: {e}"));
            }
        },
        Err(e) => errors.push(format!("UPnP discovery unconfirmed: {e}")),
    }
    let mut transport = udp::PhysicalTransport::new(&lan)?;
    let announce = udp::pcp_request(lan.local, None, 0, 0, 0, None, 0);
    match transport.exchange(&announce, true) {
        Ok(_) => {
            match udp_open(id, port, proto, journal, &lan, "PCP", &mut transport, save) {
                Ok(note) => return Ok(note),
                Err(error) => {
                    if journal.get(id).is_some_and(|i| i.mutation_attempted)
                        || error.starts_with("Cannot persist UDP mapping intent")
                    {
                        return Err(error);
                    }
                    errors.push(error);
                                                          journal.insert(id.into(), previous.clone());
                    save(journal)?;
                }
            }
        }
        Err(e) => errors.push(format!(
            "PCP ANNOUNCE unconfirmed (not a MAP capability test): {e}"
        )),
    }
    if allow_nat {
        match transport.exchange(&[0, 0], false) {
            Ok(_) => {
                return udp_open(
                    id,
                    port,
                    proto,
                    journal,
                    &lan,
                    "NAT-PMP",
                    &mut transport,
                    save,
                )
            }
            Err(e) => errors.push(format!("NAT-PMP address discovery unconfirmed: {e}")),
        }
    } else {
        errors.push(format!(
            "NAT-PMP skipped without explicit consent. {}",
            udp::NAT_RISK
        ));
    }
    Err(errors.join("\n"))
}

#[allow(clippy::too_many_arguments)]
fn udp_open(
    id: &str,
    port: u16,
    proto: &str,
    journal: &mut Journal,
    lan: &router::Lan,
    method: &str,
    transport: &mut impl Transport,
    persist: impl Fn(&Journal) -> Result<(), String>,
) -> Result<String, String> {
    let previous = journal.get(id).cloned();
    let settings = previous.clone().unwrap_or_default();
    udp::protocol(proto)?;
    let mut nonce = [0; 12];
    if method == "PCP" {
        getrandom::getrandom(&mut nonce)
            .map_err(|e| format!("Cryptographic PCP nonce unavailable: {e}"))?;
    }
    let address = if method == "NAT-PMP" {
        if !settings.allow_nat_pmp {
            return Err(udp::NAT_RISK.into());
        }
        Some(
            transport
                .exchange(&[0, 0], false)?
                .external_ip
                .ok_or("Missing NAT-PMP external address")?
                .to_string(),
        )
    } else {
        None
    };
    let intent = RouterIntent {
        gateway: Some(SocketAddrV4::new(lan.gateway, 5351).to_string()),
        local_ip: Some(lan.local.to_string()),
        interface_index: Some(lan.index),
        method: Some(method.into()),
        nonce: if method == "PCP" { Some(nonce) } else { None },
        internal_port: Some(port),
        external_port: Some(port),
        protocol: Some(proto.into()),
        external_ip: address,
        state: "unverified".into(),
        mutation_attempted: true,
        auto_renew: settings.auto_renew,
        allow_nat_pmp: settings.allow_nat_pmp,
        renewal_state: if settings.auto_renew { "paused" } else { "off" }.into(),
        extra: settings.extra,
        ..RouterIntent::default()
    };
    journal.insert(id.into(), intent);
       if let Err(error) = persist(journal) {
        if let Some(previous) = previous {
            journal.insert(id.into(), previous);
        } else {
            journal.remove(id);
        }
        return Err(format!(
            "Cannot persist UDP mapping intent; no MAP sent: {error}"
        ));
    }
    udp_map(id, port, proto, journal, lan, transport, &persist, false)
}

fn tuple(
    intent: &RouterIntent,
    port: u16,
    proto: &str,
    lan: &router::Lan,
) -> Result<(u16, Option<Ipv4Addr>), String> {
    if intent.gateway.as_deref() != Some(SocketAddrV4::new(lan.gateway, 5351).to_string().as_str())
        || intent.local_ip.as_deref() != Some(lan.local.to_string().as_str())
        || intent.interface_index != Some(lan.index)
        || intent.internal_port != Some(port)
        || intent.protocol.as_deref() != Some(proto)
    {
        return Err("Saved UDP tuple differs from current exact physical IP/interface/gateway/port/protocol; left unchanged.".into());
    }
    let external = intent
        .external_port
        .filter(|p| *p != 0)
        .ok_or("Missing granted external port")?;
    let ip = intent
        .external_ip
        .as_deref()
        .map(|ip| {
            ip.parse::<Ipv4Addr>()
                .map_err(|_| "Invalid saved external IPv4")
        })
        .transpose()?;
    if saved_method(intent) == Some("PCP") && intent.nonce.is_none() {
        return Err("Missing persisted PCP ownership nonce".into());
    }
    if saved_method(intent) == Some("NAT-PMP") && !intent.allow_nat_pmp {
        return Err(udp::NAT_RISK.into());
    }
    Ok((external, ip))
}

#[allow(clippy::too_many_arguments)]
fn udp_map(
    id: &str,
    port: u16,
    proto: &str,
    journal: &mut Journal,
    lan: &router::Lan,
    transport: &mut impl Transport,
    persist: &impl Fn(&Journal) -> Result<(), String>,
    renewing: bool,
) -> Result<String, String> {
    let old = journal.get(id).ok_or("Missing lease intent")?.clone();
    if !renewing && saved_method(&old) == Some("NAT-PMP") && !old.allow_nat_pmp {
        return Err(udp::NAT_RISK.into());
    }
    let pcp = saved_method(&old) == Some("PCP");
    let (external, ip) = tuple(&old, port, proto, lan)?;
    if renewing && external != port {
        return Err("Remapped lease is cleanup-only; cannot renew".into());
    }
    let request = if pcp {
        udp::pcp_request(
            lan.local,
            old.nonce,
            udp::protocol(proto)?,
            port,
            external,
            ip,
            udp::LIFETIME,
        )
    } else {
        udp::nat_request(udp::protocol(proto)?, port, external, udp::LIFETIME)
    };
    let started = now();
       if renewing {
        persist(journal)?;
    }
    if renewing && old.expires_at.is_none_or(|end| end <= now()) {
        return Err("Known lease expired during preflight/save; not recreated.".into());
    }
    let reply = match transport.exchange(&request, pcp) {
        Ok(reply) => reply,
        Err(error) => {
            let entry = journal.get_mut(id).unwrap();
            entry.last_error = Some(error.clone());
            if !renewing
                && [
                    "PCP error 1 (",
                    "PCP error 4 (",
                    "PCP error 5 (",
                    "PCP error 9 (",
                ]
                .iter()
                .any(|prefix| error.starts_with(prefix))
            {
                               entry.mutation_attempted = false;
                entry.state = "failed".into();
                persist(journal)?;
            }
            return Err(error);
        }
    };
    let intent = journal.get_mut(id).unwrap();
    intent.external_port = Some(reply.external_port);
    if let Some(ip) = reply.external_ip {
        intent.external_ip = Some(ip.to_string());
    }
    intent.granted_at = Some(started);
    intent.granted_lifetime = Some(reply.lifetime);
    intent.epoch = Some(reply.epoch);
    intent.epoch_received_at = Some(now());
    intent.expires_at = if reply.lifetime > 0 {
        Some(started.saturating_add(u64::from(reply.lifetime)))
    } else {
        None
    };
    intent.confirmed = false;
    intent.state = "unverified".into();
       persist(journal)?;
    udp::validate_grant(&reply, port, if renewing { ip } else { None }, false)?;
    if renewing
        && !udp::epoch_valid(
            old.epoch.ok_or("Missing saved epoch")?,
            reply.epoch,
            now().saturating_sub(
                old.epoch_received_at
                    .or(old.granted_at)
                    .ok_or("Missing grant time")?,
            ),
        )
    {
        return Err(
            "Gateway epoch changed during renewal; mapping unverified, automatic renewal paused."
                .into(),
        );
    }
    let intent = journal.get_mut(id).unwrap();
    lease::grant(intent, started, reply.lifetime);
    intent.state = "mapped".into();
    persist(journal)?;
    Ok(format!("{} mapped to {}:{port}; exact external port {}; finite granted lease {} seconds, expires at {}. Journal is not read-only inspection or Internet reachability proof.{}",if pcp {"PCP"} else {"NAT-PMP"},lan.local,reply.external_port,reply.lifetime,intent_expiry(journal,id),if pcp {""} else {udp::NAT_RISK}))
}

fn intent_expiry(journal: &Journal, id: &str) -> u64 {
    journal[id].expires_at.unwrap_or_default()
}

pub fn renew(id: &str, port: u16, proto: &str, journal: &mut Journal) -> Result<String, String> {
    let intent = journal.get(id).ok_or("Missing saved intent")?.clone();
    if !intent.confirmed || intent.expires_at.is_none_or(|end| end <= now()) {
        return Err("Lease expired or ownership grant unconfirmed; not recreated.".into());
    }
    if !matches!(saved_method(&intent), Some("UPnP" | "PCP" | "NAT-PMP")) {
        return Err("Unknown saved method; no renewal mutation.".into());
    }
    if saved_method(&intent) == Some("UPnP") {
        return router::renew(id, port, proto, journal);
    }
    let lan = router::physical_lan_for_intent(&intent)?;
    tuple(&intent, port, proto, &lan)?;
    let mut transport =
        udp::PhysicalTransport::new(&lan)?.before_expiry(intent.expires_at.unwrap());
    preflight_epoch(&intent, &lan, &mut transport)?;
    udp_map(id, port, proto, journal, &lan, &mut transport, &save, true)
}

fn preflight_epoch(
    intent: &RouterIntent,
    lan: &router::Lan,
    transport: &mut impl Transport,
) -> Result<(), String> {
    let pcp = saved_method(intent) == Some("PCP");
    let request = if pcp {
        udp::pcp_request(lan.local, None, 0, 0, 0, None, 0)
    } else {
        vec![0, 0]
    };
    let reply = transport.exchange(&request, pcp)?;
    let previous = intent
        .epoch
        .ok_or("Missing saved gateway epoch; no safe renewal/deletion")?;
    let granted = intent
        .epoch_received_at
        .or(intent.granted_at)
        .ok_or("Missing saved grant time")?;
    let current = now();
    if current < granted || !udp::epoch_valid(previous, reply.epoch, current - granted) {
        return Err(
            "Gateway reboot/epoch or client clock discontinuity; paused, not recreated or deleted."
                .into(),
        );
    }
    if !pcp
        && intent.external_ip.is_some()
        && intent.external_ip.as_deref() != reply.external_ip.map(|ip| ip.to_string()).as_deref()
    {
        return Err(
            "NAT-PMP external address changed; tuple may have been reassigned, left unchanged."
                .into(),
        );
    }
    Ok(())
}

pub fn close(id: &str, port: u16, proto: &str, intent: &RouterIntent) -> Result<String, String> {
    match saved_method(intent) {
        Some("PCP") | Some("NAT-PMP") => {
            let lan = router::physical_lan_for_intent(intent)?;
            tuple(intent, port, proto, &lan)?;
            let mut transport = udp::PhysicalTransport::new(&lan)?;
            if saved_method(intent) == Some("NAT-PMP") {
                transport = transport.before_expiry(
                    intent
                        .expires_at
                        .ok_or("Unknown NAT-PMP lease deadline; not deleted")?,
                );
            }
            udp_close(port, proto, intent, &lan, &mut transport)
        }
        Some("UPnP") | None => router::close(id, port, proto, intent),
        _ => Err("Unknown mapping method; left unchanged.".into()),
    }
}

fn udp_close(
    port: u16,
    proto: &str,
    intent: &RouterIntent,
    lan: &router::Lan,
    transport: &mut impl Transport,
) -> Result<String, String> {
    let (external, ip) = tuple(intent, port, proto, lan)?;
    let pcp = saved_method(intent) == Some("PCP");
    if !matches!(saved_method(intent), Some("PCP" | "NAT-PMP")) {
        return Err("Unknown saved UDP method; no deletion.".into());
    }
    if !pcp {
        if intent.granted_at.is_none()
            || intent.expires_at.is_none_or(|end| end <= now())
            || intent.granted_lifetime.is_none_or(|l| l == 0 || l > 3600)
        {
            return Err("NAT-PMP grant unknown/expired/invalid: cannot inspect ownership; refusing destructive delete of a possibly unrelated mapping. Intent retained.".into());
        }
        preflight_epoch(intent, lan, transport)?;
    }
    let request = if pcp {
        udp::pcp_request(
            lan.local,
            intent.nonce,
            udp::protocol(proto)?,
            port,
            external,
            ip,
            0,
        )
    } else {
        udp::nat_request(udp::protocol(proto)?, port, external, 0)
    };
    let reply = transport.exchange(&request, pcp)?;
    udp::validate_grant(&reply, external, ip, true)?;
    Ok(format!("{port}/{proto}: {} saved internal tuple deletion acknowledged; not a read-only absence check.{}",saved_method(intent).unwrap(),if pcp {""} else {udp::NAT_RISK}))
}

pub fn inspect(id: &str, port: u16, proto: &str, intent: &RouterIntent) -> Result<String, String> {
    match saved_method(intent) {
        Some("PCP") | Some("NAT-PMP") => Ok(format!("{port}/{proto}: {} lease journal only, unverified; gateway {:?}, internal {:?}, granted external port {:?}, expiry {:?}. No safe read-only mapping inspection; MAP lifetime=0 is deletion, never a diagnostic.{}",saved_method(intent).unwrap(),intent.gateway,intent.local_ip,intent.external_port,intent.expires_at,if saved_method(intent)==Some("NAT-PMP") {udp::NAT_RISK} else {""})),
        Some("UPnP")|None => router::inspect(id,port,proto,intent),
        _=>Err("Unknown saved mapping method; no diagnostic mutation or assumption.".into()),
    }
}

pub struct CheckRouter {
    pub lan: router::Lan,
    upnp: Option<router::Router>,
    method: String,
}

pub fn check_router(intent: Option<&RouterIntent>) -> Result<CheckRouter, String> {
    if let Some(intent) = intent {
        if !matches!(
            saved_method(intent),
            Some("UPnP" | "PCP" | "NAT-PMP") | None
        ) {
            return Err("Unknown saved mapping method; no external-address assumption.".into());
        }
        if matches!(saved_method(intent), Some("PCP" | "NAT-PMP")) {
            return Ok(CheckRouter {
                lan: router::physical_lan_for_intent(intent)?,
                upnp: None,
                method: saved_method(intent).unwrap().into(),
            });
        }
    }
    let upnp = match intent {
        Some(intent) => router::from_intent(intent)?,
        None => {
            let lan = router::physical_lans()?
                .into_iter()
                .next()
                .ok_or("No physical LAN")?;
            router::verify_route(&lan)?;
            match router::discover_on(lan.clone()) {
                Ok(router) => router,
                Err(_) => {
                    return Ok(CheckRouter {
                        lan,
                        upnp: None,
                        method: "NAT-PMP".into(),
                    })
                }
            }
        }
    };
    Ok(CheckRouter {
        lan: upnp.lan.clone(),
        upnp: Some(upnp),
        method: "UPnP".into(),
    })
}

pub fn external_ip(context: &CheckRouter) -> Result<Ipv4Addr, String> {
    if let Some(upnp) = &context.upnp {
        return router::external_ip(upnp);
    }
    if context.method == "NAT-PMP" {
        let mut transport = udp::PhysicalTransport::new(&context.lan)?;
        return transport
            .exchange(&[0, 0], false)?
            .external_ip
            .ok_or("Missing fresh NAT-PMP external address".into());
    }
    Err("PCP has no read-only fresh external-address API; saved MAP address is stale evidence, external probe skipped (no diagnostic MAP sent).".into())
}

#[cfg(test)]
#[path = "mapping_tests.rs"]
mod tests;
