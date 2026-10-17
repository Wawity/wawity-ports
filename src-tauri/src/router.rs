use crate::{now, powershell, save, Journal, RouterIntent};
use igd::Gateway;
use reqwest::{blocking::Client, Url};
use serde::Deserialize;
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    collections::HashMap,
    io::Read,
    net::{IpAddr, Ipv4Addr, SocketAddrV4, UdpSocket},
    time::{Duration, Instant},
};
use xmltree::Element;

#[derive(Clone, Debug, Deserialize)]
pub struct Lan {
    pub local: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub index: u32,
    prefix: u8,
}

pub struct Router {
    pub gateway: Gateway,
    pub lan: Lan,
    service: String,
    client: Client,
}

pub(crate) fn network_allowed() -> Result<(), String> {
    if cfg!(test) || std::env::var_os("WAWITY_PORTS_TEST_MODE").is_some() {
        Err("Router network operations disabled in test mode.".into())
    } else {
        Ok(())
    }
}

fn validate_lan(lan: &Lan) -> Result<(), String> {
    if !lan.gateway.is_private()
        || !lan.local.is_private()
        || lan.index == 0
        || !(1..=30).contains(&lan.prefix)
        || lan.local == lan.gateway
    {
        return Err("No safe private IPv4 physical LAN gateway/address pair.".into());
    }
    let mask = u32::MAX << (32 - lan.prefix);
    if u32::from(lan.local) & mask != u32::from(lan.gateway) & mask {
        return Err("Physical gateway is not on the local subnet.".into());
    }
    Ok(())
}

pub(crate) fn physical_lans() -> Result<Vec<Lan>, String> {
    network_allowed()?;
    let json = powershell(
        r#"$items=@(Get-NetAdapter -Physical | Where-Object Status -eq 'Up' | Sort-Object ifIndex | ForEach-Object {
      $index=$_.ifIndex; $c=Get-NetIPConfiguration -InterfaceIndex $index;
      foreach ($g in $c.IPv4DefaultGateway) { foreach ($a in @(Get-NetIPAddress -InterfaceIndex $index -AddressFamily IPv4 | Where-Object { $_.AddressState -eq 'Preferred' -and -not $_.SkipAsSource })) {
        [pscustomobject]@{ local=$a.IPAddress; gateway=$g.NextHop; index=$index; prefix=$a.PrefixLength }
      } }
    }); ConvertTo-Json -InputObject $items -Compress"#,
    )?;
    let mut lans: Vec<Lan> =
        serde_json::from_str(&json).map_err(|e| format!("Physical adapter detection: {e}"))?;
    lans.retain(|lan| validate_lan(lan).is_ok());
    if lans.is_empty() {
        return Err("No physical adapter with a private on-link IPv4 gateway. Refusing VPN/default-interface fallback.".into());
    }
    Ok(lans)
}

pub(crate) fn verify_route(lan: &Lan) -> Result<(), String> {
    validate_lan(lan)?;
    let output = powershell(&format!("$a=@(Get-NetAdapter -Physical | Where-Object {{ $_.ifIndex -eq {} -and $_.Status -eq 'Up' }}); if ($a.Count -ne 1) {{ throw 'Selected physical adapter is no longer up.' }}; $r=@(Find-NetRoute -RemoteIPAddress '{}' -LocalIPAddress '{}'); if ($r.Count -eq 0 -or @($r | Where-Object {{ $_.InterfaceIndex -ne {} }}).Count -gt 0) {{ throw 'Gateway route is not through the selected physical LAN; no VPN fallback.' }}; 'OK'", lan.index, lan.gateway, lan.local, lan.index))?;
    if output != "OK" {
        return Err("Cannot verify physical gateway route.".into());
    }
    Ok(())
}

fn client(lan: &Lan) -> Result<Client, String> {
    Client::builder()
        .local_address(IpAddr::V4(lan.local))
        .no_proxy()
        .timeout(Duration::from_secs(6))
        .connect_timeout(Duration::from_secs(3))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| e.to_string())
}

fn endpoint(base: &Url, value: &str, gateway: Ipv4Addr) -> Result<Url, String> {
    if value.is_empty() || value.contains('\\') || value.chars().any(char::is_control) {
        return Err("Unsafe or empty router endpoint.".into());
    }
    let url = base.join(value).map_err(|e| e.to_string())?;
    if url.scheme() != "http"
        || url.host_str() != Some(gateway.to_string().as_str())
        || !gateway.is_private()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.port_or_known_default() != base.port_or_known_default()
        || url.port_or_known_default() == Some(0)
    {
        return Err("Router endpoint must stay on the verified private gateway and port.".into());
    }
    Ok(url)
}

fn bounded_text(mut response: reqwest::blocking::Response) -> Result<String, String> {
    let mut bytes = Vec::new();
    response
        .by_ref()
        .take(262_145)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > 262_144 {
        return Err("Router/API response exceeded 256 KiB.".into());
    }
    String::from_utf8(bytes).map_err(|e| e.to_string())
}

pub fn response_text(response: reqwest::blocking::Response) -> Result<String, String> {
    bounded_text(response)
}

fn fetch(client: &Client, url: &Url, lan: &Lan) -> Result<String, String> {
    network_allowed()?;
    verify_route(lan)?;
    let response = client.get(url.clone()).send().map_err(|e| e.to_string())?;
    if !response.status().is_success() {
        return Err(format!(
            "Router descriptor HTTP {}; redirects refused",
            response.status()
        ));
    }
    bounded_text(response)
}

fn supported(service: &str) -> bool {
    matches!(
        service,
        "urn:schemas-upnp-org:service:WANIPConnection:1"
            | "urn:schemas-upnp-org:service:WANIPConnection:2"
            | "urn:schemas-upnp-org:service:WANPPPConnection:1"
            | "urn:schemas-upnp-org:service:WANPPPConnection:2"
    )
}

fn descriptor(xml: &str, location: &Url, ip: Ipv4Addr) -> Result<(String, Url, Url), String> {
    let root = Element::parse(xml.as_bytes()).map_err(|e| e.to_string())?;
    let base = match root.get_child("URLBase").and_then(Element::get_text) {
        Some(value) => endpoint(location, value.trim(), ip)?,
        None => location.clone(),
    };
    fn service(element: &Element) -> Option<&Element> {
        if element.name == "service"
            && element
                .get_child("serviceType")
                .and_then(Element::get_text)
                .is_some_and(|s| supported(s.trim()))
        {
            return Some(element);
        }
        element
            .children
            .iter()
            .filter_map(|c| c.as_element())
            .find_map(service)
    }
    let service = service(&root).ok_or("No supported WANIP/WANPPP service v1/v2")?;
    Ok((
        text(service, "serviceType")?.trim().into(),
        endpoint(&base, text(service, "controlURL")?.trim(), ip)?,
        endpoint(&base, text(service, "SCPDURL")?.trim(), ip)?,
    ))
}

fn schema(xml: &str) -> Result<HashMap<String, Vec<String>>, String> {
    let root = Element::parse(xml.as_bytes()).map_err(|e| e.to_string())?;
    let list = find(&root, "actionList").ok_or("Missing actionList")?;
    let mut schema = HashMap::new();
    for action in list
        .children
        .iter()
        .filter_map(|c| c.as_element())
        .filter(|e| e.name == "action")
    {
        let name = text(action, "name")?;
        let mut inputs = Vec::new();
        if let Some(list) = action.get_child("argumentList") {
            for arg in list
                .children
                .iter()
                .filter_map(|c| c.as_element())
                .filter(|e| e.name == "argument")
            {
                if text(arg, "direction")?.trim() == "in" {
                    inputs.push(text(arg, "name")?);
                }
            }
        }
        schema.insert(name, inputs);
    }
    if !schema.contains_key("GetSpecificPortMappingEntry") {
        return Err("Router cannot verify specific mapping ownership.".into());
    }
    Ok(schema)
}

fn ssdp_location(reply: &str, ip: Ipv4Addr) -> Result<Url, String> {
    if !reply
        .lines()
        .next()
        .is_some_and(|s| s.starts_with("HTTP/1.1 200"))
    {
        return Err("Invalid SSDP response".into());
    }
    let value = reply
        .lines()
        .filter_map(|l| l.split_once(':'))
        .find(|(key, _)| key.trim().eq_ignore_ascii_case("location"))
        .map(|(_, v)| v.trim())
        .ok_or("Missing SSDP LOCATION")?;
       let url = Url::parse(value).map_err(|e| e.to_string())?;
    let origin = Url::parse(&format!(
        "http://{}:{}/",
        ip,
        url.port_or_known_default().ok_or("Missing port")?
    ))
    .map_err(|e| e.to_string())?;
    endpoint(&origin, value, ip)
}

pub(crate) fn discover_on(lan: Lan) -> Result<Router, String> {
    verify_route(&lan)?;
    let socket =
        Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).map_err(|e| e.to_string())?;
    socket
        .bind(&SocketAddrV4::new(lan.local, 0).into())
        .map_err(|e| e.to_string())?;
       socket
        .set_multicast_if_v4(&lan.local)
        .map_err(|e| format!("IP_MULTICAST_IF failed: {e}"))?;
    socket.set_multicast_ttl_v4(2).map_err(|e| e.to_string())?;
    let socket: UdpSocket = socket.into();
    let request = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n";
    socket
        .send_to(request.as_bytes(), "239.255.255.250:1900")
        .map_err(|e| e.to_string())?;
    let deadline = Instant::now() + Duration::from_secs(4);
    let mut buffer = [0; 8192];
    let mut location = None;
    for _ in 0..64 {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        socket
            .set_read_timeout(Some(remaining))
            .map_err(|e| e.to_string())?;
        match socket.recv_from(&mut buffer) {
            Ok((len, from)) if from.ip() == IpAddr::V4(lan.gateway) => {
                if let Ok(url) =
                    ssdp_location(&String::from_utf8_lossy(&buffer[..len]), lan.gateway)
                {
                    location = Some(url);
                    break;
                }
            }
            Ok(_) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                break
            }
            Err(e) => return Err(e.to_string()),
        }
    }
    let location = location.ok_or_else(|| format!("No SSDP router reply on physical {} (index {}, gateway {}). No VPN fallback; UPnP, LAN filtering or a kill switch may block access. Router state could not be inspected or changed.", lan.local, lan.index, lan.gateway))?;
    let client = client(&lan)?;
    let (service, control, scpd) =
        descriptor(&fetch(&client, &location, &lan)?, &location, lan.gateway)?;
    let control_schema = schema(&fetch(&client, &scpd, &lan)?)?;
    Ok(Router {
        gateway: Gateway {
            addr: SocketAddrV4::new(lan.gateway, location.port_or_known_default().unwrap()),
            root_url: location.to_string(),
            control_url: control.to_string(),
            control_schema_url: scpd.to_string(),
            control_schema,
        },
        lan,
        service,
        client,
    })
}

fn cached_for_lan(intent: &RouterIntent, lan: &Lan) -> Result<Option<Gateway>, String> {
    validate_lan(lan)?;
    let addr: SocketAddrV4 = intent
        .gateway
        .as_deref()
        .ok_or("Missing saved gateway")?
        .parse()
        .map_err(|_| "Invalid saved gateway")?;
    if *addr.ip() != lan.gateway
        || intent.local_ip.as_deref() != Some(lan.local.to_string().as_str())
    {
        return Err(
            "Saved gateway/local address does not match the current physical LAN; left unchanged."
                .into(),
        );
    }
    let fields = [
        intent.root_url.is_some(),
        intent.control_url.is_some(),
        intent.control_schema_url.is_some(),
        intent.control_schema.is_some(),
        intent.service_type.is_some(),
    ];
    if fields.iter().all(|v| !v) {
        return Ok(None);
    } 
    if fields.iter().any(|v| !v) {
        return Err("Incomplete cached router endpoint; refusing unsafe fallback.".into());
    }
    if !supported(intent.service_type.as_deref().unwrap()) {
        return Err("Unsupported cached serviceType".into());
    }
    let base = Url::parse(&format!("http://{addr}/")).map_err(|e| e.to_string())?;
    let root = endpoint(&base, intent.root_url.as_deref().unwrap(), lan.gateway)?;
    let control = endpoint(&root, intent.control_url.as_deref().unwrap(), lan.gateway)?;
    let scpd = endpoint(
        &root,
        intent.control_schema_url.as_deref().unwrap(),
        lan.gateway,
    )?;
    let schema = intent.control_schema.clone().unwrap();
    if !schema.contains_key("GetSpecificPortMappingEntry") {
        return Err("Cached schema lacks ownership query.".into());
    }
    Ok(Some(Gateway {
        addr,
        root_url: root.to_string(),
        control_url: control.to_string(),
        control_schema_url: scpd.to_string(),
        control_schema: schema,
    }))
}

pub fn from_intent(intent: &RouterIntent) -> Result<Router, String> {
    let lan = physical_lan_for_intent(intent)?;
    let cached = cached_for_lan(intent, &lan)?;
    verify_route(&lan)?;
    if let Some(gateway) = cached {
        return Ok(Router {
            gateway,
            service: intent.service_type.clone().unwrap(),
            client: client(&lan)?,
            lan,
        });
    }
    let router = discover_on(lan.clone())?;
    if Some(router.gateway.addr.to_string().as_str()) != intent.gateway.as_deref()
        || router.lan.local != lan.local
    {
        return Err("Discovered gateway differs from saved gateway; left unchanged.".into());
    }
    Ok(router)
}

pub(crate) fn physical_lan_for_intent(intent: &RouterIntent) -> Result<Lan, String> {
    let lan = physical_lans()?
        .into_iter()
        .find(|lan| {
            intent.local_ip.as_deref() == Some(lan.local.to_string().as_str())
                && intent
                    .gateway
                    .as_deref()
                    .and_then(|s| s.parse::<SocketAddrV4>().ok())
                    .is_some_and(|a| *a.ip() == lan.gateway)
        })
        .ok_or("Saved router is not on the current physical LAN; no VPN fallback.")?;
    if intent
        .interface_index
        .is_some_and(|index| index != lan.index)
    {
        return Err("Saved physical interface changed; left unchanged.".into());
    }
    verify_route(&lan)?;
    Ok(lan)
}

fn find<'a>(element: &'a Element, name: &str) -> Option<&'a Element> {
    if element.name == name {
        return Some(element);
    }
    element
        .children
        .iter()
        .filter_map(|c| c.as_element())
        .find_map(|c| find(c, name))
}
fn text(element: &Element, name: &str) -> Result<String, String> {
    find(element, name)
        .and_then(|e| e.get_text())
        .map(|s| s.to_string())
        .ok_or_else(|| format!("Router response missing {name}"))
}

struct Mapping {
    ip: Ipv4Addr,
    port: u16,
    description: String,
    lease: u32,
    enabled: bool,
}

fn soap(router: &Router, action: &str, arguments: &str) -> Result<Option<Element>, String> {
    soap_before(router, action, arguments, None)
}

fn soap_before(
    router: &Router,
    action: &str,
    arguments: &str,
    deadline: Option<u64>,
) -> Result<Option<Element>, String> {
    network_allowed()?;
    verify_route(&router.lan)?;
    if deadline.is_some_and(|end| end <= now()) {
        return Err("Known lease deadline reached before UPnP mutation; not recreated.".into());
    }
    let gateway = &router.gateway;
    let service = &router.service;
    if !gateway.control_schema.contains_key(action) {
        return Err(format!(
            "Router does not support {action}; refusing mutation without verification."
        ));
    }
    let body = format!(
        r#"<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:{action} xmlns:u="{service}">{arguments}</u:{action}></s:Body></s:Envelope>"#
    );
    let base = Url::parse(&format!("http://{}/", gateway.addr)).map_err(|e| e.to_string())?;
    let url = endpoint(&base, &gateway.control_url, router.lan.gateway)?;
    let response = router
        .client
        .post(url)
        .header("SOAPAction", format!("\"{service}#{action}\""))
        .header("Content-Type", "text/xml; charset=utf-8")
        .body(body)
        .send()
        .map_err(|e| format!("{action}: {e}; outcome may be unconfirmed"))?;
    let success = response.status().is_success();
    if response.status().is_redirection() {
        return Err(format!(
            "{action}: router redirect refused; outcome may be unconfirmed"
        ));
    }
    let xml =
        bounded_text(response).map_err(|e| format!("{action}: {e}; outcome may be unconfirmed"))?;
    parse_response(&xml, success, action)
}

fn parse_response(xml: &str, success: bool, action: &str) -> Result<Option<Element>, String> {
    let root = Element::parse(xml.as_bytes()).map_err(|e| format!("Invalid router XML: {e}"))?;
    if let Some(fault) = find(&root, "Fault") {
        let code = text(fault, "errorCode")?;
        if code == "714" && action == "GetSpecificPortMappingEntry" {
            return Ok(None);
        }
        if code == "725" {
            return Err(
                "Router supports only permanent leases; refused (no infinite-lease retry).".into(),
            );
        }
        return Err(format!("{action} rejected by router (UPnP {code})"));
    }
    if !success {
        return Err(format!("{action}: HTTP failure"));
    }
    find(&root, &format!("{action}Response"))
        .cloned()
        .map(Some)
        .ok_or_else(|| format!("Missing {action} response"))
}

fn mapping_arguments(port: u16, proto: &str) -> String {
             format!("<NewExternalPort>{port}</NewExternalPort><NewProtocol>{proto}</NewProtocol>")
}

fn add_arguments(port: u16, proto: &str, local: Ipv4Addr, id: &str) -> Result<String, String> {
    let (id_port, id_proto) = crate::ports::parse_id(id)?;
    if id_port != port || id_proto != proto {
        return Err("Mapping id does not match requested port/protocol".into());
    }
    Ok(format!("{}<NewInternalPort>{port}</NewInternalPort><NewInternalClient>{local}</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>{id}</NewPortMappingDescription><NewLeaseDuration>3600</NewLeaseDuration>", mapping_arguments(port, proto)))
}

fn verified_lease(entry: &Mapping) -> Result<u32, String> {
    if entry.lease == 0 || entry.lease > 3600 {
        return Err(format!("Router reported lease {} seconds (0 means permanent); expiry is not confirmed. Owned mapping retained for explicit close.", entry.lease));
    }
    Ok(entry.lease)
}

fn specific(gateway: &Router, port: u16, protocol: &str) -> Result<Option<Mapping>, String> {
    let Some(entry) = soap(
        gateway,
        "GetSpecificPortMappingEntry",
        &mapping_arguments(port, protocol),
    )?
    else {
        return Ok(None);
    };
    Ok(Some(Mapping {
        ip: text(&entry, "NewInternalClient")?
            .parse()
            .map_err(|_| "Invalid internal IP")?,
        port: text(&entry, "NewInternalPort")?
            .parse()
            .map_err(|_| "Invalid internal port")?,
        description: text(&entry, "NewPortMappingDescription")?,
        lease: text(&entry, "NewLeaseDuration")?
            .parse()
            .map_err(|_| "Invalid mapping lease duration")?,
        enabled: match text(&entry, "NewEnabled")?.trim() {
            "1" | "true" => true,
            "0" | "false" => false,
            _ => return Err("Invalid mapping enabled state".into()),
        },
    }))
}

fn owned(entry: &Mapping, id: &str, port: u16, local: Ipv4Addr) -> bool {
    entry.description == id && entry.port == port && entry.ip == local
}

pub fn open(
    gateway: &Router,
    id: &str,
    port: u16,
    proto: &str,
    journal: &mut Journal,
) -> Result<String, String> {
    verify_route(&gateway.lan)?;
    let local = gateway.lan.local;
    let renewing = journal
        .get(id)
        .is_some_and(|intent| intent.renewal_state == "retry");
    let current = specific(gateway, port, proto)?;
    if renewing
        && current.as_ref().is_none_or(|entry| {
            !entry.enabled || !owned(entry, id, port, local) || verified_lease(entry).is_err()
        })
    {
        return Err(
            "Owned finite UPnP mapping absent, altered or disabled during renewal; not recreated."
                .into(),
        );
    }
    if let Some(entry) = current {
        if !owned(&entry, id, port, local) {
            if let Some(intent) = journal.get_mut(id) {
                intent.state = "conflict".into();
            }
            return Err("An existing foreign mapping occupies this port; left unchanged.".into());
        }
        if let Some(intent) = journal.get_mut(id) {
                                  intent.mutation_attempted = true;
            intent.gateway = Some(gateway.gateway.addr.to_string());
            intent.local_ip = Some(local.to_string());
            intent.method = Some("UPnP".into());
            intent.interface_index = Some(gateway.lan.index);
            intent.control_url = Some(gateway.gateway.control_url.clone());
            intent.root_url = Some(gateway.gateway.root_url.clone());
            intent.control_schema_url = Some(gateway.gateway.control_schema_url.clone());
            intent.control_schema = Some(gateway.gateway.control_schema.clone());
            intent.service_type = Some(gateway.service.clone());
        }
        save(journal)?;
    }
    if !gateway
        .gateway
        .control_schema
        .contains_key("AddPortMapping")
    {
        return Err("Router does not support AddPortMapping.".into());
    }
    let response =
        soap(gateway, "GetExternalIPAddress", "")?.ok_or("Missing external IP response")?;
    let external: Ipv4Addr = text(&response, "NewExternalIPAddress")?
        .parse()
        .map_err(|_| "Invalid external IP")?;
    let previous = journal.get(id).cloned().unwrap_or_default();
    if previous.renewal_state == "retry" && previous.expires_at.is_none_or(|end| end <= now()) {
        return Err("Known lease expired during UPnP preflight; not recreated.".into());
    }
    let started = now();
    journal.insert(
        id.into(),
        RouterIntent {
            gateway: Some(gateway.gateway.addr.to_string()),
            local_ip: Some(local.to_string()),
            expires_at: None,
            external_ip: Some(external.to_string()),
            state: "unverified".into(),
            control_url: Some(gateway.gateway.control_url.clone()),
            root_url: Some(gateway.gateway.root_url.clone()),
            control_schema_url: Some(gateway.gateway.control_schema_url.clone()),
            control_schema: Some(gateway.gateway.control_schema.clone()),
            service_type: Some(gateway.service.clone()),
            interface_index: Some(gateway.lan.index),
            method: Some("UPnP".into()),
            internal_port: Some(port),
            external_port: Some(port),
            protocol: Some(proto.into()),
            mutation_attempted: true,
            confirmed: false,
            auto_renew: previous.auto_renew,
            allow_nat_pmp: previous.allow_nat_pmp,
            extra: previous.extra,
            ..RouterIntent::default()
        },
    );
    save(journal)?;
    if previous.renewal_state == "retry" && previous.expires_at.is_none_or(|end| end <= now()) {
        return Err("Known lease expired during UPnP save; not recreated.".into());
    }
    soap_before(
        gateway,
        "AddPortMapping",
        &add_arguments(port, proto, local, id)?,
        if previous.renewal_state == "retry" {
            previous.expires_at
        } else {
            None
        },
    )?;
    let intent = journal.get_mut(id).unwrap();
    intent.expires_at = None;
    intent.state = "unverified".into();
    save(journal)?;
    match specific(gateway, port, proto)? {
        Some(entry) if owned(&entry, id, port, local) => {
            if !entry.enabled {
                return Err(
                    "Owned router mapping is disabled; inbound forwarding was not confirmed."
                        .into(),
                );
            }
            let lease = verified_lease(&entry)?;
            let intent = journal.get_mut(id).unwrap();
            crate::lease::grant(intent, started, lease);
            intent.state = "mapped".into();
            Ok(format!("UPnP mapped to {local}:{port}; external IP {external}. Finite lease: {lease} seconds; expires at {}. Renewal only while this app runs and explicitly enabled; Internet reachability is not guaranteed.", intent.expires_at.unwrap()))
        }
        _ => Err(
            "Router accepted add but ownership verification failed; mapping is unverified.".into(),
        ),
    }
}

pub fn close(id: &str, port: u16, proto: &str, intent: &RouterIntent) -> Result<String, String> {
       let Some(_) = &intent.gateway else {
        return Ok("No router mapping was attempted; intent cleared.".into());
    };
    let gateway = from_intent(intent)?;
    let local = gateway.lan.local;
    match specific(&gateway, port, proto)? {
        None => Ok(format!("{port}/{proto}: router mapping already absent.")),
        Some(entry) if owned(&entry, id, port, local) => {
            soap(
                &gateway,
                "DeletePortMapping",
                &mapping_arguments(port, proto),
            )?;
            if specific(&gateway, port, proto)?.is_some() {
                return Err("Router deletion was not confirmed.".into());
            }
            Ok(format!("{port}/{proto}: owned router mapping removed."))
        }
        Some(_) => {
            Err("Mapping is not owned by this app and local address; left unchanged.".into())
        }
    }
}

pub fn external_ip(router: &Router) -> Result<Ipv4Addr, String> {
    let response =
        soap(router, "GetExternalIPAddress", "")?.ok_or("Missing external IP response")?;
    text(&response, "NewExternalIPAddress")?
        .parse()
        .map_err(|_| "Invalid router external IPv4".into())
}

pub fn inspect(id: &str, port: u16, proto: &str, intent: &RouterIntent) -> Result<String, String> {
    let router = from_intent(intent)?;
    match specific(&router, port, proto)? {
        None => Ok(format!("{port}/{proto}: saved UPnP mapping is currently absent (specific read-only query).")),
        Some(entry) if owned(&entry, id, port, router.lan.local) => Ok(format!("{port}/{proto}: saved UPnP ownership verified at {} -> {}:{}; enabled={}; router reports lease {} seconds (0 means permanent). Reachability is not proven; no renewal or mutation performed.", router.gateway.addr, entry.ip, entry.port, entry.enabled, entry.lease)),
        Some(_) => Ok(format!("{port}/{proto}: router entry is foreign or changed; saved ownership not verified, left unchanged.")),
    }
}

pub(crate) fn renew(
    id: &str,
    port: u16,
    proto: &str,
    journal: &mut Journal,
) -> Result<String, String> {
    let intent = journal.get(id).ok_or("Missing lease")?.clone();
    let gateway = from_intent(&intent)?;
    match specific(&gateway, port, proto)? {
        Some(entry) if owned(&entry, id, port, gateway.lan.local) && entry.enabled => {
            verified_lease(&entry)?;
            let result = open(&gateway, id, port, proto, journal);
            if result.is_err() {
                                              journal.insert(id.into(), intent);
            }
            result
        }
        _ => Err(
            "Saved UPnP mapping is absent, disabled or foreign; renewal paused, not recreated."
                .into(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn lan() -> Lan {
        Lan {
            local: "192.168.1.10".parse().unwrap(),
            gateway: "192.168.1.1".parse().unwrap(),
            index: 7,
            prefix: 24,
        }
    }
    fn intent() -> RouterIntent {
        serde_json::from_str(r#"{"gateway":"192.168.1.1:5000","local_ip":"192.168.1.10","expires_at":null,"external_ip":null,"state":"mapped"}"#).unwrap()
    }
    #[test]
    fn legacy_records_and_cached_endpoint_validation() {
        let lan = lan();
        let mut intent = intent();
        assert!(cached_for_lan(&intent, &lan).unwrap().is_none());
        intent.root_url = Some("/device/root.xml".into());
        assert!(cached_for_lan(&intent, &lan).is_err());
        intent.control_url = Some("../control".into());
        intent.control_schema_url = Some("schema.xml".into());
        intent.control_schema = Some(HashMap::from([
            ("GetSpecificPortMappingEntry".into(), vec![]),
            ("DeletePortMapping".into(), vec![]),
        ]));
        intent.service_type = Some("urn:schemas-upnp-org:service:WANPPPConnection:2".into());
        let gateway = cached_for_lan(&intent, &lan).unwrap().unwrap();
        assert_eq!(gateway.control_url, "http://192.168.1.1:5000/control");
        intent.control_url = Some("http://192.168.1.2:5000/control".into());
        assert!(cached_for_lan(&intent, &lan).is_err());
        intent.control_url = Some("/control".into());
        intent.gateway = Some("192.168.1.2:5000".into());
        assert!(cached_for_lan(&intent, &lan).is_err());
        intent.gateway = Some("192.168.1.1:5000".into());
        intent.service_type = Some("urn:schemas-upnp-org:service:Other:1".into());
        assert!(cached_for_lan(&intent, &lan).is_err());
        intent.service_type = Some("urn:schemas-upnp-org:service:WANIPConnection:2".into());
        intent.control_url = Some("http://192.168.1.1:80/control".into());
        assert!(cached_for_lan(&intent, &lan).is_err());
        intent.control_url = Some("/control".into());
        intent.local_ip = Some("192.168.1.11".into());
        assert!(cached_for_lan(&intent, &lan).is_err());
        assert!(matches!(from_intent(&intent), Err(e) if e.contains("test mode")));
    }
    #[test]
    fn endpoint_and_ssdp_reject_arbitrary_hosts() {
        let lan = lan();
        let base = Url::parse("http://192.168.1.1:5000/device/root.xml").unwrap();
        assert_eq!(
            endpoint(&base, "../control", lan.gateway).unwrap().as_str(),
            "http://192.168.1.1:5000/control"
        );
        for value in [
            "",
            "https://192.168.1.1:5000/control",
            "//evil.example/control",
            "http://10.0.0.1:5000/control",
            "http://192.168.1.1:80/control",
            "http://user@192.168.1.1:5000/control",
            "/control#fragment",
            "\\\\evil.example\\control",
            "/control\n",
        ] {
            assert!(endpoint(&base, value, lan.gateway).is_err(), "{value}");
        }
        assert!(ssdp_location(
            "HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.1:5000/root.xml\r\n",
            lan.gateway
        )
        .is_ok());
        assert!(ssdp_location(
            "HTTP/1.1 200 OK\r\nLOCATION: http://evil.example/root.xml\r\n",
            lan.gateway
        )
        .is_err());
        let mut wrong = lan.clone();
        wrong.gateway = "192.168.2.1".parse().unwrap();
        assert!(validate_lan(&wrong).is_err());
        wrong = lan.clone();
        wrong.prefix = 0;
        assert!(validate_lan(&wrong).is_err());
    }
    #[test]
    fn descriptor_preserves_service_type_and_relative_paths() {
        let location = Url::parse("http://192.168.1.1:5000/device/root.xml").unwrap();
        for kind in [
            "WANIPConnection:1",
            "WANIPConnection:2",
            "WANPPPConnection:1",
            "WANPPPConnection:2",
        ] {
            let xml = format!("<root><device><deviceList><device><serviceList><service><serviceType>urn:schemas-upnp-org:service:{kind}</serviceType><controlURL>../control</controlURL><SCPDURL>schema.xml</SCPDURL></service></serviceList></device></deviceList></device></root>");
            let (service, control, scpd) = descriptor(&xml, &location, lan().gateway).unwrap();
            assert_eq!(service, format!("urn:schemas-upnp-org:service:{kind}"));
            assert_eq!(control.as_str(), "http://192.168.1.1:5000/control");
            assert_eq!(scpd.as_str(), "http://192.168.1.1:5000/device/schema.xml");
            assert!(descriptor(
                &xml.replace("../control", "http://evil.example/control"),
                &location,
                lan().gateway
            )
            .is_err());
            assert!(descriptor(
                &xml.replace(
                    "<device>",
                    "<URLBase>http://evil.example/</URLBase><device>"
                ),
                &location,
                lan().gateway
            )
            .is_err());
        }
        let xml = "<scpd><actionList><action><name>GetSpecificPortMappingEntry</name><argumentList><argument><name>NewExternalPort</name><direction>in</direction></argument><argument><name>NewInternalPort</name><direction>out</direction></argument></argumentList></action><action><name>GetExternalIPAddress</name></action></actionList></scpd>";
        let parsed = schema(xml).unwrap();
        assert_eq!(
            parsed["GetSpecificPortMappingEntry"],
            vec!["NewExternalPort"]
        );
        assert!(parsed["GetExternalIPAddress"].is_empty());
        assert!(schema("<scpd><actionList/></scpd>").is_err());
    }
    #[test]
    fn ownership_requires_all_fields() {
        let ip = Ipv4Addr::new(192, 168, 1, 10);
        let entry = Mapping {
            ip,
            port: 80,
            description: "WawityPorts-80-TCP".into(),
            lease: 3600,
            enabled: true,
        };
        assert!(owned(&entry, "WawityPorts-80-TCP", 80, ip));
        assert!(!owned(&entry, "Foreign", 80, ip));
        assert!(!owned(&entry, "WawityPorts-80-TCP", 81, ip));
        assert!(!owned(
            &entry,
            "WawityPorts-80-TCP",
            80,
            Ipv4Addr::LOCALHOST
        ));
    }

    #[test]
    fn finite_lease_only_and_safe_arguments() {
        let ip = Ipv4Addr::LOCALHOST;
        let args = add_arguments(80, "TCP", ip, "WawityPorts-80-TCP").unwrap();
        assert!(args.contains("<NewLeaseDuration>3600</NewLeaseDuration>"));
        assert!(!args.contains("<NewLeaseDuration>0</NewLeaseDuration>"));
        assert!(add_arguments(81, "TCP", ip, "WawityPorts-80-TCP").is_err());
        let mut entry = Mapping {
            ip,
            port: 80,
            description: String::new(),
            lease: 0,
            enabled: true,
        };
        assert!(verified_lease(&entry).is_err());
        entry.lease = 3601;
        assert!(verified_lease(&entry).is_err());
        entry.lease = 3599;
        assert_eq!(verified_lease(&entry).unwrap(), 3599);
    }

    #[test]
    fn soap_faults_are_action_specific() {
        let fault = |code| {
            format!("<Envelope><Fault><detail><UPnPError><errorCode>{code}</errorCode></UPnPError></detail></Fault></Envelope>")
        };
        assert!(
            parse_response(&fault(714), false, "GetSpecificPortMappingEntry")
                .unwrap()
                .is_none()
        );
        assert!(parse_response(&fault(714), false, "DeletePortMapping").is_err());
        assert!(parse_response(&fault(725), false, "AddPortMapping")
            .unwrap_err()
            .contains("no infinite-lease retry"));
        assert!(parse_response("<Envelope/>", true, "AddPortMapping").is_err());
    }
}
