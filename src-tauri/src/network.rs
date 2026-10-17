use crate::{
    checks, load, powershell, router,
    udp::{self, Transport},
    OPERATIONS,
};
use serde::Serialize;
use std::net::Ipv6Addr;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkDiagnostics {
    local_ip: Option<String>,
    gateway: Option<String>,
    ipv6: Vec<String>,
    methods: Vec<Method>,
    messages: Vec<String>,
}

#[derive(Serialize)]
struct Method {
    name: String,
    state: String,
    detail: String,
}

fn method(name: &str, result: Result<String, String>) -> Method {
    match result {
        Ok(detail) => Method {
            name: name.into(),
            state: "available".into(),
            detail,
        },
        Err(detail) => Method {
            name: name.into(),
            state: "unconfirmed".into(),
            detail,
        },
    }
}

fn global_ipv6(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
       s[0] & 0xe000 == 0x2000
        && !(s[0] == 0x2001 && (s[1] == 0xdb8 || s[1] < 0x200))
        && s[0] != 0x2002
}

pub fn diagnostics() -> NetworkDiagnostics {
    let mut result=NetworkDiagnostics {local_ip:None,gateway:None,ipv6:vec![],methods:vec![],messages:vec![
        "Read-only physical-LAN diagnostics. No third-party Internet identity/probe, MAP mutation, IPv6 firewall opening, VPN disable or global network change.".into(),
        udp::NAT_RISK.into(),
    ]};
    let Ok(_guard) = OPERATIONS.lock() else {
        result.messages.push("Operation lock failed".into());
        return result;
    };
    let selected = load().and_then(|journal| {
        if let Some(intent) = journal.values().find(|i| i.gateway.is_some()) {
            router::physical_lan_for_intent(intent)
        } else {
            router::physical_lans()?
                .into_iter()
                .next()
                .ok_or("No physical LAN".into())
        }
    });
    let lan = match selected {
        Ok(lan) => lan,
        Err(error) => {
            result.messages.push(error.clone());
            result.methods = ["UPnP", "PCP", "NAT-PMP"]
                .iter()
                .map(|name| method(name, Err(error.clone())))
                .collect();
            return result;
        }
    };
    result.local_ip = Some(lan.local.to_string());
    result.gateway = Some(lan.gateway.to_string());
    let ipv6=powershell(&format!("$ips=@(Get-NetIPAddress -InterfaceIndex {} -AddressFamily IPv6 | Where-Object {{ $_.AddressState -eq 'Preferred' -and -not $_.SkipAsSource }} | ForEach-Object IPAddress); ConvertTo-Json -InputObject $ips -Compress",lan.index))
        .and_then(|json| serde_json::from_str::<Vec<String>>(&json).map_err(|e| e.to_string()));
    match ipv6 {
        Ok(ips) => {
            result.ipv6 = ips
                .into_iter()
                .filter(|ip| ip.parse::<Ipv6Addr>().is_ok_and(global_ipv6))
                .collect()
        }
        Err(error) => result.messages.push(format!(
            "Physical global IPv6 detection unconfirmed: {error}"
        )),
    }
    result.messages.push("Global IPv6 addresses are observations, not inbound reachability proof; IPv6 firewall is never opened automatically.".into());
    let upnp=router::discover_on(lan.clone()).and_then(|router| {
        let ip=router::external_ip(&router)?;
        wan_message(ip,&mut result.messages);
        Ok(format!("Read-only UPnP descriptor/ownership-query service discovered; current WAN IPv4 {ip}. Mapping success is not promised."))
    });
    result.methods.push(method("UPnP", upnp));
    let pcp=udp::PhysicalTransport::new(&lan).and_then(|mut t| t.exchange(&udp::pcp_request(lan.local,None,0,0,0,None,0),true))
        .map(|reply| format!("PCP ANNOUNCE replied, epoch {}. This does not prove MAP or mandatory PREFER_FAILURE support; no mapping created. Fresh external address unavailable without mutation.",reply.epoch));
    result.methods.push(method("PCP", pcp));
    let nat=udp::PhysicalTransport::new(&lan).and_then(|mut t| t.exchange(&[0,0],false)).and_then(|reply| {
        let ip=reply.external_ip.ok_or("Missing NAT-PMP address")?;
        wan_message(ip,&mut result.messages);
        Ok(format!("NAT-PMP read-only address reply: {ip}, epoch {}. MAP capability/initial ownership not proven; mapping requires explicit consent.",reply.epoch))
    });
    result.methods.push(method("NAT-PMP", nat));
    result
}

fn wan_message(ip: std::net::Ipv4Addr, messages: &mut Vec<String>) {
    if !checks::public_ipv4(ip) {
        messages.push(format!("Router reports non-public WAN IPv4 {ip}; private/upstream NAT or CGNAT may prevent inbound IPv4. No public identity service queried."));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ipv6_scope_and_diagnostics_shape_without_network() {
        for ip in [
            "::",
            "::1",
            "fe80::1",
            "fd00::1",
            "fc00::1",
            "ff02::1",
            "2001:db8::1",
            "2002::1",
            "::ffff:8.8.8.8",
        ] {
            assert!(!global_ipv6(ip.parse().unwrap()), "{ip}");
        }
        assert!(global_ipv6("2606:4700:4700::1111".parse().unwrap()));
        let result = serde_json::to_value(diagnostics()).unwrap();
        assert_eq!(result.as_object().unwrap().len(), 5);
        assert!(result["localIp"].is_null());
        assert!(result["gateway"].is_null());
        for method in result["methods"].as_array().unwrap() {
            assert_eq!(method["state"], "unconfirmed");
        }
        assert_eq!(result["methods"].as_array().unwrap().len(), 3);
    }
}
