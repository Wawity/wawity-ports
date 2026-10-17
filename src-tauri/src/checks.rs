use crate::{
    diagnostic, load, mapping, now, ports, powershell, refresh, router, Journal, OPERATIONS,
};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    net::{IpAddr, Ipv4Addr},
    time::{Duration, Instant},
};

#[derive(Deserialize)]
pub struct CheckRequest {
    ports: String,
    protocol: String,
    external: bool,
    #[serde(default, rename = "testServer")]
    test_server: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckOutcome {
    pub messages: Vec<String>,
    pub results: Vec<CheckResult>,
    pub checked_at: u64,
}

#[derive(Debug, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CheckStatus {
    Reachable,
    NoListener,
    LoopbackOnly,
    LocalOnly,
    UdpUnverified,
    Unconfirmed,
    Unknown,
    VerifiedLocal,
    TestUnconfirmed,
}

#[derive(Serialize)]
pub struct CheckResult {
    pub port: u16,
    pub protocol: String,
    pub status: CheckStatus,
    pub title: String,
    pub detail: String,
}

#[derive(Debug)]
struct NodeResult {
    message: String,
    reachable: bool,
    node_ip: Option<IpAddr>,
    window: Option<(Instant, Instant)>,
}

fn selection(request: &CheckRequest) -> Result<(Vec<u16>, &'static [&'static str]), String> {
    let ports = ports::parse_ports(&request.ports)?;
    if ports.len() > 8 {
        return Err("Check at most eight distinct ports at a time.".into());
    }
    let protocols: &[&str] = match request.protocol.as_str() {
        "TCP" => &["TCP"],
        "UDP" => &["UDP"],
        "BOTH" => &["TCP", "UDP"],
        _ => return Err("Protocol must be TCP, UDP, or BOTH.".into()),
    };
    if request.test_server {
        if !request.external || !protocols.contains(&"TCP") {
            return Err(
                "Тестовый TCP-сервер требует согласия на внешнюю проверку и протокол TCP или BOTH."
                    .into(),
            );
        }
        if ports.len() != 1 {
            return Err("Для временного тестового сервера выберите ровно один порт.".into());
        }
    }
    Ok((ports, protocols))
}

#[derive(Deserialize)]
struct Listener {
    port: u16,
    protocol: String,
    address: String,
    pid: u32,
}

fn verdict(
    port: u16,
    protocol: &str,
    listeners: Result<&[Listener], &str>,
    external: bool,
    reachable: bool,
) -> CheckResult {
       let (status, title, detail) = if protocol == "TCP" && reachable {
        (CheckStatus::Reachable, "Доступен извне", "Внешний узел подключился к публичному IP:порту. Это может быть сервис роутера; принадлежность нужной локальной программе не подтверждена.")
    } else {
        match listeners {
            Ok(rows) => {
                let matching: Vec<_> = rows.iter().filter(|r| r.port == port && r.protocol == protocol).collect();
                if matching.is_empty() {
                    (CheckStatus::NoListener, "Нет локальной программы", "Программа на этом порту не найдена. Доступ извне не подтверждён; правило брандмауэра или проброс не запускает программу.")
                } else if matching.iter().all(|r| r.address.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())) {
                    (CheckStatus::LoopbackOnly, "Только на этом компьютере", "Все найденные привязки используют loopback. Эта локальная программа не принимает подключения через сетевые интерфейсы.")
                } else if !matching.iter().any(|r| r.address.parse::<IpAddr>().is_ok_and(|ip| !ip.is_loopback())) {
                    (CheckStatus::Unknown, "Результат неизвестен", "Не удалось определить адреса локальных привязок. Доступность нужной программы не подтверждена.")
                } else if !external {
                    (CheckStatus::LocalOnly, "Найден локально", "Программа слушает сетевой интерфейс. Внешняя проверка не запрошена; доступ из интернета не подтверждён.")
                } else if protocol == "UDP" {
                    (CheckStatus::UdpUnverified, "UDP не подтверждён", "Локальный UDP-порт найден. Доступ извне проверяется только запросом и ответом нужного приложения; TCP-проверка не доказывает доступность UDP.")
                } else {
                    (CheckStatus::Unconfirmed, "Доступ извне не подтверждён", "Локальная программа найдена, но внешнее подключение не подтверждено. Тайм-аут, сбой проверки или отсутствие публичного IP не означают закрытый порт.")
                }
            }
            Err(_) => (CheckStatus::Unknown, "Результат неизвестен", "Не удалось проверить локальные привязки. Доступность нужной программы не подтверждена; это не означает закрытый порт."),
        }
    };
    CheckResult {
        port,
        protocol: protocol.into(),
        status,
        title: title.into(),
        detail: detail.into(),
    }
}

fn listener_message(row: &Listener) -> String {
    let scope = match row.address.parse::<IpAddr>() {
        Ok(ip) if ip.is_loopback() => "loopback only; not Internet-accessible",
        Ok(ip) if ip.is_unspecified() => "wildcard binding; Internet reachability is not proven",
        Ok(_) => "specific interface binding; Internet reachability is not proven",
        Err(_) => "unknown address scope; Internet reachability is indeterminate",
    };
    format!(
        "{}/{}: local {} bound at {}:{} (PID {}); {scope}.",
        row.port,
        row.protocol,
        if row.protocol == "TCP" {
            "listener"
        } else {
            "UDP endpoint"
        },
        row.address,
        row.port,
        row.pid
    )
}

fn listener_snapshot(ports: &[u16]) -> Result<Vec<Listener>, String> {
    let list = ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let script = format!(
        r#"$ports=@({list}); $rows=@();
      try {{ $rows+=@(Get-NetTCPConnection -State Listen | Where-Object {{ $_.LocalPort -in $ports }} | ForEach-Object {{ [pscustomobject]@{{ port=$_.LocalPort; protocol='TCP'; address=$_.LocalAddress; pid=$_.OwningProcess }} }}) }} catch {{ if ($_.FullyQualifiedErrorId -notlike 'CmdletizationQuery_NotFound*') {{ throw }} }};
      try {{ $rows+=@(Get-NetUDPEndpoint | Where-Object {{ $_.LocalPort -in $ports }} | ForEach-Object {{ [pscustomobject]@{{ port=$_.LocalPort; protocol='UDP'; address=$_.LocalAddress; pid=$_.OwningProcess }} }}) }} catch {{ if ($_.FullyQualifiedErrorId -notlike 'CmdletizationQuery_NotFound*') {{ throw }} }};
      ConvertTo-Json -InputObject $rows -Compress"#
    );
    powershell(&script).and_then(|s| {
        serde_json::from_str::<Vec<Listener>>(&s)
            .map_err(|e| format!("Invalid listener response: {e}"))
    })
}

fn selected_router(journal: &Journal, ports: &[u16]) -> Result<mapping::CheckRouter, String> {
    let target = journal.iter().find(|(id, intent)| {
        intent.gateway.is_some()
            && ports::parse_id(id).is_ok_and(|(p, proto)| ports.contains(&p) && proto == "TCP")
    });
    mapping::check_router(target.map(|(_, intent)| intent))
}

fn require_free_port(listeners: Result<&[Listener], &str>, port: u16) -> Result<(), String> {
    let rows = listeners.map_err(|e| {
        format!("Не удалось исключить существующий TCP-сервис; тестовый сервер не запущен: {e}")
    })?;
    if rows.iter().any(|r| r.port == port && r.protocol == "TCP") {
        return Err(format!("Порт {port}/TCP занят локальным сервисом. Он оставлен без изменений; запустите обычную проверку без тестового сервера."));
    }
    Ok(())
}

fn test_verdict(port: u16, report: &diagnostic::Report, nodes: &[NodeResult]) -> CheckResult {
    let matched_peer = nodes.iter().find_map(|node| {
        if !node.reachable {
            return None;
        }
        let ip = node.node_ip?;
        if !matches!(ip, IpAddr::V4(v4) if public_ipv4(v4)) {
            return None;
        }
        let (start, end) = node.window?;
        report
            .incoming
            .iter()
            .find(|incoming| {
                incoming.peer.ip() == ip
                    && incoming.local == report.endpoint
                    && incoming.at >= start
                    && incoming.at <= end
            })
            .map(|incoming| incoming.peer)
    });
    let verified = matched_peer.is_some();
    CheckResult {
        port,
        protocol: "TCP".into(),
        status: if verified {
            CheckStatus::VerifiedLocal
        } else {
            CheckStatus::TestUnconfirmed
        },
        title: if verified {
            "Тестовый сервер достигнут извне"
        } else {
            "Тестовый доступ не подтверждён"
        }
        .into(),
        detail: if let Some(peer) = matched_peer {
            format!("Внешний узел успешен; его публичный IP совпал с входящим {peer} на {} в окне проверки. Тестовый сервер остановлен; готовность рабочей программы не подтверждена.", report.endpoint)
        } else {
            format!("На {} принято подключений: {}. Внешние узлы не подключились за две попытки; порт закрытым не считается. Повторите тест позже или проверьте другой порт: входящие может блокировать провайдер, роутер или двойной NAT. Тестовый сервер остановлен.", report.endpoint, report.incoming.len())
        },
    }
}

pub fn check(request: CheckRequest) -> Result<CheckOutcome, String> {
    let (ports, protocols) = selection(&request)?;
    let _guard = OPERATIONS
        .lock()
        .map_err(|_| "Backend operation lock failed")?;
    let mut messages = vec!["Read-only configuration check: no mappings, firewall rules, VPN settings or routes are changed. Source binding cannot bypass VPN kill switches or Windows filtering.".into()];
    let journal = load()?;
    let mut selected = None;
    let server = if request.test_server {
        let before = listener_snapshot(&ports);
        require_free_port(before.as_deref().map_err(String::as_str), ports[0])?;
        let router = selected_router(&journal, &ports)?;
                      let before = listener_snapshot(&ports);
        require_free_port(before.as_deref().map_err(String::as_str), ports[0])?;
                      let server =
            diagnostic::TestServer::start(router.lan.local, ports[0], diagnostic::MAX_LEASE)?;
        messages.push(format!("Временный тестовый TCP-сервер запущен на {} (физический LAN, интерфейс {}, шлюз {}). Срок не более 70 секунд, максимум 64 подключения (включая одну повторную внешнюю попытку); входные данные не читаются, ответы не отправляются. Правила и пробросы не создаются.", server.endpoint, router.lan.index, router.lan.gateway));
        selected = Some(Ok(router));
        Some(server)
    } else {
        None
    };
    let listeners = listener_snapshot(&ports);
    let rules = refresh(&journal);
    let local = listeners.as_deref().map_err(String::as_str);
    let mut results = Vec::new();
    let mut test_nodes = Vec::new();
    let mut public_target = None;
    for port in &ports {
        for protocol in protocols {
            results.push(verdict(*port, protocol, local, request.external, false));
            match &listeners {
                Ok(rows) => {
                    let matching: Vec<_> = rows
                        .iter()
                        .filter(|r| r.port == *port && r.protocol == *protocol)
                        .collect();
                    if matching.is_empty() {
                        messages.push(format!("{port}/{protocol}: no local {} found; a firewall rule or UPnP mapping does not start a service.", if *protocol == "TCP" { "listener" } else { "UDP endpoint" }));
                    }
                    for row in matching {
                        if server.as_ref().is_some_and(|s| {
                            row.protocol == "TCP"
                                && row.port == s.endpoint.port()
                                && row.address.parse::<IpAddr>().ok() == Some(s.endpoint.ip())
                                && row.pid == std::process::id()
                        }) {
                            messages.push(format!("{port}/TCP: найден временный диагностический слушатель приложения, не рабочий сервис. Он будет остановлен после проверки или по жёсткому сроку."));
                        } else {
                            messages.push(listener_message(row));
                        }
                    }
                }
                Err(e) => messages.push(format!(
                    "{port}/{protocol}: local binding check indeterminate: {e}"
                )),
            }
            let id = format!("WawityPorts-{port}-{protocol}");
            match &rules {
                Ok(rules) => messages.push(format!("{port}/{protocol}: app-owned firewall allow rule {}. Other rules, profile applicability, VPN filters and global policy can still block traffic.", if rules.iter().any(|r| r.id == id && r.firewall) { "enabled in effective policy" } else { "absent, disabled or altered" })),
                Err(e) => messages.push(format!("{port}/{protocol}: app firewall check indeterminate: {e}")),
            }
            if let Some(intent) = journal.get(&id).filter(|i| i.gateway.is_some()) {
                match mapping::inspect(&id, *port, protocol, intent) {
                    Ok(note) => messages.push(note),
                    Err(e) => messages.push(format!(
                        "{port}/{protocol}: saved router verification indeterminate: {e}"
                    )),
                }
            } else {
                messages.push(format!("{port}/{protocol}: no saved router mapping; no UPnP mapping was created or assumed."));
            }
            if *protocol == "UDP" {
                messages.push(format!("{port}/UDP: generic external probing cannot prove UDP reachability; use an application-specific request and response."));
            }
        }
    }
    if request.external && protocols.contains(&"TCP") {
               let router = selected.unwrap_or_else(|| selected_router(&journal, &ports));
        match router.and_then(|r| mapping::external_ip(&r)) {
            Ok(ip) if public_ipv4(ip) => {
                public_target = Some(ip);
                for port in &ports {
                    match external_tcp(ip, *port) {
                        Ok(notes) => {
                            if let Some(result) = results.iter_mut().find(|r| r.port == *port && r.protocol == "TCP") {
                                *result = verdict(*port, "TCP", local, request.external, notes.iter().any(|n| n.reachable));
                            }
                            messages.extend(notes.iter().map(|n| n.message.clone()));
                            if request.test_server {
                                test_nodes.extend(notes);
                            }
                        }
                        Err(e) => messages.push(format!("{port}/TCP: external check indeterminate (not evidence of a closed port): {e}")),
                    }
                }
            }
            Ok(ip) => messages.push(format!("External TCP check skipped: router reports {ip}, a private/CGNAT or non-public address. Upstream NAT may prevent inbound reachability; no external target was probed.")),
            Err(e) => messages.push(format!("External TCP check skipped: router external IPv4 could not be verified: {e}")),
        }
    } else if !request.external {
        messages.push("External probing not requested; no third-party port probe sent.".into());
    }
    if let Some(server) = server {
        let report = server.stop()?;
        messages.push(format!("Тестовый сервер {} остановлен: {}. Локально наблюдалось входящих подключений: {}. Само по себе это не доказывает доступ из интернета.", report.endpoint, report.reason, report.incoming.len()));
        for incoming in &report.incoming {
            messages.push(format!("Локальное входящее подключение {} -> {}; доказательство внешнего узла учитывается только при точном совпадении публичного IP и окна успешной проверки.", incoming.peer, incoming.local));
        }
        messages.push("check-host TCP выполняет только рукопожатие, без проверки токена. Совпадение IP и времени не является криптографической идентификацией; иной исходящий IP узла, частный/LAN-источник, NAT или отсутствие совпадения дают неопределённый результат. Тест не подтверждает готовность рабочей программы.".into());
        let mut result = test_verdict(ports[0], &report, &test_nodes);
        if let Some(ip) = public_target {
            result.detail.push_str(&format!(" Проверялся путь {ip}:{} -> {} (выбранный физический LAN); настройки проброса не изменялись.", ports[0], report.endpoint));
        }
        *results.iter_mut().find(|r| r.protocol == "TCP").unwrap() = result;
    }
    Ok(CheckOutcome {
        messages,
        results,
        checked_at: now(),
    })
}

pub(crate) fn public_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !ip.is_private()
        && !ip.is_loopback()
        && !ip.is_link_local()
        && !ip.is_multicast()
        && a != 0
        && a < 224
        && !(a == 100 && (64..=127).contains(&b))
        && !(a == 192 && b == 0 && (c == 0 || c == 2))
        && !(a == 192 && b == 88 && c == 99)
        && !(a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
        && !(a == 203 && b == 0 && c == 113)
}

fn api_json(
    client: &Client,
    url: &str,
    query: &[(&str, String)],
    deadline: Instant,
) -> Result<Value, String> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err("External check polling deadline reached".into());
    }
    let response = client
        .get(url)
        .query(query)
        .header("Accept", "application/json")
        .timeout(remaining.min(Duration::from_secs(6)))
        .send()
        .map_err(|e| e.to_string())?;
    if !response.status().is_success() {
        return Err(format!(
            "check-host HTTP {}; redirects not followed",
            response.status()
        ));
    }
    serde_json::from_str(&router::response_text(response)?)
        .map_err(|e| format!("Invalid check-host response: {e}"))
}

fn node_result(node: &str, value: &Value, ip: Ipv4Addr, port: u16) -> Option<NodeResult> {
    let entry = value.as_array()?.first()?.as_object()?;
    if entry.get("address").and_then(Value::as_str) == Some(ip.to_string().as_str())
        && entry
            .get("time")
            .and_then(Value::as_f64)
            .is_some_and(|t| t >= 0.0)
        && !entry.contains_key("error")
    {
        return Some(NodeResult {
            message: format!("{port}/TCP: check-host node {node} connected to {ip}:{port}; externally reachable from that node at check time. This does not identify the intended local process; the endpoint may be the router's own service."),
            reachable: true,
            node_ip: None,
            window: None,
        });
    }
    entry.get("error").and_then(Value::as_str).map(|error| NodeResult {
        message: format!("{port}/TCP: check-host node {node} could not connect: {error}. This does not prove the port is closed; filtering, service state or node/network failure may be responsible."),
        reachable: false,
        node_ip: None,
        window: None,
    })
}

fn external_tcp_once(ip: Ipv4Addr, port: u16) -> Result<Vec<NodeResult>, String> {
    if cfg!(test) || std::env::var_os("WAWITY_PORTS_TEST_MODE").is_some() {
        return Err("External probes disabled in test mode".into());
    }
    if !public_ipv4(ip) {
        return Err("Refusing non-public external target".into());
    }
       let client = Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(6))
        .connect_timeout(Duration::from_secs(3))
        .build()
        .map_err(|e| e.to_string())?;
    let deadline = Instant::now() + Duration::from_secs(16);
    let probe_started = Instant::now();
    let start = api_json(
        &client,
        "https://check-host.net/check-tcp",
        &[("host", format!("{ip}:{port}")), ("max_nodes", "4".into())],
        deadline,
    )?;
    if start["ok"].as_u64() != Some(1) {
        return Err("check-host did not accept the check".into());
    }
    let id = start["request_id"]
        .as_str()
        .filter(|s| !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_alphanumeric()))
        .ok_or("Invalid check-host request identifier")?;
    let nodes = start["nodes"]
        .as_object()
        .filter(|n| !n.is_empty() && n.len() <= 4)
        .ok_or("Invalid check-host node list")?;
    let mut completed = std::collections::BTreeMap::new();
    let mut last_error = None;
    while Instant::now() < deadline {
        std::thread::sleep(
            Duration::from_secs(1).min(deadline.saturating_duration_since(Instant::now())),
        );
        if Instant::now() >= deadline {
            break;
        }
        let result = match api_json(
            &client,
            &format!("https://check-host.net/check-result/{id}"),
            &[],
            deadline,
        ) {
            Ok(result) => result,
            Err(e) => {
                last_error = Some(e);
                continue;
            }
        };
        for (node, advertised) in nodes {
            if let Some(mut note) = node_result(node, &result[node], ip, port) {
                note.node_ip = advertised_node_ip(advertised);
                note.window = Some((probe_started, Instant::now()));
                note.message.push_str(&format!(" Advertised node source IP: {:?}; exact incoming-peer correlation is required for a diagnostic listener.", note.node_ip));
                completed.entry(node.clone()).or_insert(note);
            }
        }
        if completed.len() == nodes.len() {
            break;
        }
    }
    for node in nodes.keys() {
        completed.entry(node.clone()).or_insert_with(|| NodeResult {
            message: format!("{port}/TCP: check-host node {node} result pending or malformed after bounded polling; indeterminate, not closed.{}", last_error.as_ref().map(|e| format!(" Last polling error: {e}")).unwrap_or_default()),
            reachable: false,
            node_ip: advertised_node_ip(&nodes[node]),
            window: Some((probe_started, Instant::now())),
        });
    }
    Ok(completed.into_values().collect())
}

fn external_tcp(ip: Ipv4Addr, port: u16) -> Result<Vec<NodeResult>, String> {
    let first = external_tcp_once(ip, port)?;
    if first.iter().any(|node| node.reachable) {
        return Ok(first);
    }
    match external_tcp_once(ip, port) {
        Ok(second) if second.iter().any(|node| node.reachable) => Ok(second),
        Ok(second) => Ok([first, second]
            .into_iter()
            .flatten()
            .map(|node| NodeResult {
                message: format!("Повторная попытка внешней проверки: {}", node.message),
                ..node
            })
            .collect()),
        Err(error) => Ok(first
            .into_iter()
            .map(|node| NodeResult {
                message: format!("{}. Повторная попытка не удалась: {error}", node.message),
                ..node
            })
            .collect()),
    }
}

fn advertised_node_ip(value: &Value) -> Option<IpAddr> {
       value.as_array()?.get(3)?.as_str()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn consent_validation_and_shipped_request_default() {
        let legacy: CheckRequest = serde_json::from_value(serde_json::json!({
            "ports":"80", "protocol":"TCP", "external":true
        }))
        .unwrap();
        assert!(!legacy.test_server);
        for (ports, protocol, external, allowed) in [
            ("80", "TCP", true, true),
            ("80,80", "BOTH", true, true),
            ("80", "TCP", false, false),
            ("80", "UDP", true, false),
            ("80,81", "TCP", true, false),
        ] {
            let request: CheckRequest = serde_json::from_value(serde_json::json!({
                "ports":ports, "protocol":protocol, "external":external, "testServer":true
            }))
            .unwrap();
            assert!(request.test_server);
            assert_eq!(selection(&request).is_ok(), allowed);
            if !allowed {
                assert!(check(request).is_err());
            }
        }
        assert!(serde_json::from_value::<CheckRequest>(serde_json::json!({
            "ports":"80", "protocol":"TCP", "external":true, "testServer":null
        }))
        .is_err());
        let request: CheckRequest = serde_json::from_value(serde_json::json!({
            "ports":"80", "protocol":"TCP", "external":true, "testServer":true
        }))
        .unwrap();
        assert!(check(request).err().unwrap().contains("TCP"));
    }

    #[test]
    fn busy_and_unknown_snapshots_refuse_test_without_touching_service() {
        for address in ["127.0.0.1", "0.0.0.0", "192.168.1.2", "::", "::1"] {
            let rows = [Listener {
                port: 80,
                protocol: "TCP".into(),
                address: address.into(),
                pid: 123,
            }];
            assert!(require_free_port(Ok(&rows), 80)
                .unwrap_err()
                .contains("обычную проверку"));
            assert!(require_free_port(Ok(&rows), 81).is_ok());
        }
        assert!(require_free_port(Err("snapshot failed"), 80).is_err());
        assert!(require_free_port(Ok(&[]), 80).is_ok());
    }

    #[test]
    fn only_exact_public_peer_endpoint_and_probe_window_verify_local() {
        let at = Instant::now();
        let endpoint = "192.168.1.10:80".parse().unwrap();
        let mut report = diagnostic::Report {
            endpoint,
            incoming: vec![diagnostic::Incoming {
                peer: "8.8.8.8:12345".parse().unwrap(),
                local: endpoint,
                at,
            }],
            reason: "explicit stop".into(),
        };
        let mut node = NodeResult {
            message: "untrusted message".into(),
            reachable: true,
            node_ip: Some("8.8.8.8".parse().unwrap()),
            window: Some((at - Duration::from_secs(1), at + Duration::from_secs(1))),
        };
        assert_eq!(
            test_verdict(80, &report, &[node]).status,
            CheckStatus::VerifiedLocal
        );
        node = NodeResult {
            message: "externally reachable".into(),
            reachable: true,
            node_ip: Some("1.1.1.1".parse().unwrap()),
            window: Some((at - Duration::from_secs(1), at + Duration::from_secs(1))),
        };
        assert_eq!(
            test_verdict(80, &report, std::slice::from_ref(&node)).status,
            CheckStatus::TestUnconfirmed
        );
        node.node_ip = Some("8.8.8.8".parse().unwrap());
        for window in [
            None,
            Some((at + Duration::from_nanos(1), at + Duration::from_secs(1))),
            Some((at - Duration::from_secs(1), at - Duration::from_nanos(1))),
        ] {
            node.window = window;
            assert_eq!(
                test_verdict(80, &report, std::slice::from_ref(&node)).status,
                CheckStatus::TestUnconfirmed
            );
        }
        node.window = Some((at, at));
        node.reachable = false;
        assert_eq!(
            test_verdict(80, &report, std::slice::from_ref(&node)).status,
            CheckStatus::TestUnconfirmed
        );
        node.reachable = true;
        for source in [
            "127.0.0.1",
            "192.168.1.1",
            "100.64.0.1",
            "198.51.100.1",
            "::1",
        ] {
            node.node_ip = Some(source.parse().unwrap());
            report.incoming[0].peer.set_ip(source.parse().unwrap());
            assert_eq!(
                test_verdict(80, &report, std::slice::from_ref(&node)).status,
                CheckStatus::TestUnconfirmed
            );
        }
        node.node_ip = Some("8.8.8.8".parse().unwrap());
        report.incoming[0].peer.set_ip(node.node_ip.unwrap());
        report.incoming[0].local.set_port(81);
        assert_eq!(
            test_verdict(80, &report, std::slice::from_ref(&node)).status,
            CheckStatus::TestUnconfirmed
        );
        report.incoming.clear();
        assert_eq!(
            test_verdict(80, &report, &[node]).status,
            CheckStatus::TestUnconfirmed
        );
        assert_eq!(
            advertised_node_ip(&serde_json::json!([
                "us",
                "USA",
                "Los Angeles",
                "5.253.30.82",
                "AS18978"
            ])),
            Some("5.253.30.82".parse().unwrap())
        );
        for metadata in [
            serde_json::json!(["8.8.8.8"]),
            serde_json::json!(["us", "USA", "City", "example.org"]),
            Value::Null,
        ] {
            assert_eq!(advertised_node_ip(&metadata), None);
        }
    }
    #[test]
    fn checking_limits_and_protocols() {
        let request = |ports: &str, protocol: &str| CheckRequest {
            ports: ports.into(),
            protocol: protocol.into(),
            external: false,
            test_server: false,
        };
        assert_eq!(selection(&request("1-8,1", "BOTH")).unwrap().0.len(), 8);
        assert!(selection(&request("1-9", "TCP")).is_err());
        assert!(selection(&request("80;whoami", "TCP")).is_err());
        assert!(selection(&request("80", "tcp")).is_err());
    }
    #[test]
    fn private_cgnat_and_reserved_targets_are_not_probed() {
        for ip in [
            "10.0.0.1",
            "192.168.1.1",
            "172.16.0.1",
            "100.64.0.1",
            "100.127.255.254",
            "127.0.0.1",
            "0.1.2.3",
            "169.254.0.1",
            "192.0.2.1",
            "198.51.100.1",
            "203.0.113.1",
            "198.18.0.1",
            "224.0.0.1",
            "255.255.255.255",
        ] {
            assert!(!public_ipv4(ip.parse().unwrap()), "{ip}");
        }
        assert!(public_ipv4("8.8.8.8".parse().unwrap()));
    }
    #[test]
    fn results_never_call_api_failure_closed() {
        let ip = "8.8.8.8".parse().unwrap();
        let success = node_result(
            "node",
            &serde_json::json!([{"address":"8.8.8.8", "time":0.03}]),
            ip,
            80,
        )
        .unwrap();
        assert!(success.reachable);
        assert!(success.message.contains("externally reachable"));
        let error = node_result(
            "node",
            &serde_json::json!([{"error":"Connection timed out"}]),
            ip,
            80,
        )
        .unwrap();
        assert!(!error.reachable);
        assert!(error.message.contains("does not prove"));
        assert!(node_result("node", &Value::Null, ip, 80).is_none());
        assert!(node_result(
            "node",
            &serde_json::json!([{"address":"1.1.1.1", "time":0.03}]),
            ip,
            80
        )
        .is_none());
        for value in [
            serde_json::json!([]),
            serde_json::json!([{"address":"8.8.8.8", "time":-1}]),
            serde_json::json!([{"address":"8.8.8.8", "time":"0.03"}]),
            serde_json::json!([{"address":"8.8.8.8", "time":0.03, "error":null}]),
            serde_json::json!({"address":"8.8.8.8", "time":0.03}),
        ] {
            assert!(node_result("node", &value, ip, 80).is_none());
        }
    }

    #[test]
    fn verdict_permutations_and_precedence() {
        for protocol in ["TCP", "UDP"] {
            let rows = |addresses: &[&str]| {
                addresses
                    .iter()
                    .map(|address| Listener {
                        port: 80,
                        protocol: protocol.into(),
                        address: (*address).into(),
                        pid: 123,
                    })
                    .collect::<Vec<_>>()
            };
            for external in [false, true] {
                for reachable in [false, true] {
                    for (addresses, base) in [
                        (vec![], CheckStatus::NoListener),
                        (vec!["127.0.0.1", "::1"], CheckStatus::LoopbackOnly),
                        (vec!["not-an-ip"], CheckStatus::Unknown),
                        (vec!["::1", "not-an-ip"], CheckStatus::Unknown),
                        (vec!["0.0.0.0"], CheckStatus::LocalOnly),
                        (vec!["::"], CheckStatus::LocalOnly),
                        (vec!["192.168.1.5"], CheckStatus::LocalOnly),
                        (vec!["::1", "0.0.0.0", "not-an-ip"], CheckStatus::LocalOnly),
                    ] {
                        let expected = if protocol == "TCP" && reachable {
                            CheckStatus::Reachable
                        } else if base == CheckStatus::LocalOnly && external {
                            if protocol == "UDP" {
                                CheckStatus::UdpUnverified
                            } else {
                                CheckStatus::Unconfirmed
                            }
                        } else {
                            base
                        };
                        let result =
                            verdict(80, protocol, Ok(&rows(&addresses)), external, reachable);
                        assert_eq!(
                            result.status, expected,
                            "{protocol} {addresses:?} external={external} reachable={reachable}"
                        );
                        assert_eq!(result.port, 80);
                        assert_eq!(result.protocol, protocol);
                        assert!(result.title.chars().count() <= 180);
                        assert!(result.detail.chars().count() <= 180);
                    }
                    let result = verdict(80, protocol, Err("snapshot failed"), external, reachable);
                    assert_eq!(
                        result.status,
                        if protocol == "TCP" && reachable {
                            CheckStatus::Reachable
                        } else {
                            CheckStatus::Unknown
                        }
                    );
                }
            }
        }
        let unrelated = vec![
            Listener {
                port: 81,
                protocol: "TCP".into(),
                address: "0.0.0.0".into(),
                pid: 1,
            },
            Listener {
                port: 80,
                protocol: "UDP".into(),
                address: "0.0.0.0".into(),
                pid: 1,
            },
        ];
        let absent = verdict(80, "TCP", Ok(&unrelated), true, false);
        assert_eq!(absent.status, CheckStatus::NoListener);
        assert!(absent.detail.contains("не найдена"));
        assert!(absent.detail.contains("не подтверждён"));
    }

    #[test]
    fn mixed_external_nodes_use_typed_evidence_not_messages() {
        let ip = "8.8.8.8".parse().unwrap();
        let success = || {
            node_result(
                "slow",
                &serde_json::json!([{"address":"8.8.8.8", "time":0.5}]),
                ip,
                80,
            )
            .unwrap()
        };
        let failure = || {
            node_result(
                "fast",
                &serde_json::json!([{"error":"Connection timed out"}]),
                ip,
                80,
            )
            .unwrap()
        };
        for nodes in [vec![success(), failure()], vec![failure(), success()]] {
            let result = verdict(80, "TCP", Ok(&[]), true, nodes.iter().any(|n| n.reachable));
            assert_eq!(result.status, CheckStatus::Reachable);
            assert!(result.detail.contains("роутера"));
        }
        let spoofed_message = NodeResult {
            message: "externally reachable".into(),
            reachable: false,
            node_ip: None,
            window: None,
        };
        assert_eq!(
            verdict(80, "TCP", Ok(&[]), true, spoofed_message.reachable).status,
            CheckStatus::NoListener
        );
        let mut verified = success();
        verified.message = "Connection timed out".into();
        assert_eq!(
            verdict(80, "TCP", Err("snapshot failed"), true, verified.reachable).status,
            CheckStatus::Reachable
        );
    }
    #[test]
    fn loopback_is_not_internet_accessible() {
        let row = Listener {
            port: 80,
            protocol: "TCP".into(),
            address: "::1".into(),
            pid: 123,
        };
        assert!(listener_message(&row).contains("loopback only; not Internet-accessible"));
        assert!(external_tcp("8.8.8.8".parse().unwrap(), 80)
            .unwrap_err()
            .contains("disabled"));
    }

    #[test]
    fn ipc_shapes_and_test_mode_are_safe() {
        let request: CheckRequest =
            serde_json::from_str(r#"{"ports":"80","protocol":"BOTH","external":true}"#).unwrap();
        let outcome = check(request).unwrap();
        assert!(outcome
            .messages
            .iter()
            .any(|m| m.contains("disabled in test mode")));
        assert!(outcome
            .messages
            .iter()
            .any(|m| m.contains("External TCP check skipped")));
        assert!(outcome
            .messages
            .iter()
            .any(|m| m.contains("cannot prove UDP reachability")));
        let json = serde_json::to_value(outcome).unwrap();
        assert!(json["messages"].is_array());
        assert_eq!(json.as_object().unwrap().len(), 3);
        assert!(json["checkedAt"].as_u64().unwrap() > 0);
        assert_eq!(json["results"].as_array().unwrap().len(), 2);
        for (i, protocol) in ["TCP", "UDP"].iter().enumerate() {
            assert_eq!(json["results"][i]["port"], 80);
            assert_eq!(json["results"][i]["protocol"], *protocol);
            assert_eq!(json["results"][i]["status"], "unknown");
            assert!(json["results"][i]["title"].is_string());
            assert!(json["results"][i]["detail"].is_string());
            assert_eq!(json["results"][i].as_object().unwrap().len(), 5);
        }
    }

    #[test]
    fn statuses_serialize_as_exact_api_strings() {
        for (status, expected) in [
            (CheckStatus::Reachable, "reachable"),
            (CheckStatus::NoListener, "no-listener"),
            (CheckStatus::LoopbackOnly, "loopback-only"),
            (CheckStatus::LocalOnly, "local-only"),
            (CheckStatus::UdpUnverified, "udp-unverified"),
            (CheckStatus::Unconfirmed, "unconfirmed"),
            (CheckStatus::Unknown, "unknown"),
            (CheckStatus::VerifiedLocal, "verified-local"),
            (CheckStatus::TestUnconfirmed, "test-unconfirmed"),
        ] {
            assert_eq!(serde_json::to_value(status).unwrap(), expected);
        }
    }

    #[test]
    fn no_consent_and_udp_only_do_not_attempt_external_tcp() {
        for (protocol, external) in [("BOTH", false), ("UDP", true)] {
            let outcome = check(CheckRequest {
                ports: "80".into(),
                protocol: protocol.into(),
                external,
                test_server: false,
            })
            .unwrap();
            assert!(!outcome
                .messages
                .iter()
                .any(|m| m.contains("External TCP check skipped")
                    || m.contains("external check indeterminate")));
            assert!(outcome
                .results
                .iter()
                .all(|r| r.status == CheckStatus::Unknown));
            if !external {
                assert!(outcome
                    .messages
                    .iter()
                    .any(|m| m.contains("no third-party port probe sent")));
            } else {
                assert_eq!(outcome.results.len(), 1);
                assert_eq!(outcome.results[0].protocol, "UDP");
            }
        }
    }
}
