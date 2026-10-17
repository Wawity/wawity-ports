#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![cfg_attr(test, allow(dead_code))]

use wawity_ports::ports;
mod checks;
mod diagnostic;
mod lease;
mod logging;
mod mapping;
mod network;
mod router;
mod telemetry;
mod udp;

use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    process::Command,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};
#[cfg(not(test))]
use tauri::Manager;

const GROUP: &str = "Wawity Ports";
static OPERATIONS: Mutex<()> = Mutex::new(());

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OpenRequest {
    ports: String,
    protocol: String,
    router: bool,
    public: bool,
    #[serde(default)]
    auto_renew: bool,
    #[serde(default)]
    allow_nat_pmp: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Rule {
    id: String,
    port: u16,
    protocol: String,
    firewall: bool,
    router: String,
    external_ip: Option<String>,
    method: Option<String>,
    expires_at: Option<u64>,
    auto_renew: bool,
    renewal_state: String,
    last_error: Option<String>,
}

#[derive(Serialize)]
struct Status {
    admin: bool,
    rules: Vec<Rule>,
}
#[derive(Serialize)]
struct Outcome {
    rules: Vec<Rule>,
    messages: Vec<String>,
}

#[derive(Clone, Default, Deserialize, Serialize)]
struct RouterIntent {
    gateway: Option<String>,
    local_ip: Option<String>,
    expires_at: Option<u64>,
    external_ip: Option<String>,
    state: String,
    #[serde(default)]
    control_url: Option<String>,
    #[serde(default)]
    root_url: Option<String>,
    #[serde(default)]
    control_schema_url: Option<String>,
    #[serde(default)]
    control_schema: Option<std::collections::HashMap<String, Vec<String>>>,
    #[serde(default)]
    service_type: Option<String>,
    #[serde(default)]
    interface_index: Option<u32>,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    nonce: Option<[u8; 12]>,
    #[serde(default)]
    internal_port: Option<u16>,
    #[serde(default)]
    external_port: Option<u16>,
    #[serde(default)]
    protocol: Option<String>,
    #[serde(default)]
    granted_at: Option<u64>,
    #[serde(default)]
    granted_lifetime: Option<u32>,
    #[serde(default)]
    epoch: Option<u32>,
    #[serde(default)]
    epoch_received_at: Option<u64>,
    #[serde(default)]
    auto_renew: bool,
    #[serde(default)]
    allow_nat_pmp: bool,
    #[serde(default = "renewal_off")]
    renewal_state: String,
    #[serde(default)]
    last_error: Option<String>,
    #[serde(default)]
    next_renewal: Option<u64>,
    #[serde(default)]
    renewal_failures: u32,
    #[serde(default)]
    mutation_attempted: bool,
    #[serde(default)]
    confirmed: bool,
    #[serde(default, flatten)]
    extra: BTreeMap<String, serde_json::Value>,
}
type Journal = BTreeMap<String, RouterIntent>;

fn renewal_off() -> String {
    "off".into()
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn journal_path() -> Result<PathBuf, String> {
    Ok(std::env::current_exe()
        .map_err(|e| e.to_string())?
        .parent()
        .ok_or("Executable has no parent")?
        .join("wawity-ports-state.json"))
}

fn load() -> Result<Journal, String> {
    if cfg!(test) || std::env::var_os("WAWITY_PORTS_TEST_MODE").is_some() {
        return Ok(Journal::new());
    }
    match fs::read(journal_path()?) {
        Ok(data) => {
            let journal: Journal = serde_json::from_slice(&data)
                .map_err(|e| format!("Cannot read router state; no changes made: {e}"))?;
            for id in journal.keys() {
                ports::parse_id(id)?;
            }
            Ok(journal)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Journal::new()),
        Err(e) => Err(format!("Cannot read router state: {e}")),
    }
}

fn save(journal: &Journal) -> Result<(), String> {
    if cfg!(test) || std::env::var_os("WAWITY_PORTS_TEST_MODE").is_some() {
        return Err("Live journal writes disabled in test mode.".into());
    }
    use std::io::Write;
    let path = journal_path()?;
    let mut file =
        tempfile::NamedTempFile::new_in(path.parent().unwrap()).map_err(|e| e.to_string())?;
    file.write_all(&serde_json::to_vec_pretty(journal).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    file.as_file().sync_all().map_err(|e| e.to_string())?;
    file.persist(&path)
        .map_err(|e| format!("Cannot persist router state beside executable: {e}"))?;
    Ok(())
}

fn powershell(script: &str) -> Result<String, String> {
    if cfg!(test) || std::env::var_os("WAWITY_PORTS_TEST_MODE").is_some() {
        return Err("PowerShell operations disabled in test mode.".into());
    }
    #[cfg(not(windows))]
    {
        let _ = script;
        Err("Windows is required.".into())
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let system = std::env::var_os("SystemRoot").ok_or("SystemRoot is missing")?;
        let exe = PathBuf::from(system).join("System32/WindowsPowerShell/v1.0/powershell.exe");
        let mut child = Command::new(exe).creation_flags(0x08000000)
            .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-Command"])
            .arg(format!("$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false); {script}"))
            .stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped())
            .spawn().map_err(|e| format!("PowerShell could not start: {e}"))?;
        let read = |mut pipe: Box<dyn std::io::Read + Send>| {
            std::thread::spawn(move || {
                let mut data = Vec::new();
                let result = pipe.read_to_end(&mut data);
                result.map(|_| data)
            })
        };
        let stdout = read(Box::new(child.stdout.take().unwrap()));
        let stderr = read(Box::new(child.stderr.take().unwrap()));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        let status = loop {
            if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
                break status;
            }
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(
                    "PowerShell exceeded fifteen seconds; any attempted change may be unconfirmed."
                        .into(),
                );
            }
            std::thread::sleep(std::time::Duration::from_millis(30));
        };
        let stdout = stdout
            .join()
            .map_err(|_| "PowerShell output reader failed")?
            .map_err(|e| e.to_string())?;
        let stderr = stderr
            .join()
            .map_err(|_| "PowerShell error reader failed")?
            .map_err(|e| e.to_string())?;
        if !status.success() {
            return Err(String::from_utf8_lossy(&stderr).trim().to_string());
        }
        Ok(String::from_utf8_lossy(&stdout)
            .trim_start_matches('\u{feff}')
            .trim()
            .to_string())
    }
}

fn admin() -> Result<bool, String> {
    Ok(powershell("([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)")? == "True")
}

fn refresh(journal: &Journal) -> Result<Vec<Rule>, String> {
       let script = r#"$items=@(Get-NetFirewallRule -PolicyStore ActiveStore | Where-Object { $_.Name -like 'WawityPorts-*' -and $_.Group -eq 'Wawity Ports' } | ForEach-Object {
      $r=$_; $f=$r | Get-NetFirewallPortFilter;
      [pscustomobject]@{ id=$r.Name; enabled=($r.Enabled -eq 'True' -and $r.Direction -eq 'Inbound' -and $r.Action -eq 'Allow'); port=[string]$f.LocalPort; protocol=[string]$f.Protocol }
    }); ConvertTo-Json -InputObject $items -Compress"#;
    #[derive(Deserialize)]
    struct FirewallRow {
        id: String,
        enabled: bool,
        port: String,
        protocol: String,
    }
    let rows: Vec<FirewallRow> = serde_json::from_str(&powershell(script)?)
        .map_err(|e| format!("Invalid firewall response: {e}"))?;
    let mut rules = BTreeMap::new();
    for row in rows {
        if let Ok((port, protocol)) = ports::parse_id(&row.id) {
            let enabled = row.enabled
                && row.port == port.to_string()
                && (row.protocol == protocol
                    || row.protocol == if protocol == "TCP" { "6" } else { "17" });
            rules.insert(
                row.id.clone(),
                Rule {
                    id: row.id.clone(),
                    port,
                    protocol: protocol.into(),
                    firewall: enabled,
                    router: "not-requested".into(),
                    external_ip: None,
                    method: None,
                    expires_at: None,
                    auto_renew: false,
                    renewal_state: "off".into(),
                    last_error: None,
                },
            );
        }
    }
    for (id, intent) in journal {
        let (port, protocol) = ports::parse_id(id)?;
        let rule = rules.entry(id.clone()).or_insert_with(|| Rule {
            id: id.clone(),
            port,
            protocol: protocol.into(),
            firewall: false,
            router: "not-requested".into(),
            external_ip: None,
            method: None,
            expires_at: None,
            auto_renew: false,
            renewal_state: "off".into(),
            last_error: None,
        });
               rule.router = if intent.state == "mapped" {
            "unverified"
        } else {
            &intent.state
        }
        .into();
        rule.external_ip = intent.external_ip.clone();
        rule.method = mapping::saved_method(intent).map(str::to_string);
        rule.expires_at = intent.expires_at;
        rule.auto_renew = intent.auto_renew;
        rule.renewal_state = lease::visible_state(intent, now()).into();
        rule.last_error = intent.last_error.clone();
    }
    Ok(rules.into_values().collect())
}

fn open_firewall(id: &str, port: u16, protocol: &str, public: bool) -> Result<(), String> {
    let profiles = if public {
        "Domain,Private,Public"
    } else {
        "Domain,Private"
    };
    powershell(&format!(
        r#"$r=@(Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object {{ $_.Name -eq '{id}' }});
      if ($r.Count -gt 0) {{
        if ($r.Count -ne 1 -or $r[0].Group -ne '{GROUP}') {{ throw 'Rule name belongs to another application; left unchanged.' }}
        $r[0] | Set-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -Profile {profiles};
        $r[0] | Get-NetFirewallPortFilter | Set-NetFirewallPortFilter -Protocol {protocol} -LocalPort {port} -RemotePort Any;
      }} else {{
        New-NetFirewallRule -PolicyStore PersistentStore -Name '{id}' -DisplayName '{id}' -Group '{GROUP}' -Description 'Managed by Wawity Ports' -Enabled True -Direction Inbound -Action Allow -Profile {profiles} -Protocol {protocol} -LocalPort {port} | Out-Null
      }}"#
    ))?;
    Ok(())
}

fn status_sync() -> Result<Status, String> {
    let _guard = OPERATIONS
        .lock()
        .map_err(|_| "Backend operation lock failed")?;
    Ok(Status {
        admin: admin()?,
        rules: refresh(&load()?)?,
    })
}

fn open_sync(request: OpenRequest) -> Result<Outcome, String> {
    let ports = ports::parse_ports(&request.ports)?;
    let protocols: &[&str] = match request.protocol.as_str() {
        "TCP" => &["TCP"],
        "UDP" => &["UDP"],
        "BOTH" => &["TCP", "UDP"],
        _ => return Err("Protocol must be TCP, UDP, or BOTH.".into()),
    };
    let _guard = OPERATIONS
        .lock()
        .map_err(|_| "Backend operation lock failed")?;
    if !admin()? {
        return Err("Administrator privileges are required. Relaunch and approve UAC.".into());
    }
    let mut journal = load()?;
    let mut messages = Vec::new();
    for port in ports {
        for protocol in protocols {
            let id = format!("WawityPorts-{port}-{protocol}");
            match open_firewall(&id, port, protocol, request.public) {
                Ok(()) => messages.push(format!(
                    "{port}/{protocol}: firewall rule enabled on {} profiles.",
                    if request.public {
                        "Domain, Private, Public (consented)"
                    } else {
                        "Domain, Private"
                    }
                )),
                Err(e) => {
                    messages.push(format!("{port}/{protocol}: firewall failed: {e}"));
                    continue;
                }
            }
            if request.router {
                let result = apply_router_request(
                    &id,
                    request.auto_renew,
                    request.allow_nat_pmp,
                    &mut journal,
                    save,
                    |journal, allow_nat| mapping::open(&id, port, protocol, journal, allow_nat),
                );
                match result {
                    Ok(note) => messages.push(format!("{port}/{protocol}: {note}")),
                    Err(e) => {
                        if let Some(intent) = journal.get_mut(&id) {
                            intent.last_error = Some(e.clone());
                            if intent.auto_renew {
                                intent.renewal_state = "paused".into();
                            }
                            if !matches!(
                                intent.state.as_str(),
                                "mapped" | "unverified" | "conflict" | "closing" | "close-failed"
                            ) {
                                intent.state = "failed".into();
                            }
                        }
                        messages.push(format!(
                            "{port}/{protocol}: firewall succeeded; router failed: {e}"
                        ));
                    }
                }
                if let Err(e) = save(&journal) {
                    messages.push(format!("Router state persistence failed: {e}"));
                }
            }
        }
    }
    let mut rules = refresh(&journal).map_err(|e| {
        format!(
            "Changes were attempted but firewall refresh failed: {e}\n{}",
            messages.join("\n")
        )
    })?;
    for rule in &mut rules {
        if journal.get(&rule.id).is_some_and(|entry| {
            entry.state == "mapped" && entry.expires_at.is_some_and(|end| end > now())
        }) {
                       if messages.iter().any(|message| {
                ["UPnP", "PCP", "NAT-PMP"].iter().any(|method| {
                    message
                        .starts_with(&format!("{}/{}: {method} mapped", rule.port, rule.protocol))
                })
            }) {
                rule.router = "mapped".into();
            }
        }
    }
    Ok(Outcome { rules, messages })
}

fn apply_router_request(
    id: &str,
    auto_renew: bool,
    allow_nat: bool,
    journal: &mut Journal,
    persist: impl Fn(&Journal) -> Result<(), String>,
    open: impl FnOnce(&mut Journal, bool) -> Result<String, String>,
) -> Result<String, String> {
    let previous = journal.get(id).cloned();
    let entry = journal.entry(id.into()).or_insert_with(|| RouterIntent {
        state: "pending".into(),
        ..RouterIntent::default()
    });
          lease::disable(entry);
    entry.allow_nat_pmp |= allow_nat;
    if let Err(error) = persist(journal) {
        if let Some(previous) = previous {
            journal.insert(id.into(), previous);
        } else {
            journal.remove(id);
        }
        return Err(error);
    }
    let mut note = open(journal, allow_nat)?;
    if auto_renew {
        let entry = journal
            .get_mut(id)
            .ok_or("Missing acknowledged router intent")?;
        lease::enable(entry, now())?;
        if let Some(error) = &entry.last_error {
            note.push_str(&format!(" Auto-renew paused: {error}"));
        }
    }
    Ok(note)
}

fn close_sync(id: String) -> Result<Outcome, String> {
    let (port, protocol) = ports::parse_id(&id)?;
    let _guard = OPERATIONS
        .lock()
        .map_err(|_| "Backend operation lock failed")?;
    if !admin()? {
        return Err("Administrator privileges are required.".into());
    }
    let mut journal = load()?;
    let mut messages = Vec::new();
       if let Some(intent) = journal.get_mut(&id) {
        lease::disable(intent);
        intent.state = "closing".into();
        save(&journal)?;
    }
    match powershell(&format!(
        r#"$r=@(Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object {{ $_.Name -eq '{id}' }});
      if (@($r | Where-Object {{ $_.Group -ne '{GROUP}' }}).Count -gt 0) {{ throw 'Foreign rule left unchanged.' }}
      $r | Remove-NetFirewallRule"#
    )) {
        Ok(_) => messages.push(format!(
            "{port}/{protocol}: app-owned firewall rule removed (or already absent)."
        )),
        Err(e) => messages.push(format!("{port}/{protocol}: firewall removal failed: {e}")),
    }
    if let Some(intent) = journal.get(&id).cloned() {
        match mapping::close(&id, port, protocol, &intent) {
            Ok(note) => {
                journal.remove(&id);
                messages.push(note);
            }
            Err(e) => {
                if let Some(entry) = journal.get_mut(&id) {
                    entry.state = "close-failed".into();
                    entry.last_error = Some(e.clone());
                }
                messages.push(format!(
                    "Router removal failed; retained intent for retry: {e}"
                ));
            }
        }
        if let Err(e) = save(&journal) {
            messages.push(e);
        }
    }
    let rules = refresh(&journal).map_err(|e| {
        format!(
            "Changes were attempted but firewall refresh failed: {e}\n{}",
            messages.join("\n")
        )
    })?;
    Ok(Outcome { rules, messages })
}

#[tauri::command]
async fn vpn_status() -> Result<Vec<String>, String> {
    let result = tauri::async_runtime::spawn_blocking(|| {
               let output = powershell(r#"$names=@(Get-NetAdapter -IncludeHidden | Where-Object { $_.Status -eq 'Up' -and ($_.Name + ' ' + $_.InterfaceDescription) -match '(?i)wawity|sing-tun|wintun|wireguard|openvpn|\btap\b|tailscale|zerotier|radmin|mullvad|proton|nordvpn|surfshark|\bvpn\b' } | ForEach-Object { $_.Name }); $names += @(Get-VpnConnection -ErrorAction SilentlyContinue | Where-Object ConnectionStatus -eq 'Connected' | ForEach-Object Name); $names += @(Get-VpnConnection -AllUserConnection -ErrorAction SilentlyContinue | Where-Object ConnectionStatus -eq 'Connected' | ForEach-Object Name); ConvertTo-Json -InputObject @($names | Sort-Object -Unique) -Compress"#)?;
        serde_json::from_str::<Vec<String>>(&output).map_err(|e| format!("VPN detection failed: {e}"))
    })
    .await
    .map_err(|e| e.to_string())
    .and_then(|r| r);
    telemetry::note_error("vpn_status", &result);
    result
}

#[tauri::command]
async fn status() -> Result<Status, String> {
    let result = tauri::async_runtime::spawn_blocking(status_sync)
        .await
        .map_err(|e| e.to_string())
        .and_then(|r| r);
    telemetry::note_error("status", &result);
    result
}
#[tauri::command]
async fn open_ports(request: OpenRequest) -> Result<Outcome, String> {
    let result = tauri::async_runtime::spawn_blocking(move || open_sync(request))
        .await
        .map_err(|e| e.to_string())
        .and_then(|r| r);
    logging::outcome("open_ports", result)
}
#[tauri::command]
async fn close_rule(id: String) -> Result<Outcome, String> {
    let result = tauri::async_runtime::spawn_blocking(move || close_sync(id))
        .await
        .map_err(|e| e.to_string())
        .and_then(|r| r);
    logging::outcome("close_rule", result)
}

fn set_auto_renew_sync(id: String, enabled: bool) -> Result<Outcome, String> {
    ports::parse_id(&id)?;
    let _guard = OPERATIONS
        .lock()
        .map_err(|_| "Backend operation lock failed")?;
    let mut journal = load()?;
    if enabled && !refresh(&journal)?.iter().any(|r| r.id == id && r.firewall) {
        return Err(
            "Own firewall missing, disabled or altered; auto-renew cannot be enabled.".into(),
        );
    }
    let intent = journal
        .get_mut(&id)
        .ok_or("No saved router lease for this rule")?;
    if enabled {
        lease::enable(intent, now())?;
    } else {
        lease::disable(intent);
    }
    save(&journal)?;
    let entry = &journal[&id];
    let note = if !enabled {
        "disabled".into()
    } else if entry.renewal_state == "paused" {
        format!(
            "requested but paused: {}",
            entry.last_error.as_deref().unwrap_or("Renewal ineligible")
        )
    } else {
        "enabled".into()
    };
    Ok(Outcome {rules:refresh(&journal)?,messages:vec![format!("{id}: auto-renew {note}. Disabling does not delete the mapping. Finite leases renew only while the app is running; no service/autostart installed.")]})
}

#[tauri::command]
async fn set_auto_renew(id: String, enabled: bool) -> Result<Outcome, String> {
    let result = tauri::async_runtime::spawn_blocking(move || set_auto_renew_sync(id, enabled))
        .await
        .map_err(|e| e.to_string())
        .and_then(|r| r);
    logging::outcome("set_auto_renew", result)
}

#[tauri::command]
async fn network_diagnostics() -> Result<network::NetworkDiagnostics, String> {
    let result: Result<network::NetworkDiagnostics, String> =
        tauri::async_runtime::spawn_blocking(network::diagnostics)
            .await
            .map_err(|e| e.to_string());
    telemetry::note_error("network_diagnostics", &result);
    result
}

#[tauri::command]
async fn check_ports(request: checks::CheckRequest) -> Result<checks::CheckOutcome, String> {
    let result = tauri::async_runtime::spawn_blocking(move || checks::check(request))
        .await
        .map_err(|e| e.to_string())
        .and_then(|r| r);
    logging::check_outcome(result)
}

#[tauri::command]
async fn write_log(text: String) -> Result<String, String> {
    let result = tauri::async_runtime::spawn_blocking(move || {
        logging::append(&text).map(|p| p.display().to_string())
    })
    .await
    .map_err(|e| e.to_string())
    .and_then(|r| r);
    telemetry::note_error("write_log", &result);
    result
}

#[tauri::command]
async fn open_log() -> Result<String, String> {
    let result = tauri::async_runtime::spawn_blocking(logging::open)
        .await
        .map_err(|e| e.to_string())
        .and_then(|r| r);
    telemetry::note_error("open_log", &result);
    result
}

#[cfg(target_os = "windows")]
fn apply_window_effects(window: &tauri::Window) {
    use windows::Win32::Foundation::HWND;
    use windows::Win32::Graphics::Dwm::{
        DwmSetWindowAttribute, DWMWA_WINDOW_CORNER_PREFERENCE, DWMWCP_ROUND,
    };
    let hwnd = window.hwnd().unwrap();
    let hwnd_val = HWND(hwnd.0 as _);
    unsafe {
        let corner_pref = DWMWCP_ROUND;
        let _ = DwmSetWindowAttribute(
            hwnd_val,
            DWMWA_WINDOW_CORNER_PREFERENCE,
            &corner_pref as *const _ as *const _,
            std::mem::size_of_val(&corner_pref) as u32,
        );
    }
}

#[cfg(not(target_os = "windows"))]
fn apply_window_effects(_window: &tauri::Window) {}

#[cfg(not(test))]
fn main() {
    let instance = match Instance::acquire() {
        Ok(instance) => instance,
        Err(error) => {
            eprintln!("Wawity Ports startup refused: {error}");
            return;
        }
    };
    tauri::Builder::default()
        .manage(instance)
        .invoke_handler(tauri::generate_handler![
            status,
            vpn_status,
            open_ports,
            close_rule,
            set_auto_renew,
            network_diagnostics,
            check_ports,
            write_log,
            open_log
        ])
        .setup(|app| {
            let win = app.get_window("main").unwrap();
            apply_window_effects(&win);
            if std::env::var_os("WAWITY_PORTS_TEST_MODE").is_none() {
                               let _ = std::thread::Builder::new()
                    .name("telemetry-init".into())
                    .spawn(telemetry::init);
                let state = app.state::<Instance>();
                let stop = state.stop.clone();
                let lock = state._file.clone();
                std::thread::Builder::new()
                    .name("lease-renewal".into())
                    .spawn(move || {
                                               let _lock = lock;
                        while !stop.load(std::sync::atomic::Ordering::Acquire) {
                            std::thread::sleep(std::time::Duration::from_secs(15));
                            if stop.load(std::sync::atomic::Ordering::Acquire) {
                                break;
                            }
                                                       let _ = lease::background_tick();
                        }
                    })?;
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("Wawity Ports startup failed");
}

struct Instance {
    _file: std::sync::Arc<fs::File>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl Instance {
    fn acquire() -> Result<Self, String> {
        let path = journal_path()?.with_file_name("wawity-ports-instance.lock");
        Self::acquire_at(&path)
    }

    fn acquire_at(path: &std::path::Path) -> Result<Self, String> {
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .map_err(|e| format!("Cannot open directory process lock: {e}"))?;
        fs2::FileExt::try_lock_exclusive(&file).map_err(|_| "Another Wawity Ports process owns this executable directory; no second scheduler started.")?;
        Ok(Self {
            _file: std::sync::Arc::new(file),
            stop: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
    }
}

impl Drop for Instance {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejected_nat_consent_and_failed_outcome_save_cannot_enroll_on_restart() {
        let id = "WawityPorts-80-TCP";
        for previously_enabled in [false, true] {
            let mut entry = RouterIntent {
                gateway: Some("192.168.1.1:5351".into()),
                method: Some("NAT-PMP".into()),
                state: "mapped".into(),
                allow_nat_pmp: true,
                auto_renew: previously_enabled,
                ..RouterIntent::default()
            };
            lease::grant(&mut entry, now(), 3600);
            let mut journal = Journal::from([(id.into(), entry)]);
            let durable = std::cell::RefCell::new(Vec::new());
            let persist = |journal: &Journal| {
                *durable.borrow_mut() = serde_json::to_vec(journal).unwrap();
                Ok(())
            };
            let error = apply_router_request(
                id,
                true,
                false,
                &mut journal,
                persist,
                |journal, allow_nat| mapping::open(id, 80, "TCP", journal, allow_nat),
            )
            .unwrap_err();
            assert!(error.contains("checkbox consent"));
            journal.get_mut(id).unwrap().last_error = Some(error);
            let failed_outcome_save =
                |_: &Journal| -> Result<(), String> { Err("disk full".into()) };
            assert!(failed_outcome_save(&journal).is_err());
            let mut restart: Journal = serde_json::from_slice(&durable.borrow()).unwrap();
            assert!(restart[id].confirmed); 
            assert!(!restart[id].auto_renew);
            assert_eq!(restart[id].renewal_state, "off");
            assert!(restart[id].next_renewal.is_none());
            lease::tick(
                &mut restart,
                now(),
                |_| true,
                |_| Ok(()),
                |_, _| panic!("Rejected request enrolled after restart"),
            )
            .unwrap();
        }
    }

    #[test]
    fn enrollment_waits_for_acknowledgement_and_failed_success_save_stays_off_on_disk() {
        let id = "WawityPorts-80-TCP";
        let mut journal = Journal::new();
        let durable = std::cell::RefCell::new(Vec::new());
        apply_router_request(
            id,
            true,
            true,
            &mut journal,
            |j| {
                *durable.borrow_mut() = serde_json::to_vec(j).unwrap();
                Ok(())
            },
            |j, allow_nat| {
                assert!(allow_nat);
                assert!(!j[id].auto_renew);
                let entry = j.get_mut(id).unwrap();
                entry.method = Some("NAT-PMP".into());
                entry.state = "mapped".into();
                lease::grant(entry, now(), 3600);
                *durable.borrow_mut() = serde_json::to_vec(j).unwrap();
                Ok("NAT-PMP mapped".into())
            },
        )
        .unwrap();
        assert!(journal[id].auto_renew);
        assert_eq!(journal[id].renewal_state, "scheduled");
               let mut restart: Journal = serde_json::from_slice(&durable.borrow()).unwrap();
        assert!(!restart[id].auto_renew);
        lease::tick(
            &mut restart,
            now(),
            |_| true,
            |_| Ok(()),
            |_, _| panic!("Unsaved enrollment"),
        )
        .unwrap();
        *durable.borrow_mut() = serde_json::to_vec(&journal).unwrap();
        let restart: Journal = serde_json::from_slice(&durable.borrow()).unwrap();
        assert!(restart[id].auto_renew);
        assert_eq!(restart[id].renewal_state, "scheduled");
    }

    #[test]
    fn shipped_request_and_journal_migration_preserve_unknown_data() {
        let request: OpenRequest =
            serde_json::from_str(r#"{"ports":"80","protocol":"TCP","router":true,"public":false}"#)
                .unwrap();
        assert!(!request.auto_renew);
        assert!(!request.allow_nat_pmp);
        let request:OpenRequest=serde_json::from_str(r#"{"ports":"80","protocol":"TCP","router":true,"public":false,"autoRenew":true,"allowNatPmp":true}"#).unwrap();
        assert!(request.auto_renew);
        assert!(request.allow_nat_pmp);
        for field in ["autoRenew", "allowNatPmp"] {
            let mut value =
                serde_json::json!({"ports":"80","protocol":"TCP","router":true,"public":false});
            value[field] = serde_json::Value::Null;
            assert!(serde_json::from_value::<OpenRequest>(value).is_err());
        }
        let legacy = r#"{"WawityPorts-80-TCP":{"gateway":"192.168.1.1:5000","local_ip":"192.168.1.10","expires_at":1234,"external_ip":"8.8.8.8","state":"mapped","futureField":{"keep":true}}}"#;
        let journal: Journal = serde_json::from_str(legacy).unwrap();
        let intent = &journal["WawityPorts-80-TCP"];
        assert!(!intent.auto_renew);
        assert!(!intent.confirmed);
        assert!(intent.nonce.is_none());
        assert_eq!(mapping::saved_method(intent), Some("UPnP"));
        assert_eq!(intent.expires_at, Some(1234));
        let serialized = serde_json::to_value(journal).unwrap();
        assert_eq!(
            serialized["WawityPorts-80-TCP"]["futureField"]["keep"],
            true
        );
        assert_eq!(
            serialized["WawityPorts-80-TCP"]["gateway"],
            "192.168.1.1:5000"
        );
        assert_eq!(serialized["WawityPorts-80-TCP"]["renewal_state"], "off");
        assert!(load().unwrap().is_empty());
        assert!(save(&Journal::new()).unwrap_err().contains("disabled"));
    }

    #[test]
    fn rule_ipc_fields_are_exact_and_lease_is_never_infinite() {
        let rule = Rule {
            id: "WawityPorts-80-TCP".into(),
            port: 80,
            protocol: "TCP".into(),
            firewall: true,
            router: "unverified".into(),
            external_ip: None,
            method: Some("PCP".into()),
            expires_at: Some(1234),
            auto_renew: true,
            renewal_state: "scheduled".into(),
            last_error: None,
        };
        let value = serde_json::to_value(rule).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 11);
        for key in [
            "id",
            "port",
            "protocol",
            "firewall",
            "router",
            "externalIp",
            "method",
            "expiresAt",
            "autoRenew",
            "renewalState",
            "lastError",
        ] {
            assert!(value.get(key).is_some(), "{key}");
        }
        assert_eq!(value["expiresAt"], 1234);
        assert_eq!(value["method"], "PCP");
        assert!(value["lastError"].is_null());
    }

    #[test]
    fn directory_lock_excludes_second_process_and_releases_without_launch() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("instance.lock");
        let first = Instance::acquire_at(&path).unwrap();
        assert!(Instance::acquire_at(&path).is_err());
        let stop = first.stop.clone();
        drop(first);
        assert!(stop.load(std::sync::atomic::Ordering::Acquire));
        let _second = Instance::acquire_at(&path).unwrap();
    }
}
