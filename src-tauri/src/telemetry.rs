
use crate::Outcome;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

const ENDPOINT: &str = "https://wawity.dass-awesome.workers.dev/e/k3v9x2m8qwe4rty7asd1fgh5jkl0zxc6vbn3mqp8";
const APP: &str = "wawity-ports";
const INSTALL_FILE: &str = "wawity-ports-install-id";
const MAX_SUMMARY: usize = 200;
const MAX_EVENTS: usize = 100;

static EVENTS_SENT: AtomicUsize = AtomicUsize::new(0);
static SEEN_ERRORS: OnceLock<Mutex<BTreeSet<String>>> = OnceLock::new();

fn test_mode() -> bool {
    cfg!(test) || std::env::var_os("WAWITY_PORTS_TEST_MODE").is_some()
}

pub fn init() {
    if test_mode() {
        return;
    }
    let _ = install_id();
}

fn install_file() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()?
        .parent()
        .map(|directory| directory.join(INSTALL_FILE))
}

fn uuid_v4() -> String {
    let mut bytes = [0u8; 16];
    if getrandom::getrandom(&mut bytes).is_err() {
               let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
            .unwrap_or_default();
        let pid = u64::from(std::process::id());
        let (low, high) = (nanos ^ pid.rotate_left(17), pid ^ nanos.rotate_left(31));
        bytes[..8].copy_from_slice(&low.to_le_bytes());
        bytes[8..].copy_from_slice(&high.to_le_bytes());
    }
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: Vec<String> = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        hex[0..4].join(""),
        hex[4..6].join(""),
        hex[6..8].join(""),
        hex[8..10].join(""),
        hex[10..16].join("")
    )
}

fn is_uuid(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                *byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

fn install_id() -> String {
    static ID: OnceLock<String> = OnceLock::new();
    ID.get_or_init(|| {
        let fresh = uuid_v4();
        if test_mode() {
            return fresh;
        }
        let Some(path) = install_file() else {
            return fresh;
        };
        if let Ok(text) = std::fs::read_to_string(&path) {
            let stored = text.trim();
            if is_uuid(stored) {
                return stored.to_string();
            }
        }
               let _ = std::fs::write(&path, format!("{fresh}\n"));
        fresh
    })
    .clone()
}

pub fn redact(summary: &str) -> String {
    let path_free = summary
        .split_whitespace()
        .map(|token| {
            if token.contains('\\') || (token.contains('/') && !token.starts_with("http")) {
                "<path>"
            } else {
                token
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    let mut end = path_free.len().min(MAX_SUMMARY);
    while !path_free.is_char_boundary(end) {
        end -= 1;
    }
    path_free[..end]
        .chars()
        .map(|c| if c.is_ascii_digit() { '#' } else { c })
        .collect()
}

fn build_payload(event: &str, props: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "event": event,
        "sessionId": install_id(),
        "app": APP,
        "appVersion": env!("CARGO_PKG_VERSION"),
        "os": std::env::consts::OS,
        "props": props,
    })
}

fn permit(dedupe_key: Option<&str>) -> bool {
    if EVENTS_SENT.load(Ordering::Relaxed) >= MAX_EVENTS {
        return false;
    }
    if let Some(key) = dedupe_key {
        let Ok(mut seen) = SEEN_ERRORS
            .get_or_init(|| Mutex::new(BTreeSet::new()))
            .lock()
        else {
            return false;
        };
        if !seen.insert(key.to_string()) {
            return false;
        }
    }
    EVENTS_SENT.fetch_add(1, Ordering::Relaxed);
    true
}

fn send(payload: serde_json::Value) {
    if test_mode() {
        return;
    }
    std::thread::spawn(move || {
        let Ok(client) = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(6))
            .build()
        else {
            return;
        };
        let _ = client.post(ENDPOINT).json(&payload).send();
    });
}

fn report_error(command: &str, summary: &str) {
    if test_mode() {
        return;
    }
    let summary = redact(summary);
    if summary.is_empty() || !permit(Some(&format!("error:{command}:{summary}"))) {
        return;
    }
    send(build_payload(
        "ports_error",
        serde_json::json!({ "command": command, "summary": summary }),
    ));
}

pub fn note_error<T>(command: &str, result: &Result<T, String>) {
    if let Err(error) = result {
        report_error(command, error);
    }
}

pub fn note_outcome(command: &str, result: &Result<Outcome, String>) {
    if test_mode() {
        return;
    }
    match result {
        Err(error) => report_error(command, error),
        Ok(outcome) => {
            if command != "open_ports" {
                return;
            }
            for (event, summary) in classify_open(outcome) {
                match summary {
                    Some(message) => report_error(command, &message),
                    None => {
                        if permit(None) {
                            send(build_payload(
                                event,
                                serde_json::json!({ "router": "mapped" }),
                            ));
                        }
                    }
                }
            }
        }
    }
}

fn classify_open(outcome: &Outcome) -> Vec<(&'static str, Option<String>)> {
    let mut events = Vec::new();
    if outcome.rules.iter().any(|rule| rule.router == "mapped") {
        events.push(("ports_opened", None));
    }
    for message in outcome
        .messages
        .iter()
        .filter(|message| looks_failed(message))
    {
        events.push(("ports_error", Some(message.clone())));
    }
    events
}

fn looks_failed(message: &str) -> bool {
    message.to_lowercase().contains("failed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_matches_wawity_shape_and_privacy_spec() {
        let error = build_payload(
            "ports_error",
            serde_json::json!({ "command": "open_ports", "summary": "firewall failed: boom" }),
        );
        let mut keys: Vec<&str> = error
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            ["app", "appVersion", "event", "os", "props", "sessionId"]
        );
        assert_eq!(error["event"], "ports_error");
        assert_eq!(error["app"], "wawity-ports");
        assert_eq!(error["appVersion"], env!("CARGO_PKG_VERSION"));
        assert_eq!(error["os"], std::env::consts::OS);
        assert!(is_uuid(error["sessionId"].as_str().unwrap()));
        assert_eq!(error["props"]["command"], "open_ports");
        assert_eq!(error["props"]["summary"], "firewall failed: boom");

        let success = build_payload(
            "ports_opened",
            serde_json::json!({ "router": "mapped" }),
        );
        assert_eq!(success["event"], "ports_opened");
        assert_eq!(success["app"], "wawity-ports");
        assert!(is_uuid(success["sessionId"].as_str().unwrap()));
        assert_eq!(success["props"]["router"], "mapped");
        let mut success_keys: Vec<&str> = success
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        success_keys.sort_unstable();
        assert_eq!(
            success_keys,
            ["app", "appVersion", "event", "os", "props", "sessionId"]
        );
    }

    #[test]
    fn summaries_hide_ports_addresses_and_paths() {
        assert_eq!(
            redact("54321/TCP firewall failed: 192.168.1.7:49152 refused"),
            "<path> firewall failed: ###.###.#.#:##### refused"
        );
        assert_eq!(
            redact("cannot read C:\\Users\\me\\secret.txt today"),
            "cannot read <path> today"
        );
        assert_eq!(
            redact("http://192.168.1.1:5000 control unreachable"),
            "http://###.###.#.#:#### control unreachable"
        );
        assert_eq!(redact("clean restart"), "clean restart");
        assert_eq!(redact(&"x".repeat(500)).len(), MAX_SUMMARY);
               assert_eq!(redact(&"✓".repeat(67)).chars().count(), 66);
        assert_eq!(redact(&"Ø".repeat(150)).chars().count(), 100);
        assert!(redact(&"Ø".repeat(150)).chars().all(|c| c == 'Ø'));
    }

    #[test]
    fn install_id_is_a_stable_random_uuid_and_never_touches_disk_in_test_mode() {
        let path = install_file();
        let before = path.as_ref().map(|p| p.exists());
        let id = install_id();
        assert!(is_uuid(&id));
        assert_eq!(id, install_id());
        let (a, b) = (uuid_v4(), uuid_v4());
        assert_ne!(a, b);
        assert_eq!(
            a.split('-').map(str::len).collect::<Vec<_>>(),
            [8, 4, 4, 4, 12]
        );
        assert_eq!(path.as_ref().map(|p| p.exists()), before);
    }

    #[test]
    fn open_classification_follows_the_two_event_spec() {
        let rule = |router: &str| crate::Rule {
            id: "WawityPorts-80-TCP".into(),
            port: 80,
            protocol: "TCP".into(),
            firewall: true,
            router: router.into(),
            external_ip: None,
            method: None,
            expires_at: None,
            auto_renew: false,
            renewal_state: "off".into(),
            last_error: None,
        };
        let success = Outcome {
            rules: vec![rule("mapped")],
            messages: vec!["80/TCP: UPnP mapped for 7200 seconds.".into()],
        };
        assert_eq!(classify_open(&success), vec![("ports_opened", None)]);
        let partial = Outcome {
            rules: vec![],
            messages: vec!["80/TCP: firewall succeeded; router failed: no IGD response".into()],
        };
        assert_eq!(
            classify_open(&partial),
            vec![(
                "ports_error",
                Some("80/TCP: firewall succeeded; router failed: no IGD response".to_string())
            )]
        );
        let plain = Outcome {
            rules: vec![rule("not-requested")],
            messages: vec!["80/TCP: firewall rule enabled on Domain, Private profiles.".into()],
        };
        assert!(classify_open(&plain).is_empty());
        let quoted_failure = Outcome {
            rules: vec![],
            messages: vec!["wish: 'failed' quoted but nothing failed".into()],
        };
        assert_eq!(classify_open(&quoted_failure).len(), 1);
    }

    #[test]
    fn test_mode_disables_dispatch_and_disk() {
        assert!(test_mode());
        let before = EVENTS_SENT.load(Ordering::Relaxed);
        report_error("open_ports", "firewall failed: 80 refused");
        note_error("status", &Err::<(), _>("PowerShell could not start".into()));
        let mapped = crate::Rule {
            id: "WawityPorts-80-TCP".into(),
            port: 80,
            protocol: "TCP".into(),
            firewall: true,
            router: "mapped".into(),
            external_ip: None,
            method: Some("UPnP".into()),
            expires_at: Some(1),
            auto_renew: false,
            renewal_state: "off".into(),
            last_error: None,
        };
        note_outcome(
            "open_ports",
            &Ok(Outcome {
                rules: vec![mapped],
                messages: vec![],
            }),
        );
        note_outcome(
            "close_rule",
            &Err::<Outcome, _>("Administrator privileges are required.".into()),
        );
        assert_eq!(EVENTS_SENT.load(Ordering::Relaxed), before);
    }
}
