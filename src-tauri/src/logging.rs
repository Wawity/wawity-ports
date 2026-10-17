use crate::{checks::CheckOutcome, now, Outcome};
use std::{fs, io::Write, path::PathBuf, sync::Mutex};

static LOG: Mutex<()> = Mutex::new(());
const MAX_TEXT: usize = 64 * 1024;
const MAX_LOG: u64 = 1024 * 1024;

fn path() -> Result<PathBuf, String> {
    Ok(std::env::current_exe()
        .map_err(|e| e.to_string())?
        .parent()
        .ok_or("Executable has no parent")?
        .join("wawity-ports.log"))
}

fn bounded(text: &str) -> &str {
    let mut end = text.len().min(MAX_TEXT);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

fn append_at(path: &std::path::Path, text: &str) -> Result<(), String> {
    let entry = format!(
        "[{}]\n{}{}\n",
        now(),
        bounded(text),
        if text.len() > MAX_TEXT {
            "\n[truncated at 64 KiB]"
        } else {
            ""
        }
    );
    let size = match fs::metadata(path) {
        Ok(meta) => meta.len(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
        Err(e) => return Err(e.to_string()),
    };
    if size + entry.len() as u64 > MAX_LOG {
        let backup = path.with_extension("log.1");
        match fs::remove_file(&backup) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.to_string()),
        }
        fs::rename(path, backup).map_err(|e| e.to_string())?;
    }
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| e.to_string())?;
    file.write_all(entry.as_bytes())
        .and_then(|_| file.flush())
        .map_err(|e| e.to_string())
}

pub fn append(text: &str) -> Result<PathBuf, String> {
    let _guard = LOG.lock().map_err(|_| "Log lock failed")?;
    let path = path()?;
    append_at(&path, text)
        .map_err(|e| format!("Cannot write operation log beside executable: {e}"))?;
    Ok(path)
}

pub fn outcome(command: &str, mut result: Result<Outcome, String>) -> Result<Outcome, String> {
    crate::telemetry::note_outcome(command, &result);
    let text = match &result {
        Ok(outcome) => format!(
            "{command}\n{}",
            serde_json::to_string_pretty(outcome).unwrap_or_default()
        ),
        Err(error) => format!("{command} failed\n{error}"),
    };
    if let Err(warning) = append(&text) {
        match &mut result {
            Ok(outcome) => outcome.messages.push(format!("Warning: {warning}")),
            Err(error) => error.push_str(&format!("\nWarning: {warning}")),
        }
    }
    result
}

fn check_text(outcome: &CheckOutcome) -> String {
    let summaries = outcome
        .results
        .iter()
        .map(|r| format!("{}/{}: {}. {}", r.port, r.protocol, r.title, r.detail))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "check_ports\n{}\nSummaries\n{summaries}\nMessages\n{}",
        serde_json::to_string_pretty(outcome).expect("CheckOutcome contains only JSON-safe values"),
        outcome.messages.join("\n")
    )
}

pub fn check_outcome(mut result: Result<CheckOutcome, String>) -> Result<CheckOutcome, String> {
    crate::telemetry::note_error("check_ports", &result);
    let text = match &result {
        Ok(outcome) => check_text(outcome),
        Err(error) => format!("check_ports failed\n{error}"),
    };
    if let Err(warning) = append(&text) {
        match &mut result {
            Ok(outcome) => outcome.messages.push(format!("Warning: {warning}")),
            Err(error) => error.push_str(&format!("\nWarning: {warning}")),
        }
    }
    result
}

pub fn open() -> Result<String, String> {
    if cfg!(test) || std::env::var_os("WAWITY_PORTS_TEST_MODE").is_some() {
        return Err("Notepad launch disabled in test mode.".into());
    }
    let path = append("open_log")?;
    let system = std::env::var_os("SystemRoot").ok_or("SystemRoot is missing")?;
       std::process::Command::new(PathBuf::from(system).join("System32/notepad.exe"))
        .arg(&path)
        .spawn()
        .map_err(|e| format!("Cannot launch Notepad: {e}"))?;
    Ok(path.display().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn diagnostic_log_keeps_verdict_evidence_and_cleanup_summary() {
        for status in [
            crate::checks::CheckStatus::VerifiedLocal,
            crate::checks::CheckStatus::TestUnconfirmed,
        ] {
            let outcome = CheckOutcome {
                messages: vec![
                    "Local incoming observed; advertised node IP matched only within probe window."
                        .into(),
                    "Diagnostic listener stopped; no firewall rules or mappings created.".into(),
                ],
                results: vec![crate::checks::CheckResult {
                    port: 12345,
                    protocol: "TCP".into(),
                    status,
                    title: "Тестовый сервер остановлен".into(),
                    detail: "Готовность рабочей программы не подтверждена.".into(),
                }],
                checked_at: 123,
            };
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("wawity-ports.log");
            append_at(&path, &check_text(&outcome)).unwrap();
            let text = fs::read_to_string(path).unwrap();
            assert!(text.contains(&serde_json::to_string(&outcome.results[0].status).unwrap()));
            assert!(text.contains("Summaries\n12345/TCP: Тестовый сервер остановлен"));
            assert!(text.contains("Diagnostic listener stopped"));
            assert!(text.contains("within probe window"));
            assert!(text.contains("Готовность рабочей программы не подтверждена."));
        }
    }

    #[test]
    fn check_log_persists_structured_outcome_and_readable_summaries() {
        let outcome = CheckOutcome {
            messages: vec!["External check indeterminate, not closed.".into()],
            results: vec![crate::checks::CheckResult {
                port: 80,
                protocol: "TCP".into(),
                status: crate::checks::CheckStatus::Unconfirmed,
                title: "Доступ извне не подтверждён".into(),
                detail: "Тайм-аут не означает закрытый порт.".into(),
            }],
            checked_at: 123456789,
        };
        let before = serde_json::to_value(&outcome).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wawity-ports.log");
        append_at(&path, &check_text(&outcome)).unwrap();
        let log = fs::read_to_string(path).unwrap();
        let json = log
            .split("check_ports\n")
            .nth(1)
            .unwrap()
            .split("\nSummaries\n")
            .next()
            .unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(json).unwrap(),
            before
        );
        assert!(log.contains("\"checkedAt\": 123456789"));
        assert!(log
            .contains("80/TCP: Доступ извне не подтверждён. Тайм-аут не означает закрытый порт."));
        assert!(log.contains("Messages\nExternal check indeterminate, not closed."));
        assert_eq!(serde_json::to_value(&outcome).unwrap(), before);
    }

    #[test]
    fn unicode_is_bounded_and_log_rotates() {
        let text = "x".repeat(MAX_TEXT - 1) + "\u{00e9}";
        assert_eq!(bounded(&text).len(), MAX_TEXT - 1);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wawity-ports.log");
        fs::write(&path, vec![b'x'; MAX_LOG as usize]).unwrap();
        append_at(&path, "next").unwrap();
        assert_eq!(
            fs::metadata(path.with_extension("log.1")).unwrap().len(),
            MAX_LOG
        );
        assert!(fs::read_to_string(&path).unwrap().contains("next"));
        append_at(&path, &"x".repeat(MAX_TEXT + 10)).unwrap();
        assert!(fs::read_to_string(path)
            .unwrap()
            .contains("[truncated at 64 KiB]"));
    }
}
