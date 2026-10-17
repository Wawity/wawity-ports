use std::collections::BTreeSet;

pub fn parse_ports(input: &str) -> Result<Vec<u16>, String> {
    let mut ports = BTreeSet::new();
    if input.trim().is_empty() || input.len() > 4096 {
        return Err("Enter 1 to 32 ports.".into());
    }
    for group in input.split(',') {
        if group.trim().is_empty() {
            return Err("Empty comma-separated port entry.".into());
        }
        for token in group.split_whitespace() {
            let number = |s: &str| -> Result<u16, String> {
                if s.is_empty() || !s.bytes().all(|c| c.is_ascii_digit()) {
                    return Err(format!("Invalid port: {s}"));
                }
                s.parse::<u16>()
                    .ok()
                    .filter(|p| *p != 0)
                    .ok_or_else(|| format!("Port must be between 1 and 65535: {s}"))
            };
            let (start, end) = match token.split_once('-') {
                Some((a, b)) => (number(a)?, number(b)?),
                None => {
                    let p = number(token)?;
                    (p, p)
                }
            };
            if start > end {
                return Err(format!("Reversed range: {token}"));
            }
            if u32::from(end) - u32::from(start) >= 32 {
                return Err("At most 32 distinct ports are allowed.".into());
            }
            ports.extend(start..=end);
            if ports.len() > 32 {
                return Err("At most 32 distinct ports are allowed.".into());
            }
        }
    }
    Ok(ports.into_iter().collect())
}

pub fn parse_id(id: &str) -> Result<(u16, &str), String> {
    let tail = id.strip_prefix("WawityPorts-").ok_or("Invalid rule id")?;
    let (port, protocol) = tail.split_once('-').ok_or("Invalid rule id")?;
    let parsed = parse_ports(port)?;
    if parsed.len() != 1 || port != parsed[0].to_string() || !matches!(protocol, "TCP" | "UDP") {
        return Err("Invalid rule id".into());
    }
    Ok((parsed[0], protocol))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accepts_and_deduplicates() {
        assert_eq!(
            parse_ports("80, 443 8000-8002,80").unwrap(),
            vec![80, 443, 8000, 8001, 8002]
        );
        assert_eq!(parse_ports("1 65535").unwrap(), vec![1, 65535]);
        assert_eq!(parse_ports("1-32").unwrap().len(), 32);
    }
    #[test]
    fn rejects_invalid_before_mutation() {
        for s in [
            "",
            " ",
            "0",
            "65536",
            "-1",
            "+1",
            "1.5",
            "a",
            "80;whoami",
            "2-1",
            "1-2-3",
            "1-",
            "1,,2",
            ",1",
            "1,",
            "1-33",
            "1-32 65535",
            "1 - 3",
        ] {
            assert!(parse_ports(s).is_err(), "accepted {s}");
        }
    }
    #[test]
    fn ids_are_exact_and_injection_safe() {
        assert_eq!(parse_id("WawityPorts-80-TCP").unwrap(), (80, "TCP"));
        for id in [
            "Other-80-TCP",
            "WawityPorts-080-TCP",
            "WawityPorts-0-UDP",
            "WawityPorts-80-BOTH",
            "WawityPorts-80-TCP'",
            "WawityPorts-1-2-TCP",
        ] {
            assert!(parse_id(id).is_err());
        }
    }
}
