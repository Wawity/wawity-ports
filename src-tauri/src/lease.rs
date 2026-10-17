use crate::{mapping, now, ports, refresh, save, Journal, RouterIntent};

const MIN_RENEWABLE_LEASE: u32 = 60;
pub const SHORT_LEASE_ERROR: &str = "Granted lease is 60 seconds or less; automatic renewal is unsupported by the 15-second worker. Mapping retained until its finite deadline, with no renewal scheduled.";

pub fn disable(intent: &mut RouterIntent) {
    intent.auto_renew = false;
    intent.renewal_state = "off".into();
    intent.next_renewal = None;
}

pub fn grant(intent: &mut RouterIntent, started: u64, lifetime: u32) {
    intent.granted_at = Some(started);
    intent.granted_lifetime = Some(lifetime);
    intent.expires_at = Some(started.saturating_add(u64::from(lifetime)));
    intent.confirmed = true;
    intent.last_error = None;
    intent.renewal_failures = 0;
    if intent.auto_renew {
        schedule(intent, started);
    } else {
        disable(intent);
    }
}

fn schedule(intent: &mut RouterIntent, time: u64) {
    if intent.granted_lifetime.unwrap() <= MIN_RENEWABLE_LEASE {
        intent.renewal_state = "paused".into();
        intent.next_renewal = None;
        intent.last_error = Some(SHORT_LEASE_ERROR.into());
    } else {
        intent.renewal_state = "scheduled".into();
        intent.next_renewal = Some(
            intent
                .granted_at
                .unwrap()
                .saturating_add(u64::from(intent.granted_lifetime.unwrap()) / 2)
                .max(time),
        );
        intent.last_error = None;
    }
}

pub fn visible_state(intent: &RouterIntent, time: u64) -> &str {
    if !intent.auto_renew {
        "off"
    } else if intent.expires_at.is_some_and(|end| end <= time) {
        "expired"
    } else if intent
        .granted_lifetime
        .is_some_and(|lease| lease <= MIN_RENEWABLE_LEASE)
    {
        "paused"
    } else if matches!(
        intent.renewal_state.as_str(),
        "scheduled" | "retry" | "paused" | "expired"
    ) {
        &intent.renewal_state
    } else {
        "paused"
    }
}

pub fn enable(intent: &mut RouterIntent, time: u64) -> Result<(), String> {
    if !intent.confirmed
        || intent.state != "mapped"
        || !matches!(
            mapping::saved_method(intent),
            Some("UPnP" | "PCP" | "NAT-PMP")
        )
        || intent
            .granted_lifetime
            .is_none_or(|lease| lease == 0 || lease > 3600)
        || intent.expires_at.is_none_or(|end| end <= time)
        || intent.granted_at.is_none_or(|start| start > time)
    {
        return Err("Auto-renew requires an acknowledged app-owned finite, unexpired lease; reopen/resolve explicitly, no automatic recreation.".into());
    }
    if mapping::saved_method(intent) == Some("NAT-PMP") && !intent.allow_nat_pmp {
        return Err(crate::udp::NAT_RISK.into());
    }
    intent.auto_renew = true;
    schedule(intent, time);
    Ok(())
}

pub fn tick(
    journal: &mut Journal,
    time: u64,
    firewall: impl Fn(&str) -> bool,
    persist: impl Fn(&Journal) -> Result<(), String>,
    mut renew: impl FnMut(&str, &mut Journal) -> Result<String, String>,
) -> Result<Vec<String>, String> {
    let mut actions = Vec::new();
    let ids: Vec<_> = journal.keys().cloned().collect();
    for id in ids {
        let intent = &journal[&id];
        if !intent.auto_renew
            || intent.renewal_state == "off"
            || matches!(intent.state.as_str(), "closing" | "close-failed")
        {
            continue;
        }
        if intent.renewal_state == "expired" {
            continue;
        }
        if intent.renewal_state == "paused"
            && !intent
                .last_error
                .as_deref()
                .is_some_and(|e| e.starts_with("Own firewall"))
        {
            continue;
        }
        let end = intent.expires_at;
        let reason = if end.is_some_and(|end| end <= time) {
            Some(("expired", "Finite lease deadline passed; not recreated."))
        } else if !intent.confirmed
            || intent.state != "mapped"
            || end.is_none()
            || intent.granted_lifetime.is_none_or(|l| l == 0 || l > 3600)
            || intent.granted_at.is_none_or(|start| start > time)
        {
            Some((
                "paused",
                "Unconfirmed ownership/finite lease or clock discontinuity; not recreated.",
            ))
        } else if intent
            .granted_lifetime
            .is_some_and(|lease| lease <= MIN_RENEWABLE_LEASE)
        {
            Some(("paused", SHORT_LEASE_ERROR))
        } else if !firewall(&id) {
            Some((
                "paused",
                "Own firewall missing, disabled or altered; renewal paused, no rule recreated.",
            ))
        } else {
            None
        };
        if let Some((state, error)) = reason {
            let entry = journal.get_mut(&id).unwrap();
            if entry.renewal_state != state || entry.last_error.as_deref() != Some(error) {
                entry.renewal_state = state.into();
                entry.last_error = Some(error.into());
                entry.next_renewal = None;
                persist(journal)?;
            }
            continue;
        }
        if intent.next_renewal.is_some_and(|next| next > time) {
            continue;
        }
        let old = intent.clone();
               let entry = journal.get_mut(&id).unwrap();
        entry.renewal_state = "retry".into();
        entry.next_renewal = Some(time.saturating_add(30));
        if let Err(e) = persist(journal) {
            journal.insert(id.clone(), old);
            return Err(e);
        }
        match renew(&id, journal) {
            Ok(note) => actions.push(format!("auto_renew {id}: {note}")),
            Err(error) => {
                let entry = journal.get_mut(&id).unwrap();
                                              let retry = entry.confirmed
                    && (error.contains("unconfirmed")
                        || error.contains("timed out")
                        || error.contains("connect")
                        || [
                            "PCP error 7 (",
                            "PCP error 8 (",
                            "PCP error 10 (",
                            "NAT-PMP error 3",
                            "NAT-PMP error 4",
                        ]
                        .iter()
                        .any(|prefix| error.starts_with(prefix)));
                entry.renewal_state = if retry { "retry" } else { "paused" }.into();
                entry.renewal_failures = old.renewal_failures.saturating_add(1);
                entry.last_error = Some(error.clone());
                let delay = 30u64
                    .saturating_mul(1u64 << entry.renewal_failures.min(4))
                    .min(300);
                entry.next_renewal = if retry {
                    Some(
                        time.saturating_add(delay)
                            .min(end.unwrap().saturating_sub(1))
                            .max(time.saturating_add(15)),
                    )
                } else {
                    None
                };
                actions.push(format!("auto_renew {id} failed: {error}"));
            }
        }
        persist(journal)?;
    }
    Ok(actions)
}

pub fn background_tick() -> Result<(), String> {
    let Ok(_guard) = crate::OPERATIONS.try_lock() else {
        return Ok(());
    };
    let mut journal = crate::load()?;
    if !journal.values().any(|i| i.auto_renew) {
        return Ok(());
    }
    let rules = refresh(&journal);
    tick(
        &mut journal,
        now(),
        |id| {
            rules
                .as_ref()
                .is_ok_and(|rules| rules.iter().any(|r| r.id == id && r.firewall))
        },
        save,
        |id, journal| {
            let (port, proto) = ports::parse_id(id)?;
            let result = mapping::renew(id, port, proto, journal);
                       let text = match &result {
                Ok(note) => format!("auto_renew {id}: {note}"),
                Err(error) => format!("auto_renew {id} failed: {error}"),
            };
            let _ = crate::logging::append(&text);
            result
        },
    )?;
    Ok(())
}

#[cfg(test)]
#[path = "lifecycle_tests.rs"]
mod tests;
