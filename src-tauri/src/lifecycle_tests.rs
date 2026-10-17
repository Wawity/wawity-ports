use crate::{lease::*, mapping, Journal, RouterIntent};
use std::cell::{Cell, RefCell};

const ID: &str = "WawityPorts-80-TCP";

#[test]
fn off_records_are_excluded_even_with_stale_auto_renew_flag() {
    let mut j = journal();
    let entry = j.get_mut(ID).unwrap();
    entry.renewal_state = "off".into();
    assert!(entry.auto_renew);
    tick(
        &mut j,
        1900,
        |_| panic!("Off record checked firewall"),
        |_| panic!("Off record persisted"),
        |_, _| panic!("Off record renewed"),
    )
    .unwrap();
}

#[test]
fn short_grants_pause_without_rejecting_mapping_and_remain_paused_after_restart() {
    for lifetime in [1, 2, 15, 16, 30, 59, 60, 61, 120] {
        let mut j = journal();
        grant(j.get_mut(ID).unwrap(), 100, lifetime);
        assert!(j[ID].confirmed);
        assert_eq!(j[ID].expires_at, Some(100 + u64::from(lifetime)));
        if lifetime <= 60 {
            assert_eq!(j[ID].renewal_state, "paused");
            assert_eq!(j[ID].last_error.as_deref(), Some(SHORT_LEASE_ERROR));
            assert!(j[ID].next_renewal.is_none());
            let saved = serde_json::to_vec(&j).unwrap();
            let mut restart: Journal = serde_json::from_slice(&saved).unwrap();
            tick(
                &mut restart,
                100,
                |_| true,
                |_| Ok(()),
                |_, _| panic!("Short lease renewed"),
            )
            .unwrap();
            assert_eq!(visible_state(&restart[ID], 100), "paused");
            assert_eq!(
                visible_state(&restart[ID], 100 + u64::from(lifetime)),
                "expired"
            );
            disable(restart.get_mut(ID).unwrap());
            enable(restart.get_mut(ID).unwrap(), 100).unwrap();
            assert_eq!(restart[ID].renewal_state, "paused");
            assert_eq!(restart[ID].last_error.as_deref(), Some(SHORT_LEASE_ERROR));
                       let entry = restart.get_mut(ID).unwrap();
            entry.renewal_state = "scheduled".into();
            entry.last_error = None;
            entry.next_renewal = Some(100);
            tick(
                &mut restart,
                100,
                |_| true,
                |_| Ok(()),
                |_, _| panic!("Legacy short lease renewed"),
            )
            .unwrap();
            assert_eq!(restart[ID].renewal_state, "paused");
            assert_eq!(restart[ID].last_error.as_deref(), Some(SHORT_LEASE_ERROR));
        } else {
            assert_eq!(j[ID].renewal_state, "scheduled");
            assert_eq!(j[ID].next_renewal, Some(100 + u64::from(lifetime) / 2));
            assert!(j[ID].last_error.is_none());
        }
    }
}

fn journal() -> Journal {
    let mut intent = RouterIntent {
        state: "mapped".into(),
        method: Some("PCP".into()),
        auto_renew: true,
        ..RouterIntent::default()
    };
    grant(&mut intent, 100, 3600);
    Journal::from([(ID.into(), intent)])
}

#[test]
fn halfway_schedule_short_grants_off_and_expiry() {
    let mut journal = journal();
    let calls = Cell::new(0);
    for time in [100, 1899] {
        assert!(tick(
            &mut journal,
            time,
            |_| true,
            |_| Ok(()),
            |_, _| {
                calls.set(calls.get() + 1);
                Ok("renew".into())
            }
        )
        .unwrap()
        .is_empty());
    }
    assert_eq!(calls.get(), 0);
    let actions = tick(
        &mut journal,
        1900,
        |_| true,
        |_| Ok(()),
        |id, j| {
            assert_eq!(id, ID);
            grant(j.get_mut(id).unwrap(), 1900, 120);
            Ok("renewed 120 seconds".into())
        },
    )
    .unwrap();
    assert_eq!(actions.len(), 1);
    assert_eq!(journal[ID].next_renewal, Some(1960));
    assert_eq!(journal[ID].expires_at, Some(2020));
    assert_eq!(visible_state(&journal[ID], 2020), "expired");
    tick(
        &mut journal,
        2020,
        |_| true,
        |_| Ok(()),
        |_, _| panic!("Must not recreate expired lease"),
    )
    .unwrap();
    assert_eq!(journal[ID].renewal_state, "expired");
    disable(journal.get_mut(ID).unwrap());
    assert_eq!(visible_state(&journal[ID], 3000), "off");
    assert!(tick(
        &mut journal,
        3000,
        |_| true,
        |_| Ok(()),
        |_, _| panic!("disabled")
    )
    .unwrap()
    .is_empty());
}

#[test]
fn failed_save_never_mutates_router_or_resurrects_close_failed() {
    let mut journal = journal();
    assert!(tick(
        &mut journal,
        1900,
        |_| true,
        |_| Err("disk full".into()),
        |_, _| panic!("No mutation after failed save")
    )
    .is_err());
    assert_eq!(journal[ID].renewal_state, "scheduled");
    let entry = journal.get_mut(ID).unwrap();
    disable(entry);
    entry.state = "closing".into();
    let saved = serde_json::to_vec(&journal).unwrap();
    journal = serde_json::from_slice(&saved).unwrap(); 
    journal.get_mut(ID).unwrap().state = "close-failed".into();
    tick(
        &mut journal,
        1900,
        |_| true,
        |_| Ok(()),
        |_, _| panic!("Close failure must not resurrect"),
    )
    .unwrap();
    assert!(!journal[ID].auto_renew);
    assert_eq!(journal[ID].renewal_state, "off");
}

#[test]
fn firewall_pause_resumes_only_known_owned_unexpired_grant() {
    let mut journal = journal();
    let saves = Cell::new(0);
    tick(
        &mut journal,
        1900,
        |_| false,
        |_| {
            saves.set(saves.get() + 1);
            Ok(())
        },
        |_, _| panic!("Do not recreate missing firewall"),
    )
    .unwrap();
    assert_eq!(journal[ID].renewal_state, "paused");
    assert_eq!(saves.get(), 1);
    tick(
        &mut journal,
        1915,
        |_| false,
        |_| {
            saves.set(saves.get() + 1);
            Ok(())
        },
        |_, _| panic!("still missing"),
    )
    .unwrap();
    assert_eq!(saves.get(), 1); 
    tick(
        &mut journal,
        1930,
        |_| true,
        |_| Ok(()),
        |id, j| {
            grant(j.get_mut(id).unwrap(), 1930, 3600);
            Ok("resumed".into())
        },
    )
    .unwrap();
    assert_eq!(journal[ID].renewal_state, "scheduled");
    journal.get_mut(ID).unwrap().confirmed = false;
    tick(
        &mut journal,
        3730,
        |_| true,
        |_| Ok(()),
        |_, _| panic!("unconfirmed"),
    )
    .unwrap();
    assert_eq!(journal[ID].renewal_state, "paused");
}

#[test]
fn bounded_backoff_preserves_original_expiry_terminal_alien_and_restart() {
    let mut journal = journal();
    let calls = Cell::new(0);
    for (time, next) in [(1900, 1960), (1960, 2080), (2080, 2320), (2320, 2620)] {
        let actions = tick(
            &mut journal,
            time,
            |_| true,
            |_| Ok(()),
            |_, _| {
                calls.set(calls.get() + 1);
                Err("UDP outcome unconfirmed".into())
            },
        )
        .unwrap();
        assert_eq!(actions.len(), 1);
        assert_eq!(journal[ID].renewal_state, "retry");
        assert_eq!(journal[ID].next_renewal, Some(next));
        assert_eq!(journal[ID].expires_at, Some(3700));
        assert!(journal[ID].confirmed);
        let saved = serde_json::to_vec(&journal).unwrap();
        journal = serde_json::from_slice(&saved).unwrap();
    }
    assert_eq!(calls.get(), 4);
    tick(
        &mut journal,
        2500,
        |_| true,
        |_| Ok(()),
        |_, _| panic!("Backoff must survive restart"),
    )
    .unwrap();
    tick(
        &mut journal,
        2620,
        |_| true,
        |_| Ok(()),
        |_, _| Err("UPnP mapping foreign or absent; not recreated".into()),
    )
    .unwrap();
    assert_eq!(journal[ID].renewal_state, "paused");
    tick(
        &mut journal,
        3000,
        |_| true,
        |_| Ok(()),
        |_, _| panic!("alien"),
    )
    .unwrap();
}

#[test]
fn sleep_past_expiry_and_clock_rollback_never_recreate() {
    for time in [99, 4000, 100000] {
        let mut journal = journal();
        tick(
            &mut journal,
            time,
            |_| true,
            |_| Ok(()),
            |_, _| panic!("Unsafe resume/clock"),
        )
        .unwrap();
        assert_eq!(
            journal[ID].renewal_state,
            if time < 100 { "paused" } else { "expired" }
        );
    }
}

#[test]
fn enable_requires_acknowledged_finite_ownership_legacy_not_enrolled() {
    let mut entry = journal().remove(ID).unwrap();
    disable(&mut entry);
    enable(&mut entry, 2000).unwrap();
    assert_eq!(entry.next_renewal, Some(2000));
    for invalid in [
        "unconfirmed",
        "expired",
        "infinite",
        "foreign",
        "closing",
        "clock",
        "unknown",
    ] {
        let mut entry = journal().remove(ID).unwrap();
        match invalid {
            "unconfirmed" => entry.confirmed = false,
            "expired" => entry.expires_at = Some(2000),
            "infinite" => entry.granted_lifetime = Some(0),
            "foreign" => entry.state = "conflict".into(),
            "closing" => entry.state = "close-failed".into(),
            "clock" => entry.granted_at = Some(2001),
            _ => entry.method = Some("OTHER".into()),
        };
        assert!(enable(&mut entry, 2000).is_err(), "{invalid}");
    }
    let mut legacy:RouterIntent=serde_json::from_str(r#"{"gateway":"192.168.1.1:5000","local_ip":"192.168.1.10","expires_at":5000,"external_ip":null,"state":"mapped"}"#).unwrap();
    assert!(enable(&mut legacy, 2000).is_err());
    legacy.method = Some("NAT-PMP".into());
    legacy.confirmed = true;
    legacy.granted_at = Some(100);
    legacy.granted_lifetime = Some(3600);
    assert!(enable(&mut legacy, 2000).is_err());
}

#[test]
fn save_sequence_surrounds_action_and_cancellation_is_persisted() {
    let mut journal = journal();
    let events = RefCell::new(Vec::new());
    tick(
        &mut journal,
        1900,
        |_| true,
        |j| {
            events
                .borrow_mut()
                .push(format!("save {}", j[ID].renewal_state));
            Ok(())
        },
        |id, j| {
            events.borrow_mut().push("mutate".into());
            grant(j.get_mut(id).unwrap(), 1900, 3600);
            Ok("renew".into())
        },
    )
    .unwrap();
    assert_eq!(*events.borrow(), ["save retry", "mutate", "save scheduled"]);
    assert_eq!(mapping::saved_method(&journal[ID]), Some("PCP"));
}
