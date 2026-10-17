use super::*;
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;

const ID: &str = "WawityPorts-80-TCP";
struct Fake {
    replies: VecDeque<Result<udp::Reply, String>>,
    requests: Vec<Vec<u8>>,
}
impl Transport for Fake {
    fn exchange(&mut self, request: &[u8], _: bool) -> Result<udp::Reply, String> {
        self.requests.push(request.to_vec());
        self.replies
            .pop_front()
            .expect("Unexpected transport request")
    }
}
fn lan() -> router::Lan {
    serde_json::from_str(
        r#"{"local":"192.168.1.10","gateway":"192.168.1.1","index":7,"prefix":24}"#,
    )
    .unwrap()
}
fn reply(port: u16, lease: u32) -> udp::Reply {
    udp::Reply {
        lifetime: lease,
        epoch: 100,
        external_port: port,
        external_ip: Some("8.8.8.8".parse().unwrap()),
    }
}
fn fake(replies: Vec<Result<udp::Reply, String>>) -> Fake {
    Fake {
        replies: replies.into(),
        requests: vec![],
    }
}
fn journal() -> Journal {
    Journal::from([(
        ID.into(),
        RouterIntent {
            auto_renew: true,
            allow_nat_pmp: true,
            ..RouterIntent::default()
        },
    )])
}

#[test]
fn nonce_and_exact_tuple_are_durable_before_map_and_survive_restart() {
    let mut j = journal();
    let mut t = fake(vec![Ok(reply(80, 120))]);
    let durable = RefCell::new(Vec::new());
    udp_open(ID, 80, "TCP", &mut j, &lan(), "PCP", &mut t, |j| {
        durable.borrow_mut().push(serde_json::to_vec(j).unwrap());
        Ok(())
    })
    .unwrap();
    let before: Journal = serde_json::from_slice(&durable.borrow()[0]).unwrap();
    assert!(before[ID].mutation_attempted);
    assert!(!before[ID].confirmed);
    assert_eq!(before[ID].gateway.as_deref(), Some("192.168.1.1:5351"));
    assert_eq!(before[ID].nonce, j[ID].nonce);
    assert_ne!(j[ID].nonce, Some([0; 12]));
    assert_eq!(&t.requests[0][24..36], &before[ID].nonce.unwrap());
    assert_eq!(j[ID].granted_lifetime, Some(120));
    assert!(j[ID].confirmed);
    assert_eq!(j[ID].renewal_state, "scheduled");
    let restart: Journal = serde_json::from_slice(durable.borrow().last().unwrap()).unwrap();
    assert_eq!(restart[ID].nonce, j[ID].nonce);
    assert_eq!(restart[ID].external_port, Some(80));
    assert_eq!(restart[ID].expires_at, j[ID].expires_at);
}

#[test]
fn save_failure_never_sends_map_and_timeout_never_allows_fallback() {
    let mut j = journal();
    let mut t = fake(vec![]);
    assert!(
        udp_open(ID, 80, "TCP", &mut j, &lan(), "PCP", &mut t, |_| Err(
            "disk full".into()
        ))
        .is_err()
    );
    assert!(t.requests.is_empty());
    let mut j = journal();
    let mut t = fake(vec![Err(
        "timeout after mutation; outcome unconfirmed".into()
    )]);
    assert!(udp_open(ID, 80, "TCP", &mut j, &lan(), "PCP", &mut t, |_| Ok(())).is_err());
    assert!(j[ID].mutation_attempted);
    assert!(!j[ID].confirmed);
    assert!(j[ID].nonce.is_some());
    assert_eq!(t.requests.len(), 1);
    let error = open(ID, 80, "TCP", &mut j, true).unwrap_err();
    assert!(error.contains("ambiguous")); 
}

#[test]
fn protocol_rejections_vs_malformed_timeout_and_remapped_cleanup() {
    for (error, safe) in [
        ("PCP error 5 (UNSUPP_OPTION)", true),
        ("PCP error 4 (UNSUPP_OPCODE)", true),
        ("PCP error 2 (NOT_AUTHORIZED)", false),
        ("PCP nonce/protocol/internal port identity mismatch", false),
        ("timeout outcome unconfirmed", false),
    ] {
        let mut j = journal();
        let mut t = fake(vec![Err(error.into())]);
        assert!(udp_open(ID, 80, "TCP", &mut j, &lan(), "PCP", &mut t, |_| Ok(())).is_err());
        assert_eq!(!j[ID].mutation_attempted, safe, "{error}");
    }
    let mut j = journal();
    let mut t = fake(vec![Ok(reply(81, 3600))]);
    assert!(
        udp_open(ID, 80, "TCP", &mut j, &lan(), "PCP", &mut t, |_| Ok(()))
            .unwrap_err()
            .contains("remapped")
    );
    assert_eq!(j[ID].external_port, Some(81));
    assert!(!j[ID].confirmed);
    let mut delete = reply(81, 0);
    delete.epoch = 101;
    let mut t = fake(vec![Ok(delete)]);
    udp_close(80, "TCP", &j[ID], &lan(), &mut t).unwrap();
    assert_eq!(&t.requests[0][42..44], &81u16.to_be_bytes());
    assert_eq!(&t.requests[0][24..36], &j[ID].nonce.unwrap());
    assert_eq!(t.requests[0].len(), 60);
    assert_eq!(&t.requests[0][4..8], &[0; 4]);
}

#[test]
fn udp_renew_uses_original_nonce_address_and_exact_port_save_before_mutation() {
    let mut j = journal();
    let mut t = fake(vec![Ok(reply(80, 3600))]);
    udp_open(ID, 80, "TCP", &mut j, &lan(), "PCP", &mut t, |_| Ok(())).unwrap();
    let old = j[ID].clone();
    let saves = Cell::new(0);
    let mut t = fake(vec![Ok(reply(80, 120))]);
    udp_map(
        ID,
        80,
        "TCP",
        &mut j,
        &lan(),
        &mut t,
        &|_| {
            saves.set(saves.get() + 1);
            Ok(())
        },
        true,
    )
    .unwrap();
    assert!(saves.get() >= 3);
    assert_eq!(j[ID].nonce, old.nonce);
    assert_eq!(&t.requests[0][56..60], &[8, 8, 8, 8]);
    assert_eq!(&t.requests[0][60..64], &[2, 0, 0, 0]);
    let mut t = fake(vec![]);
    assert!(udp_map(
        ID,
        80,
        "TCP",
        &mut j,
        &lan(),
        &mut t,
        &|_| Err("cannot save".into()),
        true
    )
    .is_err());
    assert!(t.requests.is_empty());
    let mut t = fake(vec![Err("timeout outcome unconfirmed".into())]);
    assert!(udp_map(ID, 80, "TCP", &mut j, &lan(), &mut t, &|_| Ok(()), true).is_err());
    assert!(j[ID].confirmed);
    assert_eq!(j[ID].granted_lifetime, Some(120));
}

#[test]
fn nat_consent_external_address_and_non_destructive_expiry_epoch_checks() {
    let mut j = journal();
    j.get_mut(ID).unwrap().allow_nat_pmp = false;
    let mut t = fake(vec![]);
    assert!(
        udp_open(ID, 80, "TCP", &mut j, &lan(), "NAT-PMP", &mut t, |_| Ok(()))
            .unwrap_err()
            .contains("pre-existing")
    );
    assert!(t.requests.is_empty());
    let mut j = journal();
    let address = udp::Reply {
        lifetime: 0,
        epoch: 100,
        external_port: 0,
        external_ip: Some("8.8.8.8".parse().unwrap()),
    };
    let mut mapped = reply(81, 3600);
    mapped.external_ip = None;
    let mut t = fake(vec![Ok(address.clone()), Ok(mapped)]);
    assert!(udp_open(ID, 80, "TCP", &mut j, &lan(), "NAT-PMP", &mut t, |_| Ok(())).is_err());
    assert_eq!(j[ID].external_ip.as_deref(), Some("8.8.8.8"));
    assert_eq!(j[ID].external_port, Some(81));
    let mut t = fake(vec![
        Ok(address.clone()),
        Ok(udp::Reply {
            lifetime: 0,
            epoch: 100,
            external_port: 0,
            external_ip: None,
        }),
    ]);
    udp_close(80, "TCP", &j[ID], &lan(), &mut t).unwrap();
    assert_eq!(t.requests.len(), 2);
    assert_eq!(&t.requests[1][4..6], &80u16.to_be_bytes());
    assert_eq!(&t.requests[1][6..12], &[0; 6]);
    let mut expired = j[ID].clone();
    expired.expires_at = Some(now() - 1);
    let mut t = fake(vec![]);
    assert!(udp_close(80, "TCP", &expired, &lan(), &mut t).is_err());
    assert!(t.requests.is_empty());
    let mut reset = address.clone();
    reset.epoch = 0;
    let mut t = fake(vec![Ok(reset)]);
    assert!(udp_close(80, "TCP", &j[ID], &lan(), &mut t).is_err());
    assert_eq!(t.requests.len(), 1);
    let mut changed = address;
    changed.external_ip = Some("1.1.1.1".parse().unwrap());
    let mut t = fake(vec![Ok(changed)]);
    assert!(udp_close(80, "TCP", &j[ID], &lan(), &mut t).is_err());
    assert_eq!(t.requests.len(), 1);
}

#[test]
fn tuple_change_or_foreign_intent_never_deletes_and_inspection_never_maps() {
    let mut j = journal();
    let mut t = fake(vec![Ok(reply(80, 3600))]);
    udp_open(ID, 80, "TCP", &mut j, &lan(), "PCP", &mut t, |_| Ok(())).unwrap();
    for field in ["ip", "gateway", "interface", "port", "proto", "nonce"] {
        let mut intent = j[ID].clone();
        match field {
            "ip" => intent.local_ip = Some("192.168.1.11".into()),
            "gateway" => intent.gateway = Some("192.168.1.2:5351".into()),
            "interface" => intent.interface_index = Some(8),
            "port" => intent.internal_port = Some(81),
            "proto" => intent.protocol = Some("UDP".into()),
            _ => intent.nonce = None,
        };
        let mut t = fake(vec![]);
        assert!(udp_close(80, "TCP", &intent, &lan(), &mut t).is_err());
        assert!(t.requests.is_empty());
    }
    assert!(inspect(ID, 80, "TCP", &j[ID])
        .unwrap()
        .contains("journal only, unverified"));
    let context = CheckRouter {
        lan: lan(),
        upnp: None,
        method: "PCP".into(),
    };
    assert!(external_ip(&context)
        .unwrap_err()
        .contains("external probe skipped"));
    assert!(udp::PhysicalTransport::new(&lan())
        .err()
        .unwrap()
        .contains("disabled in test mode"));
}

#[test]
fn result_save_failure_retains_durable_nonce_and_ambiguous_cleanup_record() {
    let mut j = journal();
    let mut t = fake(vec![Ok(reply(81, 120))]);
    let writes = Cell::new(0);
    let durable = RefCell::new(Vec::new());
    let error = udp_open(ID, 80, "TCP", &mut j, &lan(), "PCP", &mut t, |j| {
        writes.set(writes.get() + 1);
        if writes.get() == 2 {
            return Err("result disk failure".into());
        }
        *durable.borrow_mut() = serde_json::to_vec(j).unwrap();
        Ok(())
    })
    .unwrap_err();
    assert!(error.contains("disk"));
    assert_eq!(t.requests.len(), 1);
    let restart: Journal = serde_json::from_slice(&durable.borrow()).unwrap();
    assert_eq!(restart[ID].nonce, j[ID].nonce);
    assert_eq!(restart[ID].external_port, Some(80));
    assert!(!restart[ID].confirmed);
    assert!(restart[ID].mutation_attempted);
    assert_eq!(j[ID].external_port, Some(81));
    assert!(!j[ID].confirmed);
}

#[test]
fn first_save_failure_restores_previous_or_absent_record_after_outer_save_and_restart() {
    for method in ["PCP", "NAT-PMP"] {
        for existing in [false, true] {
            let mut j = if existing || method == "NAT-PMP" {
                journal()
            } else {
                Journal::new()
            };
            if let Some(entry) = j.get_mut(ID) {
                entry.state = "pending".into();
                entry
                    .extra
                    .insert("preserved".into(), serde_json::json!({"user": true}));
            }
            let original = serde_json::to_value(&j).unwrap();
            let address = udp::Reply {
                lifetime: 0,
                epoch: 100,
                external_port: 0,
                external_ip: Some("8.8.8.8".parse().unwrap()),
            };
            let mut t = fake(if method == "NAT-PMP" {
                vec![Ok(address)]
            } else {
                vec![]
            });
            assert!(
                udp_open(ID, 80, "TCP", &mut j, &lan(), method, &mut t, |_| Err(
                    "first save failed".into()
                ))
                .is_err()
            );
            assert!(t.requests.iter().all(|r| r.as_slice() == [0, 0]));
            assert_eq!(serde_json::to_value(&j).unwrap(), original);
                       let outer_save = serde_json::to_vec(&j).unwrap();
            let mut restart: Journal = serde_json::from_slice(&outer_save).unwrap();
            assert!(restart
                .get(ID)
                .is_none_or(|i| i.gateway.is_none() && !i.mutation_attempted && i.nonce.is_none()));
            let mut granted = reply(80, 3600);
            let mut replies = Vec::new();
            if method == "NAT-PMP" {
                replies.push(Ok(udp::Reply {
                    lifetime: 0,
                    epoch: 100,
                    external_port: 0,
                    external_ip: granted.external_ip,
                }));
                granted.external_ip = None;
            }
            replies.push(Ok(granted));
            let mut t = fake(replies);
            udp_open(ID, 80, "TCP", &mut restart, &lan(), method, &mut t, |_| {
                Ok(())
            })
            .unwrap();
            assert!(restart[ID].confirmed);
            assert_eq!(restart[ID].state, "mapped");
        }
    }
}

#[test]
fn short_udp_grants_map_successfully_but_auto_renew_pauses() {
    for method in ["PCP", "NAT-PMP"] {
        for lifetime in [1, 15, 60, 61] {
            let mut j = journal();
            let mut granted = reply(80, lifetime);
            let mut replies = Vec::new();
            if method == "NAT-PMP" {
                replies.push(Ok(udp::Reply {
                    lifetime: 0,
                    epoch: 100,
                    external_port: 0,
                    external_ip: granted.external_ip,
                }));
                granted.external_ip = None;
            }
            replies.push(Ok(granted));
            let mut t = fake(replies);
            let note = udp_open(ID, 80, "TCP", &mut j, &lan(), method, &mut t, |_| Ok(())).unwrap();
            assert!(note.starts_with(&format!("{method} mapped")));
            assert!(j[ID].confirmed);
            assert_eq!(j[ID].state, "mapped");
            assert_eq!(
                j[ID].renewal_state,
                if lifetime <= 60 {
                    "paused"
                } else {
                    "scheduled"
                }
            );
            assert_eq!(
                j[ID].last_error.as_deref(),
                if lifetime <= 60 {
                    Some(lease::SHORT_LEASE_ERROR)
                } else {
                    None
                }
            );
        }
    }
}

#[test]
fn renewal_epoch_or_grant_change_is_terminal_and_not_newly_confirmed() {
    for bad in [
        reply(81, 3600),
        reply(80, 0),
        reply(80, 3601),
        udp::Reply {
            epoch: 0,
            ..reply(80, 3600)
        },
    ] {
        let mut j = journal();
        let mut t = fake(vec![Ok(reply(80, 3600))]);
        udp_open(ID, 80, "TCP", &mut j, &lan(), "PCP", &mut t, |_| Ok(())).unwrap();
        let mut t = fake(vec![Ok(bad)]);
        assert!(udp_map(ID, 80, "TCP", &mut j, &lan(), &mut t, &|_| Ok(()), true).is_err());
        assert!(!j[ID].confirmed);
        assert_eq!(j[ID].state, "unverified");
    }
}
