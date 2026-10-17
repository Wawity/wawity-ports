use super::*;

fn pcp_response(request: &[u8], lease: u32) -> Vec<u8> {
    let mut b = request.to_vec();
    b[1] |= 128;
    b[4..8].copy_from_slice(&lease.to_be_bytes());
    b[8..12].copy_from_slice(&100u32.to_be_bytes());
    b[12..24].fill(0);
    if request[1] == 1 {
        b[44..60].fill(0);
        b[54..56].copy_from_slice(&[255, 255]);
        b[56..60].copy_from_slice(&[8, 8, 8, 8]);
    }
    b
}

#[test]
fn pcp_wire_exact_nonce_ipv4_protocol_ports_and_mandatory_option() {
    let nonce = [0xab; 12];
    for (proto, code) in [("TCP", 6), ("UDP", 17)] {
        let request = pcp_request(
            "192.168.1.10".parse().unwrap(),
            Some(nonce),
            protocol(proto).unwrap(),
            25565,
            25565,
            None,
            LIFETIME,
        );
        assert_eq!(request.len(), 64);
        assert_eq!(&request[..4], &[2, 1, 0, 0]);
        assert_eq!(&request[4..8], &3600u32.to_be_bytes());
        assert_eq!(
            &request[8..24],
            &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 192, 168, 1, 10]
        );
        assert_eq!(&request[24..36], &nonce);
        assert_eq!(request[36], code);
        assert_eq!(&request[40..44], &[0x63, 0xdd, 0x63, 0xdd]);
        assert_eq!(
            &request[44..60],
            &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 0]
        );
        assert_eq!(&request[60..64], &[2, 0, 0, 0]);
        let response = pcp_response(&request, 3600);
        let reply = pcp_decode(&response, &request).unwrap();
        assert_eq!(reply.external_port, 25565);
        assert_eq!(reply.external_ip, Some("8.8.8.8".parse().unwrap()));
        assert!(validate_grant(&reply, 25565, None, false).is_ok());
        for i in [0, 1, 24, 35, 36, 40, 41, 44, 45, 54, 55] {
            let mut bad = response.clone();
            bad[i] ^= 1;
            assert!(pcp_decode(&bad, &request).is_err(), "byte {i}");
        }
        for len in 0..response.len() {
            assert!(
                pcp_decode(&response[..len], &request).is_err(),
                "length {len}"
            );
        }
        let mut bad = response.clone();
        bad.extend_from_slice(&[2, 0, 0, 0]);
        assert!(pcp_decode(&bad, &request).is_err());
        let mut bad = response.clone();
        bad[62..64].copy_from_slice(&5u16.to_be_bytes());
        assert!(pcp_decode(&bad, &request).is_err());
        let mut unknown = response.clone();
        unknown.extend_from_slice(&[127, 0, 0, 1, 42, 0, 0, 0]);
        assert!(pcp_decode(&unknown, &request).is_ok());
        let mut reserved = response.clone();
        reserved[2] = 255;
        reserved[12] = 255;
        reserved[37] = 255;
        reserved[61] = 255;
        assert!(pcp_decode(&reserved, &request).is_ok()); 
    }
    assert!(protocol("BOTH").is_err());
}

#[test]
fn initial_pcp_map_matches_independent_full_wire_fixture() {
    let request = pcp_request(
        "192.168.1.10".parse().unwrap(),
        Some([0xab; 12]),
        6,
        25565,
        25565,
        None,
        3600,
    );
    let expected = [
        2, 1, 0, 0, 0, 0, 14, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 192, 168, 1, 10, 171,
        171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 6, 0, 0, 0, 99, 221, 99, 221, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 2, 0, 0, 0,
    ];
    assert_eq!(request.as_slice(), expected);
}

#[test]
fn pcp_errors_lifetimes_addresses_and_remaps_are_not_success() {
    let request = pcp_request(
        "192.168.1.10".parse().unwrap(),
        Some([7; 12]),
        6,
        80,
        80,
        None,
        3600,
    );
    for code in 1..=255 {
        let mut b = pcp_response(&request, 3600);
        b[3] = code;
        b[42..60].copy_from_slice(&request[42..60]);
        assert!(pcp_decode(&b, &request)
            .unwrap_err()
            .starts_with("PCP error"));
        b[24] ^= 1;
        assert!(!pcp_decode(&b, &request)
            .unwrap_err()
            .starts_with("PCP error"));
    }
    for lease in [0, 1, 3599, 3600, 3601, u32::MAX] {
        let reply = pcp_decode(&pcp_response(&request, lease), &request).unwrap();
        assert_eq!(
            validate_grant(&reply, 80, None, false).is_ok(),
            (1..=3600).contains(&lease)
        );
    }
    let mut b = pcp_response(&request, 3600);
    b[42..44].copy_from_slice(&81u16.to_be_bytes());
    let reply = pcp_decode(&b, &request).unwrap();
    assert_eq!(reply.external_port, 81); 
    assert!(validate_grant(&reply, 80, None, false).is_err());
    assert!(validate_grant(&reply, 81, Some("1.1.1.1".parse().unwrap()), false).is_err());
    for ip in [
        [0, 0, 0, 0],
        [127, 0, 0, 1],
        [224, 0, 0, 1],
        [255, 255, 255, 255],
    ] {
        b[56..60].copy_from_slice(&ip);
        assert!(pcp_decode(&b, &request).is_err());
    }
    b = pcp_response(&request, 3600);
    b.resize(1104, 0);
    assert!(pcp_decode(&b, &request).is_err());
}

#[test]
fn announce_is_read_only_not_map_support_and_deletion_has_no_prefer_failure() {
    let local = "192.168.1.10".parse().unwrap();
    let announce = pcp_request(local, None, 0, 0, 0, None, 0);
    assert_eq!(announce.len(), 24);
    assert_eq!(announce[1], 0);
    assert_eq!(
        pcp_decode(&pcp_response(&announce, 0), &announce)
            .unwrap()
            .external_ip,
        None
    );
    assert!(pcp_decode(&pcp_response(&announce, 1), &announce).is_err());
    let delete = pcp_request(
        local,
        Some([3; 12]),
        6,
        80,
        81,
        Some("8.8.8.8".parse().unwrap()),
        0,
    );
    assert_eq!(delete.len(), 60);
    assert_eq!(&delete[42..44], &81u16.to_be_bytes());
    let reply = pcp_decode(&pcp_response(&delete, 0), &delete).unwrap();
    assert!(validate_grant(&reply, 81, reply.external_ip, true).is_ok());
    assert!(validate_grant(&reply, 81, reply.external_ip, false).is_err());
}

fn nat_response(request: &[u8], lease: u32, external: u16) -> Vec<u8> {
    let mut b = vec![0; 16];
    b[1] = 128 | request[1];
    b[4..8].copy_from_slice(&100u32.to_be_bytes());
    b[8..10].copy_from_slice(&request[4..6]);
    b[10..12].copy_from_slice(&external.to_be_bytes());
    b[12..16].copy_from_slice(&lease.to_be_bytes());
    b
}

#[test]
fn nat_wire_identity_errors_address_and_rfc_delete() {
    for proto in [6, 17] {
        let request = nat_request(proto, 25565, 25565, 3600);
        assert_eq!(&request[0..4], &[0, if proto == 6 { 2 } else { 1 }, 0, 0]);
        assert_eq!(&request[4..8], &[0x63, 0xdd, 0x63, 0xdd]);
        assert_eq!(&request[8..12], &3600u32.to_be_bytes());
        let response = nat_response(&request, 3600, 25565);
        assert!(nat_decode(&response, &request).is_ok());
        for len in 0..16 {
            assert!(nat_decode(&response[..len], &request).is_err());
        }
        for i in [0, 1, 8, 9] {
            let mut b = response.clone();
            b[i] ^= 1;
            assert!(nat_decode(&b, &request).is_err());
        }
        for code in [1u16, 2, 3, 4, 5, 65535] {
            let mut b = response.clone();
            b[2..4].copy_from_slice(&code.to_be_bytes());
            assert!(nat_decode(&b, &request)
                .unwrap_err()
                .starts_with("NAT-PMP error"));
            b[8] ^= 1;
            assert!(!nat_decode(&b, &request)
                .unwrap_err()
                .starts_with("NAT-PMP error"));
        }
        for lease in [0, 1, 3600, 3601, u32::MAX] {
            let reply = nat_decode(&nat_response(&request, lease, 80), &request).unwrap();
            assert_eq!(
                validate_grant(&reply, 80, None, false).is_ok(),
                (1..=3600).contains(&lease)
            );
        }
        let delete = nat_request(proto, 25565, 25565, 0);
        assert_eq!(&delete[6..12], &[0; 6]);
        let reply = nat_decode(&nat_response(&delete, 0, 0), &delete).unwrap();
        assert!(validate_grant(&reply, 25565, None, true).is_ok());
    }
    let address = [0, 128, 0, 0, 0, 0, 0, 100, 8, 8, 8, 8];
    assert_eq!(
        nat_decode(&address, &[0, 0]).unwrap().external_ip,
        Some("8.8.8.8".parse().unwrap())
    );
    assert!(nat_decode(&address[..8], &[0, 0]).is_err());
}

#[test]
fn epochs_allow_quantization_and_drift_but_not_reboot_wrap_or_sleep_loss() {
    assert!(epoch_valid(100, 100, 0));
    assert!(epoch_valid(100, 102, 0));
    assert!(epoch_valid(100, 200, 100));
    assert!(epoch_valid(100, 196, 100));
    assert!(epoch_valid(100, 205, 100));
    assert!(!epoch_valid(100, 99, 0));
    assert!(!epoch_valid(100, 0, 1800));
    assert!(!epoch_valid(100, 102, 1800));
    assert!(!epoch_valid(u32::MAX, 0, 1));
    assert!(!epoch_valid(0, u32::MAX, 0));
    assert!(!epoch_valid(0, 1, u64::MAX));
}

#[test]
fn malformed_request_contexts_fail_without_indexing_panics() {
    for request in [
        vec![],
        vec![0],
        vec![0, 1],
        vec![2, 1],
        vec![3; 64],
        vec![0, 255],
    ] {
        assert!(pcp_decode(&[0; 64], &request).is_err());
        assert!(nat_decode(&[0; 16], &request).is_err());
    }
}
