import json
import random
from pathlib import Path

from tests.helpers import run, table, variant

RECORDS = (Path(__file__).parent / "fixtures" / "records.jsonl").read_text().splitlines()
NGINX = next(r for r in RECORDS if '"d767b4f6' in r)
WITH_CVES = next(r for r in RECORDS if '"cfb933d2' in r)
UNTAGGED = next(r for r in RECORDS if '"633ccbc2' in r)
SIGNAL_RECORDS = (
    (Path(__file__).parent / "fixtures" / "signal_records.jsonl").read_text().splitlines()
)
NTLM = next(r for r in SIGNAL_RECORDS if '"889b057f' in r)
RDP = next(r for r in SIGNAL_RECORDS if '"51215953' in r)
SMB_IPC_ONLY = next(r for r in SIGNAL_RECORDS if '"349f62ae' in r)
FTP_ANONYMOUS = next(r for r in SIGNAL_RECORDS if '"d27145be' in r)
MYSQL_REFUSING = next(r for r in SIGNAL_RECORDS if '"2aec7dfa' in r)
VNC = next(r for r in SIGNAL_RECORDS if '"2b111c5a' in r)
# From the full 2026-10-26 file (the sample has no Lantronix record); its MAC is on one IP there.
LANTRONIX = {
    "type": "X90",
    "version": "6.10.0.1",
    "mac": "00:0A:00:17:6D:01",
    "ip": "75.99.22.110",
    "gateway": "75.99.22.105",
    "password": "5640",
}


def test_dedupe_folds_repeat_sightings_and_loses_no_record(tmp_path: Path) -> None:
    later = variant(NGINX, 1, timestamp="2026-10-26T13:00:00.000000")
    run(tmp_path, [*RECORDS, later])
    services = table(tmp_path, "service", "sightings")
    assert len(services) == len(RECORDS)
    assert sum(n for (n,) in services) == len(RECORDS) + 1


def test_finding_seen_in_one_sighting_survives_dedupe(tmp_path: Path) -> None:
    earlier_id = json.loads(WITH_CVES)["_shodan"]["id"]
    later = variant(WITH_CVES, 1, timestamp="2026-10-26T13:00:00.000000", vulns={}, hostnames=[])
    run(tmp_path, [*RECORDS, later])
    (key,) = table(tmp_path, "service", "service_key", "sightings = 2")[0]
    vuln_ids = table(tmp_path, "service_vuln", "DISTINCT rec_id", f"service_key = '{key}'")
    clue_ids = table(tmp_path, "identity_evidence", "DISTINCT rec_id", f"service_key = '{key}'")
    assert vuln_ids == clue_ids == [(earlier_id,)]
    assert len(table(tmp_path, "service_vuln", where=f"service_key = '{key}'")) == 8


def test_honeypot_address_labels_every_service_on_it(tmp_path: Path) -> None:
    decoy = variant(UNTAGGED, 1, port=8073, tags=["honeypot"])
    run(tmp_path, [*RECORDS, decoy])
    ip = json.loads(UNTAGGED)["ip_str"]
    assert table(tmp_path, "service", "port, noise_reason", f"ip = '{ip}'") == [
        (8072, "honeypot"),
        (8073, "honeypot"),
    ]


def test_keys_and_shown_row_are_stable_across_reruns_and_input_order(tmp_path: Path) -> None:
    # Same service, same timestamp, both with a product: only rec_id can break the tie.
    tied = [variant(NGINX, n, timestamp="2026-10-26T13:00:00.000000") for n in (1, 2)]
    lines = [*RECORDS, *tied]
    shuffled = lines[:]
    random.Random(7).shuffle(shuffled)
    columns = "service_key, shown_rec_id"

    run(tmp_path / "a", lines)
    first = table(tmp_path / "a", "service", columns)
    run(tmp_path / "a", lines)
    run(tmp_path / "b", shuffled)

    assert table(tmp_path / "a", "service", columns) == first
    assert table(tmp_path / "b", "service", columns) == first
    assert ("00000000-0000-0000-0000-000000000002",) in table(
        tmp_path / "a", "service", "shown_rec_id"
    )


def test_platform_name_is_infrastructure_unless_a_customer_domain_is_inside(
    tmp_path: Path,
) -> None:
    # Both names are from the 2M-line slice of the 2026-10-26 file.
    names = ["d3o7okqs1lmm3v.cloudfront.net", "www.btig.com.cdn.cloudflare.net"]
    run(tmp_path, [variant(UNTAGGED, 1, hostnames=names), *RECORDS])
    assert table(
        tmp_path,
        "identity_evidence",
        "raw_value, normalized_value, is_infrastructure, infra_reason",
        f"raw_value IN {tuple(names)}",
    ) == [
        ("d3o7okqs1lmm3v.cloudfront.net", "cloudfront.net", True, "platform_domain"),
        ("www.btig.com.cdn.cloudflare.net", "btig.com", False, None),
    ]


def test_network_with_several_peeringdb_types_takes_the_landlord_class(tmp_path: Path) -> None:
    asn = json.loads(UNTAGGED)["asn"]
    run(tmp_path, RECORDS, networks=[(asn, ["Enterprise", "Content"])])
    ip = json.loads(UNTAGGED)["ip_str"]
    assert table(tmp_path, "address", "owner_class, owner_class_source", f"ip = '{ip}'") == [
        ("hosting", "peeringdb")
    ]


def test_mostly_cloud_network_is_cloud_but_one_cloud_address_does_not_flip_a_business(
    tmp_path: Path,
) -> None:
    cloud_net = json.loads(UNTAGGED)["asn"]
    business_net = "AS64500"
    lines = [
        *RECORDS,
        variant(UNTAGGED, 1, ip_str="198.51.100.1", tags=["cloud"]),
        variant(UNTAGGED, 2, ip_str="198.51.100.2", tags=["cloud"]),
        *(variant(UNTAGGED, n, ip_str=f"203.0.113.{n}", asn=business_net) for n in (3, 4, 5)),
        variant(UNTAGGED, 6, ip_str="203.0.113.6", asn=business_net, tags=["cloud"]),
    ]
    networks = [(cloud_net, ["Enterprise"]), (business_net, ["Enterprise"])]
    run(tmp_path, lines, networks, asn_cloud_min_addresses=3, asn_cloud_min_share=0.5)

    untagged_ip = json.loads(UNTAGGED)["ip_str"]
    columns = "owner_class, owner_class_source"
    assert table(tmp_path, "address", columns, f"ip = '{untagged_ip}'") == [
        ("cloud", "asn_cloud_share")
    ]
    assert (
        table(tmp_path, "address", columns, "ip IN ('203.0.113.3', '203.0.113.4', '203.0.113.5')")
        == [("enterprise", "peeringdb")] * 3
    )


def test_ntlm_forest_name_is_a_clue_and_a_local_name_is_not(tmp_path: Path) -> None:
    local_names = {"dns_forest_name": "corp.local", "dns_domain_name": "corp.local"}
    ntlm = {**json.loads(NTLM)["ntlm"], **local_names, "fqdn": "PAD-01.corp.local"}
    local = variant(NTLM, 1, ip_str="198.51.100.9", ntlm=ntlm)
    run(tmp_path, [*RECORDS, NTLM, local])
    assert table(
        tmp_path,
        "identity_evidence",
        "DISTINCT rec_id, normalized_value, is_infrastructure",
        "evidence_type = 'ntlm_dns_name'",
    ) == [(json.loads(NTLM)["_shodan"]["id"], "pragerberckhoff.com", False)]


def rec_id(line: str) -> str:
    return str(json.loads(line)["_shodan"]["id"])


def test_signal_seen_in_one_sighting_survives_dedupe(tmp_path: Path) -> None:
    later = variant(
        RDP, 1, timestamp="2026-10-26T23:00:00.000000", rdp_encryption=None, product=None, data="x"
    )
    run(tmp_path, [*RECORDS, RDP, later])
    (key,) = table(tmp_path, "service", "service_key", "sightings = 2")[0]
    assert table(tmp_path, "service_signal", "rec_id, signal_code", f"service_key = '{key}'") == [
        (rec_id(RDP), "rdp_exposed"),
        (rec_id(RDP), "rdp_standard_security"),
    ]


def test_no_signal_on_honeypot_or_cdn_services(tmp_path: Path) -> None:
    honeypot = variant(RDP, 1, ip_str="198.51.100.11", tags=["honeypot"])
    cdn = json.loads(variant(RDP, 2, ip_str="198.51.100.12", tags=["cdn"]))
    cdn["_shodan"]["options"] = {"hostname": "remote.example.com"}
    run(tmp_path, [*RECORDS, RDP, honeypot, json.dumps(cdn)])
    assert table(tmp_path, "service_signal", "DISTINCT rec_id") == [(rec_id(RDP),)]


def test_rules_match_only_what_the_reply_proves(tmp_path: Path) -> None:
    no_auth = {**json.loads(VNC)["vnc"], "security_types": {"1": "None"}}
    vnc_no_product = variant(VNC, 1, ip_str="198.51.100.21", vnc=no_auth, product=None)
    vnc_fictus = variant(VNC, 2, ip_str="198.51.100.22", vnc=no_auth, product="FictusVNC")
    lantronix = {"port": 30718, "transport": "udp", "lantronix": LANTRONIX}
    cloned = [variant(UNTAGGED, n, ip_str=f"198.51.100.{n + 30}", **lantronix) for n in (3, 4)]
    unique_mac = {**LANTRONIX, "mac": "00:0A:00:17:6D:02"}
    unique = variant(UNTAGGED, 5, ip_str="198.51.100.35", **{**lantronix, "lantronix": unique_mac})
    lines = [FTP_ANONYMOUS, SMB_IPC_ONLY, MYSQL_REFUSING, vnc_no_product, vnc_fictus, *cloned]
    run(tmp_path, [*RECORDS, *lines, unique])

    codes = ("ftp_anonymous", "smb_anonymous", "tag_database", "vnc_noauth", "lantronix_password")
    assert set(
        table(tmp_path, "service_signal", "rec_id, signal_code", f"signal_code IN {codes}")
    ) == {
        (rec_id(FTP_ANONYMOUS), "ftp_anonymous"),
        (rec_id(vnc_no_product), "vnc_noauth"),
        (rec_id(unique), "lantronix_password"),
    }


def test_provider_domain_stays_infrastructure_when_the_network_turns_cloud(
    tmp_path: Path,
) -> None:
    # The AS8075 case on the full 2026-10-26 file: once G1 made the network cloud, its many
    # tagged customer machines diluted office.com below the share and it became a business.
    net = "AS64501"
    customers = [
        variant(
            UNTAGGED,
            n,
            ip_str=f"198.51.100.{n}",
            asn=net,
            tags=["cloud"],
            hostnames=[f"app.customer{n}.com"],
        )
        for n in range(1, 9)
    ]
    own = [
        variant(UNTAGGED, n, ip_str=f"203.0.113.{n}", asn=net, hostnames=["mail.office.com"])
        for n in (9, 10)
    ]
    run(
        tmp_path,
        [*RECORDS, *customers, *own],
        [(net, ["Content"])],
        asn_cloud_min_addresses=3,
        network_domain_min_records=2,
    )
    assert table(
        tmp_path,
        "identity_evidence",
        "DISTINCT is_infrastructure, infra_reason",
        "normalized_value = 'office.com'",
    ) == [(True, "network_main_domain")]


def test_ransom_page_in_any_case_shows_the_note_as_evidence(tmp_path: Path) -> None:
    # A blank excerpt fails the file's blocking evidence check, so this case must not blank it.
    note = "Your database was backed up. To Recover Your Files send 0.1 BTC to the address below"
    page = variant(UNTAGGED, 1, ip_str="198.51.100.41", data=note)
    run(tmp_path, [*RECORDS, page])
    assert table(
        tmp_path, "service_signal", "evidence_field, evidence_text", "signal_code = 'ransom_note'"
    ) == [("data", "Recover Your Files send 0.1 BTC to the address below")]
