import ipaddress
from pathlib import Path

import duckdb

from pipeline import stage
from pipeline.meta import Check
from pipeline.silver.owner_class import MAPPED_TYPES
from pipeline.silver.signal_rules import RULES

IPV4 = r"^((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$"


def run(
    con: duckdb.DuckDBPyConnection, staging: Path, rows: dict[str, int]
) -> tuple[list[Check], dict[str, float]]:
    """Blocking checks on the staged tables, and the run-log metrics that don't block."""

    def t(table: str) -> str:
        return stage.read(staging, table)

    def one(sql: str) -> tuple[int, ...]:
        row = con.execute(sql).fetchone()
        assert row is not None
        return tuple(int(x or 0) for x in row)

    def missing(log: str, column: str, target: str) -> int:
        return one(
            f"SELECT count(*) FROM {log} l WHERE NOT EXISTS "
            f"(SELECT 1 FROM {target} x WHERE x.{column} = l.{column})"
        )[0]

    readable_bronze = "(SELECT rec_id FROM bronze_banner WHERE parse_error IS NULL)"
    (readable,) = one("SELECT count(*) FROM bronze_banner WHERE parse_error IS NULL")
    (expected_vulns,) = one(f"SELECT count(*) FROM bronze_vuln v WHERE rec_id IN {readable_bronze}")
    bad_v4, bad_version, upper_host = one(
        f"SELECT count(*) FILTER (WHERE ip_version = 4 AND NOT regexp_matches(ip, '{IPV4}')), "
        "count(*) FILTER (WHERE ip_version IS DISTINCT FROM 4 AND ip_version IS DISTINCT FROM 6),"
        f" count(*) FILTER (WHERE hostname <> lower(hostname)) FROM {t('sightings')}"
    )
    v6 = con.execute(f"SELECT DISTINCT ip FROM {t('sightings')} WHERE ip_version = 6").fetchall()
    bad_v6 = sum(1 for (ip,) in v6 if not _is_compressed_v6(ip))
    null_key, dup_key, sightings_sum = one(
        f"SELECT count(*) FILTER (WHERE service_key IS NULL), "
        f"count(service_key) - count(DISTINCT service_key), sum(sightings) FROM {t('service')}"
    )
    (dup_ip,) = one(f"SELECT count(*) - count(DISTINCT ip) FROM {t('address')}")
    (null_infra,) = one(
        f"SELECT count(*) FILTER (WHERE is_infrastructure IS NULL) FROM {t('identity_evidence')}"
    )
    orphan = {
        "service.ip": missing(t("service"), "ip", t("address")),
        "identity_evidence.rec_id": missing(t("identity_evidence"), "rec_id", readable_bronze),
        "service_vuln.rec_id": missing(t("service_vuln"), "rec_id", readable_bronze),
        "identity_evidence.service_key": missing(
            t("identity_evidence"), "service_key", t("service")
        ),
        "service_vuln.service_key": missing(t("service_vuln"), "service_key", t("service")),
        "service_signal.rec_id": missing(t("service_signal"), "rec_id", readable_bronze),
        "service_signal.service_key": missing(t("service_signal"), "service_key", t("service")),
    }
    on_noise, no_evidence, unknown_code = one(
        f"SELECT count(*) FILTER (WHERE sv.noise_reason IS NOT NULL OR a.owner_class = 'cdn'), "
        "count(*) FILTER (WHERE coalesce(g.evidence_text, '') = ''), "
        f"count(*) FILTER (WHERE g.signal_code IS NULL OR NOT list_contains({list(RULES)}, "
        f"g.signal_code)) FROM {t('service_signal')} g "
        f"LEFT JOIN {t('service')} sv USING (service_key) "
        f"LEFT JOIN {t('address')} a ON a.ip = sv.ip"
    )
    unmapped = [
        r[0]
        for r in con.execute(
            "SELECT DISTINCT ty FROM (SELECT unnest(info_types) AS ty FROM peeringdb) "
            "WHERE NOT list_contains($mapped, ty) ORDER BY 1",
            {"mapped": MAPPED_TYPES},
        ).fetchall()
    ]

    checks = [
        Check(
            name="sightings_reconciliation",
            blocking=True,
            passed=rows["sightings"] == readable,
            detail=f"{rows['sightings']} sightings; bronze has {readable} readable records",
        ),
        Check(
            name="ip_standard_form",
            blocking=True,
            passed=bad_v4 == bad_v6 == bad_version == 0,
            detail=f"{bad_v4} IPv4 sightings and {bad_v6} distinct IPv6 not in standard form; "
            f"{bad_version} with ip_version not 4 or 6",
        ),
        Check(
            name="hostname_lowercase",
            blocking=True,
            passed=upper_host == 0,
            detail=f"{upper_host} sightings with uppercase in hostname",
        ),
        Check(
            name="service_key_unique",
            blocking=True,
            passed=null_key == dup_key == 0,
            detail=f"{null_key} NULL, {dup_key} duplicated",
        ),
        Check(
            name="dedupe_loses_no_record",
            blocking=True,
            passed=sightings_sum == readable,
            detail=f"service.sightings sums to {sightings_sum}; {readable} readable records",
        ),
        Check(
            name="address_ip_unique",
            blocking=True,
            passed=dup_ip == 0,
            detail=f"{dup_ip} duplicated",
        ),
        Check(
            name="infrastructure_flag_set",
            blocking=True,
            passed=null_infra == 0,
            detail=f"{null_infra} identity_evidence rows with is_infrastructure NULL",
        ),
        Check(
            name="vuln_reconciliation",
            blocking=True,
            passed=rows["service_vuln"] == expected_vulns,
            detail=f"service_vuln {rows['service_vuln']} rows; "
            f"bronze vuln has {expected_vulns} on readable records",
        ),
        Check(
            name="references_resolve",
            blocking=True,
            passed=not any(orphan.values()),
            detail=", ".join(f"{k} {v} unmatched" for k, v in orphan.items()),
        ),
        Check(
            name="signal_skips_noise_and_cdn",
            blocking=True,
            passed=on_noise == 0,
            detail=f"{on_noise} service_signal rows on a noise service or a cdn address",
        ),
        Check(
            name="signal_evidence_present",
            blocking=True,
            passed=no_evidence == 0,
            detail=f"{no_evidence} service_signal rows with no evidence_text",
        ),
        Check(
            name="signal_codes_known",
            blocking=True,
            passed=unknown_code == 0,
            detail=f"{unknown_code} service_signal rows with a code not in the rule catalogue",
        ),
        Check(
            name="peeringdb_types_mapped",
            blocking=False,
            passed=not unmapped,
            detail=", ".join(unmapped) or "all mapped",
        ),
    ]
    return checks, _metrics(con, staging)


def _is_compressed_v6(ip: str) -> bool:
    try:
        return str(ipaddress.IPv6Address(ip)) == ip
    except ValueError:
        return False


def _metrics(con: duckdb.DuckDBPyConnection, staging: Path) -> dict[str, float]:
    def t(table: str) -> str:
        return stage.read(staging, table)

    def pairs(sql: str, prefix: str) -> dict[str, float]:
        return {f"{prefix}.{k}": float(v) for k, v in con.execute(sql).fetchall()}

    metrics: dict[str, float] = {}
    metrics |= pairs(
        f"SELECT owner_class_source, count(*) FROM {t('address')} GROUP BY 1", "addresses_by_source"
    )
    metrics |= pairs(
        f"SELECT a.owner_class_source, count(*) FROM {t('sightings')} s "
        f"JOIN {t('address')} a USING (ip) GROUP BY 1",
        "records_by_source",
    )
    metrics |= pairs(
        f"SELECT owner_class, count(*) FROM {t('address')} GROUP BY 1", "addresses_by_class"
    )
    metrics |= pairs(
        f"SELECT a.owner_class, count(*) FROM {t('sightings')} s "
        f"JOIN {t('address')} a USING (ip) GROUP BY 1",
        "records_by_class",
    )
    # The known gap: unknown owner and no clue that names a business, so gold cannot
    # attribute these at all until owner-class data rules exist.
    gap = con.execute(
        f"""
        WITH named AS (
          SELECT DISTINCT s.ip
          FROM {t("identity_evidence")} e JOIN {t("service")} s USING (service_key)
          WHERE NOT e.is_infrastructure
        ),
        gap AS (
          SELECT ip FROM {t("address")}
          WHERE owner_class = 'unknown' AND ip NOT IN (SELECT ip FROM named)
        )
        SELECT (SELECT count(*) FROM gap),
          (SELECT count(*) FROM {t("sightings")} WHERE ip IN (SELECT ip FROM gap))
        """
    ).fetchone()
    assert gap is not None
    metrics["known_gap.addresses"], metrics["known_gap.records"] = float(gap[0]), float(gap[1])
    metrics["asn_cloud_share.asns"] = float(
        con.execute(
            f"SELECT count(DISTINCT asn) FROM {t('address')} "
            "WHERE owner_class_source = 'asn_cloud_share'"
        ).fetchall()[0][0]
    )
    # G1 moves whole ASNs, so a company's own block on a cloud ASN becomes cloud and leaves the
    # known gap without being attributed. An org never seen on a scanner-tagged address of the
    # same ASN is the visible upper bound; it also counts the provider's own org names.
    metrics["asn_cloud_share.org_unseen_on_tagged"] = float(
        con.execute(
            f"""
            SELECT count(*) FROM {t("address")} m
            WHERE owner_class_source = 'asn_cloud_share' AND NOT EXISTS (
              SELECT 1 FROM {t("address")} x
              WHERE x.owner_class_source = 'scanner_tag' AND x.owner_class = 'cloud'
                AND x.asn = m.asn AND x.org IS NOT DISTINCT FROM m.org)
            """
        ).fetchall()[0][0]
    )
    signals = t("service_signal")
    metrics |= pairs(f"SELECT signal_code, count(*) FROM {signals} GROUP BY 1", "signals.rows")
    metrics |= pairs(
        f"SELECT signal_code, count(DISTINCT service_key) FROM {signals} GROUP BY 1",
        "signals.services",
    )
    metrics |= pairs(
        f"""
        SELECT g.signal_code, count(DISTINCT g.service_key)
        FROM {signals} g JOIN {t("service")} sv USING (service_key) JOIN {t("address")} a
          ON a.ip = sv.ip
        WHERE a.owner_class IN ('enterprise', 'edu', 'gov') OR g.service_key IN (
          SELECT service_key FROM {t("identity_evidence")} WHERE NOT is_infrastructure)
        GROUP BY 1
        """,
        "signals.attributable_services",
    )
    # What the NTLM and LDAP routes add: services on a business or unknown address whose only
    # business clue is a name the server reports about itself. Decides whether they stay.
    first_clue = con.execute(
        f"""
        WITH clue AS (
          SELECT service_key,
            bool_or(evidence_type IN ('ntlm_dns_name', 'ldap_dns_name')) AS from_reply,
            bool_or(evidence_type NOT IN ('ntlm_dns_name', 'ldap_dns_name')) AS from_other
          FROM {t("identity_evidence")}
          WHERE NOT is_infrastructure
          GROUP BY service_key
        )
        SELECT count(*), count(DISTINCT s.ip)
        FROM clue JOIN {t("service")} s USING (service_key) JOIN {t("address")} a USING (ip)
        WHERE from_reply AND NOT from_other
          AND a.owner_class IN ('unknown', 'enterprise', 'edu', 'gov')
        """
    ).fetchone()
    assert first_clue is not None
    metrics["reply_names_first_clue.services"] = float(first_clue[0])
    metrics["reply_names_first_clue.addresses"] = float(first_clue[1])
    metrics |= pairs(
        f"SELECT evidence_type, count(*) FROM {t('identity_evidence')} GROUP BY 1",
        "evidence_by_type",
    )
    metrics |= pairs(
        f"SELECT infra_reason, count(*) FROM {t('identity_evidence')} "
        "WHERE is_infrastructure GROUP BY 1",
        "evidence_infrastructure_by_reason",
    )
    metrics |= pairs(
        f"SELECT evidence_type, count(*) FROM {t('identity_candidates')} "
        "WHERE normalized_value IS NULL GROUP BY 1",
        "hostnames_dropped_no_domain",
    )
    metrics |= pairs(
        f"SELECT platform, count(*) FROM {t('identity_candidates')} "
        "WHERE platform IS NOT NULL GROUP BY 1",
        "platform_names",
    )
    echoes = con.execute(
        f"SELECT sum(len(list_filter(hostnames, lambda h: h = hostname))) FROM {t('sightings')}"
    ).fetchone()
    metrics["dns_hostname_echoes_dropped"] = float(echoes[0] or 0) if echoes else 0.0
    metrics |= pairs(
        f"SELECT coalesce(noise_reason, 'none'), count(*) FROM {t('service')} GROUP BY 1",
        "services_by_noise",
    )
    ae = con.execute(
        f"SELECT count(*) FILTER (WHERE answers_everything), "
        f"count(*) FILTER (WHERE answers_everything AND owner_class <> 'cdn' "
        f"AND NOT is_honeypot) FROM {t('address')}"
    ).fetchone()
    assert ae is not None
    metrics["answers_everything.addresses"] = float(ae[0])
    metrics["answers_everything.non_cdn_non_honeypot"] = float(ae[1])
    return metrics
