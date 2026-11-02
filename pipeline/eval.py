"""Measure gold's guesses: attribution on the synthetic cases, the finding-score answers
against outside sources, and the ranking comparison.

The cases are SYNTHETIC: written by AI with the answer known by construction, and reported
as such wherever their numbers appear.
"""

import gzip
import hashlib
import json
from collections import Counter
from pathlib import Path

import duckdb
from pydantic import BaseModel

from api.reports import (
    AnswersCheck,
    AttributionReport,
    Disagreement,
    EpssByAnswer,
    KevDisagreement,
    ModelAgreement,
    ModelCheck,
    QuestionAgreement,
    RankingReport,
    RankPair,
    ReportStamp,
    ScorerCount,
    Tally,
    VictimMatch,
)
from pipeline.gold import finding
from pipeline.gold.attribution import attribute
from pipeline.meta import report_stamp
from pipeline.ref import finding_scores, snapshot
from pipeline.settings import RefSettings, Settings
from pipeline.silver.identity import registrable_domain


class Evidence(BaseModel):
    type: str
    raw: str
    normalized: str | None
    is_infrastructure: bool
    infra_reason: str | None


class Service(BaseModel):
    ip: str
    spread: int = 1
    asn: str
    port: int
    hostname: str | None
    truth: str | None
    evidence: list[Evidence]


class Network(BaseModel):
    asn: str
    org: str
    owner_class: str
    owner_class_source: str
    asdb_landlord: bool | None = None


class Case(BaseModel):
    id: str
    scenario: str
    based_on: str
    networks: list[Network]
    services: list[Service]


class Cases(BaseModel):
    about: str
    cases: list[Case]


def load_cases(con: duckdb.DuckDBPyConnection, path: Path) -> None:
    """Create the tables an attribution strategy reads, plus `truth`, from the case file."""
    cases = Cases.model_validate_json(path.read_text()).cases
    services: list[tuple[str, str, int, str | None]] = []
    addresses: dict[str, tuple[str, str, str, str]] = {}
    evidence: list[tuple[str, str, str, str | None, bool, str | None]] = []
    truth: list[tuple[str, str, str | None]] = []
    landlords: dict[str, bool] = {}
    for case in cases:
        networks = {n.asn: n for n in case.networks}
        for net in case.networks:
            if net.asdb_landlord is not None:
                landlords[net.asn] = net.asdb_landlord
        for s in case.services:
            prefix, first = s.ip.rsplit(".", 1)
            for copy in range(s.spread):
                octet = int(first) + copy
                ip = f"{prefix}.{octet}"
                key = f"{case.id}:{ip}:{s.port}:{s.hostname}"
                net = networks[s.asn]
                address = (ip, s.asn, net.org, net.owner_class)
                if addresses.setdefault(ip, address) != address:
                    raise ValueError(f"{ip} is on two networks in the case file")
                services.append((key, ip, s.port, s.hostname))
                truth.append((key, case.id, s.truth))
                for e in s.evidence:
                    raw = e.raw.replace("{i}", str(copy)).replace("{o}", str(octet))
                    evidence.append(
                        (key, e.type, raw, e.normalized, e.is_infrastructure, e.infra_reason)
                    )
    tables = {
        "silver_service": (
            "service_key VARCHAR, ip VARCHAR, port INTEGER, hostname VARCHAR, noise_reason VARCHAR",
            [(*s, None) for s in services],
        ),
        "silver_address": (
            "ip VARCHAR, asn VARCHAR, org VARCHAR, owner_class VARCHAR",
            list(addresses.values()),
        ),
        "silver_identity_evidence": (
            "service_key VARCHAR, evidence_type VARCHAR, raw_value VARCHAR, "
            "normalized_value VARCHAR, is_infrastructure BOOLEAN, infra_reason VARCHAR",
            evidence,
        ),
        "asdb_landlord": ("asn VARCHAR, landlord BOOLEAN", list(landlords.items())),
        "truth": ("service_key VARCHAR, case_id VARCHAR, truth VARCHAR", truth),
    }
    for name, (columns, rows) in tables.items():
        con.execute(f"CREATE OR REPLACE TABLE {name} ({columns})")
        if rows:
            marks = ", ".join("?" * (columns.count(",") + 1))
            con.executemany(f"INSERT INTO {name} VALUES ({marks})", rows)


def score_attribution(
    con: duckdb.DuckDBPyConnection, strategy: str, stamp: ReportStamp
) -> AttributionReport:
    """Per service: the true company named is right, unknown is a miss, any other is wrong."""
    rows = (
        attribute(con, strategy)
        .set_alias("a")
        .join(con.table("truth").set_alias("t"), "a.service_key = t.service_key")
        .select("t.case_id, t.truth, a.company_key, a.confidence")
        .fetchall()
    )
    total = Counter[str]()
    by_case: dict[str, Counter[str]] = {}
    by_confidence: dict[str, Counter[str]] = {}
    for case_id, truth, company, confidence in rows:
        outcome = "right" if company == truth else "missed" if company is None else "wrong"
        total[outcome] += 1
        by_case.setdefault(case_id, Counter())[outcome] += 1
        by_confidence.setdefault(confidence or "unknown", Counter())[outcome] += 1
    return AttributionReport(
        stamp=stamp,
        strategy=strategy,
        total=Tally(**total),
        by_case={k: Tally(**v) for k, v in by_case.items()},
        by_confidence={k: Tally(**v) for k, v in sorted(by_confidence.items())},
    )


def check_answers(settings: RefSettings) -> AnswersCheck:
    """Report how the stored answers compare with outside sources and with each other.

    Reported, never a gate: KEV against the blind exploitation answer, the median EPSS by
    that answer (it should rise from none to poc to active), each question's agreement
    between the model gold scores with and every other model, and where exposed RDP lands
    among exposures.
    """
    answers = [
        a
        for a in finding_scores.read_answers(settings.answers_path)
        if a.prompt_version == settings.prompt_version
    ]
    answers_hash = (
        hashlib.sha256(settings.answers_path.read_bytes()).hexdigest()
        if settings.answers_path.exists()
        else "none"
    )
    stamp_inputs = {
        "answers": str(settings.answers_path),
        "answers_sha256": answers_hash,
        "prompt_version": settings.prompt_version,
        "finding_scorer": settings.finding_scorer,
    }
    if not answers:
        return AnswersCheck(
            stamp=report_stamp("pipeline ref finding-scores check", **stamp_inputs),
            prompt_version=settings.prompt_version,
            answers_model=settings.answers_model,
            kev_catalog_version=None,
            epss_version=None,
            models=[],
            agreement=[],
        )
    con = duckdb.connect()
    con.execute(
        "CREATE TABLE answer (item_id VARCHAR, kind VARCHAR, status VARCHAR, "
        "exploitation VARCHAR, automatable VARCHAR, technical_impact VARCHAR, model VARCHAR)"
    )
    con.executemany(
        "INSERT INTO answer VALUES (?, ?, ?, ?, ?, ?, ?)",
        [
            (
                a.item_id,
                a.kind,
                a.status,
                a.exploitation,
                a.automatable,
                a.technical_impact,
                a.model,
            )
            for a in answers
        ],
    )
    con.execute(
        f"""
        CREATE TABLE kev AS SELECT DISTINCT v.cveID AS cve FROM (
          SELECT unnest(vulnerabilities) AS v
          FROM read_json('{settings.kev_path}', maximum_object_size = 104857600));
        CREATE TABLE epss AS SELECT cve, epss::DOUBLE AS epss
          FROM read_csv('{settings.epss_path}', skip = 1, header = true);
        """
    )
    kev_version = json.loads(settings.kev_path.read_text()).get("catalogVersion")
    with gzip.open(settings.epss_path, "rt") as f:
        epss_header = f.readline().strip().lstrip("#")
    models = [m for (m,) in con.execute("SELECT DISTINCT model FROM answer ORDER BY 1").fetchall()]
    checks = []
    for model in models:
        statuses = con.execute(
            "SELECT status, count(*) FROM answer WHERE model = ? GROUP BY 1 ORDER BY 1", [model]
        ).fetchall()
        both, model_only, kev_only, neither = con.execute(
            """
            SELECT count(*) FILTER (WHERE a.exploitation = 'active' AND k.cve IS NOT NULL),
              count(*) FILTER (WHERE a.exploitation = 'active' AND k.cve IS NULL),
              count(*) FILTER (WHERE a.exploitation <> 'active' AND k.cve IS NOT NULL),
              count(*) FILTER (WHERE a.exploitation <> 'active' AND k.cve IS NULL)
            FROM answer a LEFT JOIN kev k ON k.cve = a.item_id
            WHERE a.model = ? AND a.status = 'answered' AND a.item_id LIKE 'CVE-%'
            """,
            [model],
        ).fetchone() or (0, 0, 0, 0)
        kev_disagreements = [
            KevDisagreement(item_id=item_id, exploitation=exploitation, on_kev=listed)
            for item_id, exploitation, listed in con.execute(
                """
                SELECT a.item_id, a.exploitation, k.cve IS NOT NULL FROM answer a
                LEFT JOIN kev k ON k.cve = a.item_id
                WHERE a.model = ? AND a.status = 'answered' AND a.item_id LIKE 'CVE-%'
                  AND (a.exploitation = 'active') <> (k.cve IS NOT NULL)
                ORDER BY 1
                """,
                [model],
            ).fetchall()
        ]
        epss_by_answer = [
            EpssByAnswer(exploitation=level, cves_with_epss=n, median_epss=median)
            for level, n, median in con.execute(
                """
                SELECT a.exploitation, count(e.epss), median(e.epss) FROM answer a
                LEFT JOIN epss e ON e.cve = a.item_id
                WHERE a.model = ? AND a.status = 'answered' AND a.item_id LIKE 'CVE-%'
                GROUP BY 1
                ORDER BY CASE a.exploitation WHEN 'none' THEN 1 WHEN 'poc' THEN 2 ELSE 3 END
                """,
                [model],
            ).fetchall()
        ]
        quoted = model.replace("'", "''")
        con.execute(
            "CREATE OR REPLACE VIEW finding_answers AS "
            f"SELECT * FROM answer WHERE model = '{quoted}'"
        )
        con.execute("CREATE OR REPLACE VIEW kev_catalog AS SELECT cve FROM kev")
        scores = finding.FINDING_SCORERS[settings.finding_scorer](con).sql_query()
        exposures = con.execute(
            f"SELECT s.item_id, s.score FROM ({scores}) s JOIN answer a ON a.item_id = s.item_id "
            f"WHERE a.model = '{quoted}' AND a.kind = 'exposure' ORDER BY s.score DESC, 1"
        ).fetchall()
        checks.append(
            ModelCheck(
                model=model,
                statuses=dict(statuses),
                kev_both=both,
                kev_model_only=model_only,
                kev_only=kev_only,
                kev_neither=neither,
                kev_disagreements=kev_disagreements,
                epss_by_answer=epss_by_answer,
                rdp_exposed_rank=next(
                    (i for i, (item, _) in enumerate(exposures, 1) if item == "rdp_exposed"),
                    None,
                ),
                scored_exposures=len(exposures),
            )
        )

    first = settings.answers_model
    others = [m for m in models if m != first] if first in models else []
    agreement = []
    for second in others:
        questions = []
        for question in ("exploitation", "automatable", "technical_impact"):
            same, n = con.execute(
                f"""
                SELECT count(*) FILTER (WHERE x.{question} = y.{question}), count(*)
                FROM answer x JOIN answer y USING (item_id)
                WHERE x.model = ? AND y.model = ? AND x.status = 'answered'
                  AND y.status = 'answered'
                """,
                [first, second],
            ).fetchone() or (0, 0)
            disagreements = [
                Disagreement(item_id=item_id, reference=a, other=b)
                for item_id, a, b in con.execute(
                    f"""
                    SELECT item_id, x.{question}, y.{question}
                    FROM answer x JOIN answer y USING (item_id)
                    WHERE x.model = ? AND y.model = ? AND x.status = 'answered'
                      AND y.status = 'answered' AND x.{question} <> y.{question}
                    ORDER BY 1
                    """,
                    [first, second],
                ).fetchall()
            ]
            questions.append(
                QuestionAgreement(
                    question=question, agree=same, both_answered=n, disagreements=disagreements
                )
            )
        agreement.append(ModelAgreement(reference=first, other=second, questions=questions))
    return AnswersCheck(
        stamp=report_stamp(
            "pipeline ref finding-scores check",
            **stamp_inputs,
            kev_catalog_version=str(kev_version),
            epss=epss_header,
        ),
        prompt_version=settings.prompt_version,
        answers_model=settings.answers_model,
        kev_catalog_version=kev_version,
        epss_version=epss_header,
        models=checks,
        agreement=agreement,
    )


def ranking_report_path(data_root: Path, file_id: str) -> Path:
    return data_root / "_meta" / "eval" / f"ranking_{file_id}.json"


def compare_rankings(settings: Settings, file_id: str) -> RankingReport:
    """The two company scorers side by side, and where past ransomware victims landed.

    No test can show either rule is better: a synthetic "right order" would be our own
    preference written down. The victims look backwards (they show whether past victims were
    exposed when we scanned, not whether the ranking predicts the next one), and are too few
    for a rate. ransomware.live's terms: name the source and never republish raw records, so
    only totals and our own companies and ranks are reported. Their third term,
    non-commercial use, is met because this is an interview assignment.
    """
    company = settings.data_root / "gold" / "company" / f"file_id={file_id}" / "*.parquet"
    con = duckdb.connect()
    con.execute(f"CREATE VIEW company AS SELECT * FROM read_parquet('{company}')")
    scorers = [
        ScorerCount(scorer=scorer, ranked=ranked, total=total)
        for scorer, ranked, total in con.execute(
            "SELECT company_scorer, count(rank), count(*) FROM company GROUP BY 1 ORDER BY 1"
        ).fetchall()
    ]
    if len(scorers) < 2 or not any(s.ranked for s in scorers):
        return RankingReport(
            stamp=report_stamp("pipeline eval ranking", file_id=file_id),
            file_id=file_id,
            note="Illustration, not a measurement.",
            scorers=scorers,
            first_scorer=None,
            second_scorer=None,
            top_100_shared=None,
            biggest_moves=[],
            victims=None,
        )
    first, second = scorers[0].scorer, scorers[1].scorer
    pair = f"""
        SELECT x.company_key, x.company_name, x.rank AS rank_x, y.rank AS rank_y
        FROM company x JOIN company y USING (company_key)
        WHERE x.company_scorer = '{first}' AND y.company_scorer = '{second}'
    """
    (shared,) = con.execute(
        f"SELECT count(*) FROM ({pair}) WHERE rank_x <= 100 AND rank_y <= 100"
    ).fetchone() or (0,)
    moves = con.execute(
        f"SELECT * FROM ({pair}) WHERE (rank_x <= 100 OR rank_y <= 100) "
        "AND rank_x IS DISTINCT FROM rank_y "
        "ORDER BY abs(rank_x - rank_y) DESC NULLS FIRST, company_key LIMIT 10"
    ).fetchall()

    snapshot_dir, as_of = snapshot.newest(settings.ref_root, "ransomware_live")
    domains = set()
    for path in sorted(snapshot_dir.glob("victims_*.json")):
        for victim in json.loads(path.read_text())["victims"]:
            site = (victim.get("website") or "").strip().lower()
            site = site.removeprefix("https://").removeprefix("http://").split("/")[0]
            domain = registrable_domain(site.split(":")[0])[0] if site else None
            if domain:
                domains.add(domain)
    con.execute("CREATE TABLE victim (domain VARCHAR)")
    con.executemany("INSERT INTO victim VALUES (?)", [(d,) for d in sorted(domains)])
    (matched, ranked) = con.execute(
        f"SELECT count(*), count(rank_x) FROM ({pair}) p SEMI JOIN victim v "
        "ON v.domain = p.company_key"
    ).fetchone() or (0, 0)
    victims = con.execute(
        f"SELECT * FROM ({pair}) p SEMI JOIN victim v ON v.domain = p.company_key "
        "WHERE rank_x IS NOT NULL ORDER BY rank_x"
    ).fetchall()
    return RankingReport(
        stamp=report_stamp("pipeline eval ranking", file_id=file_id, ransomware_live_as_of=as_of),
        file_id=file_id,
        note="Illustration, not a measurement.",
        scorers=scorers,
        first_scorer=first,
        second_scorer=second,
        top_100_shared=shared,
        biggest_moves=[
            RankPair(company_key=k, company_name=n, rank_first=x, rank_second=y)
            for k, n, x, y in moves
        ],
        victims=VictimMatch(
            source="Ransomware.live (https://www.ransomware.live)",
            as_of=as_of,
            victim_domains=len(domains),
            matched=matched,
            ranked=ranked,
            companies=[
                RankPair(company_key=k, company_name=n, rank_first=x, rank_second=y)
                for k, n, x, y in victims
            ],
        ),
    )
