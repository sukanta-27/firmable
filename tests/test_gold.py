import gzip
import json
from pathlib import Path

import anthropic
import duckdb
import pytest
from anthropic.types import Message

from pipeline import eval, gold, llm_usage
from pipeline.gold import company
from pipeline.gold.attribution import attribute
from pipeline.meta import report_stamp
from pipeline.ref import finding_scores
from pipeline.settings import RefSettings, Settings
from tests.helpers import run, variant

CASES = Path(__file__).parent / "eval" / "attribution_cases.json"


def test_synthetic_cases_rules_ab_v1_commits_to() -> None:
    con = duckdb.connect()
    eval.load_cases(con, CASES)
    report = eval.score_attribution(con, "rules_ab_v1", report_stamp("test"))

    # Known failures, not asserted: cloud_customer_fleet (a tenant with a landlord's spread is
    # dropped by rule A) and template_directory_name (no rule for generic directory names).
    # hoster_ntlm_forest and cloud_rdns_spread being right means no landlord is named.
    must_be_right = [
        "tenant_on_shared_hosting",
        "cloud_rdns_spread",
        "hoster_ntlm_forest",
        "tenant_ntlm_on_isp",
        "university_own_network",
        "company_network_no_domain",
        "landlord_declared_enterprise",
        "scan_hostname_vs_stale_rdns",
        "placeholder_domain",
        "home_lines_ip_number_rdns",
        "cdn_scanned_by_hostname",
        "platform_subdomain",
        "virtual_hosting_one_address",
        "company_on_unclassified_network",
        "small_business_rdns_only",
    ]
    wrong_or_missed = {
        case: tally
        for case, tally in report.by_case.items()
        if case in must_be_right and (tally.missed or tally.wrong)
    }
    assert wrong_or_missed == {}

    attributed = attribute(con, "rules_ab_v1").set_alias("a")
    stale = (
        attributed.join(con.table("truth").set_alias("t"), "a.service_key = t.service_key")
        .filter("t.case_id = 'scan_hostname_vs_stale_rdns'")
        .select("a.company_key, a.confidence")
        .fetchall()
    )
    assert stale == [("meridianfreight.com", "Low")]


SIGNAL_RECORDS = (
    (Path(__file__).parent / "fixtures" / "signal_records.jsonl").read_text().splitlines()
)
RDP = next(r for r in SIGNAL_RECORDS if '"51215953' in r)


def answer(item_id: str, **changes: object) -> dict[str, object]:
    return {
        "item_id": item_id,
        "answerable": True,
        "exploitation": "active",
        "automatable": "yes",
        "technical_impact": "total",
        "reason": "Brute-forced login.",
        "salesperson_line": "Anyone can try passwords on your remote desktop.",
        **changes,
    }


def test_answer_import_keeps_bad_answers_unscored_and_render_stays_blind(tmp_path: Path) -> None:
    run(tmp_path, [RDP])
    settings = Settings(
        data_root=tmp_path / "data", ref_root=tmp_path / "ref", answers_path=tmp_path / "a.jsonl"
    )
    prompt = (finding_scores.render(settings) / "prompt.md").read_text().lower()
    assert "rdp_exposed" in prompt
    assert not any(word in prompt for word in ("kev", "epss", "cvss"))
    # Real summaries: CVE-2017-7269's trailing clause, CVE-2021-41773's closing sentence.
    assert (
        finding_scores.without_exploitation_claims(
            'via a long header beginning with "If: <http://" in a PROPFIND request, '
            "as exploited in the wild in July or August 2016."
        )
        == 'via a long header beginning with "If: <http://" in a PROPFIND request.'
    )
    assert (
        finding_scores.without_exploitation_claims(
            "Apache 2.4.49 is affected. This issue is known to be exploited in the wild."
        )
        == "Apache 2.4.49 is affected."
    )

    render_dir = tmp_path / "render"
    render_dir.mkdir()
    items: list[dict[str, object]] = [
        {"item_id": i, "kind": "exposure", "description": "d", "evidence": []}
        for i in ("good", "bad_value", "unsure", "missing", "not_a_bool", "twice")
    ]
    (render_dir / "items.json").write_text(json.dumps(items))
    reply = tmp_path / "reply.json"
    reply.write_text(
        "```json\n"
        + json.dumps(
            [
                answer("good"),
                answer("bad_value", exploitation="high"),
                answer("unsure", answerable=False, exploitation=None),
                answer("not_in_render"),
                answer("not_a_bool", answerable="no"),
                answer("twice"),
                answer("twice", exploitation="none"),
            ]
        )
        + "\n```"
    )

    counts = finding_scores.import_answers(settings, reply, "m", "claude_code", render_dir)
    first = settings.answers_path.read_text()
    statuses = {a.item_id: a.status for a in finding_scores.read_answers(settings.answers_path)}
    assert statuses == {
        "good": "answered",
        "bad_value": "invalid",
        "unsure": "unanswerable",
        "missing": "invalid",
        "not_a_bool": "invalid",
        "twice": "invalid",
    }
    assert counts["unknown_item"] == 1

    finding_scores.import_answers(settings, reply, "m", "claude_code", render_dir)
    assert settings.answers_path.read_text() == first


def test_check_compares_each_model_with_the_one_gold_scores_with(tmp_path: Path) -> None:
    kev, epss = tmp_path / "kev.json", tmp_path / "epss.csv.gz"
    kev.write_text(json.dumps({"catalogVersion": "t", "vulnerabilities": [{"cveID": "CVE-1"}]}))
    with gzip.open(epss, "wt") as f:
        f.write("#model_version:t,score_date:t\ncve,epss,percentile\nCVE-1,0.9,0.99\n")
    settings = RefSettings(answers_path=tmp_path / "a.jsonl", kev_path=kev, epss_path=epss)
    rows = [
        finding_scores.Answer(
            item_id=item_id,
            kind="vulnerability" if item_id.startswith("CVE") else "exposure",
            status="answered",
            exploitation=exploitation,
            automatable="yes",
            technical_impact="total",
            model=model,
            prompt_version=settings.prompt_version,
            run_via="api",
            run_date="2026-11-02",
            input_hash="h",
        )
        for model in ("claude-haiku-5-5", "claude-opus-5-5", "claude-sonnet-5-5")
        for item_id, exploitation in (("CVE-1", "active"), ("rdp_exposed", "active"))
    ]
    settings.answers_path.write_text("".join(a.model_dump_json() + "\n" for a in rows))

    out = eval.check_answers(settings).lines()

    # Alphabetically haiku sorts before opus, which once made it the reference model.
    assert [line for line in out if line.startswith("\n== agreement")] == [
        "\n== agreement, claude-opus-5-5 vs claude-haiku-5-5, items both answered",
        "\n== agreement, claude-opus-5-5 vs claude-sonnet-5-5, items both answered",
    ]


def test_a_refused_ask_imports_nothing_but_is_logged_and_costed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    refusal = Message.model_validate(
        {
            "id": "msg_t",
            "type": "message",
            "role": "assistant",
            "model": "claude-haiku-5-5",
            "content": [],
            "stop_reason": "refusal",
            "stop_sequence": None,
            "usage": {"input_tokens": 12_000, "output_tokens": 300},
        }
    )

    class Stream:
        request_id = "req_t"

        def __enter__(self) -> "Stream":
            return self

        def __exit__(self, *_: object) -> None:
            return None

        def get_final_message(self) -> Message:
            return refusal

    class Client:
        def __init__(self, **_: object) -> None:
            self.messages = self

        def stream(self, **_: object) -> Stream:
            return Stream()

    monkeypatch.setattr(anthropic, "Anthropic", Client)
    settings = RefSettings(
        answers_path=tmp_path / "a.jsonl",
        llm_usage_path=tmp_path / "calls.jsonl",
        llm_usage_report=tmp_path / "summary.json",
    )
    render_dir = tmp_path / "render"
    render_dir.mkdir()
    (render_dir / "items.json").write_text(
        json.dumps([{"item_id": "x", "kind": "exposure", "description": "d", "evidence": []}])
    )
    (render_dir / "prompt.md").write_text("p")

    with pytest.raises(RuntimeError, match="refusal"):
        finding_scores.ask(settings, render_dir, "claude-haiku-5-5")

    assert not settings.answers_path.exists()
    [total] = llm_usage.summarise(settings).totals
    assert (total.calls, total.failures, total.unpriced_calls) == (1, 1, 0)
    assert total.cost_usd == pytest.approx((12_000 * 0.10 + 300 * 0.50) / 1_000_000)


def _measure_setup(tmp_path: Path) -> tuple[RefSettings, Path]:
    settings = RefSettings(
        ref_root=tmp_path / "ref",
        answers_path=tmp_path / "answers.jsonl",
        llm_usage_path=tmp_path / "calls.jsonl",
        llm_usage_report=tmp_path / "summary.json",
    )
    settings.answers_path.write_text('{"item_id": "x", "model": "claude-opus-5-5"}\n')
    render_dir = settings.ref_root / "finding_scores" / "prompt_v1" / "2026-11-01"
    render_dir.mkdir(parents=True)
    (render_dir / "items.json").write_text("[]")
    (render_dir / "prompt.md").write_text("p")
    (render_dir / "response_claude-opus-5-5.json").write_text("the reply gold was built from")
    return settings, render_dir


def test_measure_logs_the_call_and_leaves_answers_and_render_untouched(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reply = Message.model_validate(
        {
            "id": "msg_t",
            "type": "message",
            "role": "assistant",
            "model": "claude-opus-5-5",
            "content": [{"type": "text", "text": "[]"}],
            "stop_reason": "end_turn",
            "stop_sequence": None,
            "usage": {"input_tokens": 19_360, "output_tokens": 40_000},
        }
    )

    class Stream:
        request_id = "req_t"

        def __enter__(self) -> "Stream":
            return self

        def __exit__(self, *_: object) -> None:
            return None

        def get_final_message(self) -> Message:
            return reply

    class Client:
        def __init__(self, **_: object) -> None:
            self.messages = self

        def stream(self, **_: object) -> Stream:
            return Stream()

    monkeypatch.setattr(anthropic, "Anthropic", Client)
    settings, render_dir = _measure_setup(tmp_path)
    before = {p: p.read_bytes() for p in [settings.answers_path, *render_dir.iterdir()]}

    kept = finding_scores.measure(settings, render_dir, "claude-opus-5-5")

    assert {p: p.read_bytes() for p in [settings.answers_path, *render_dir.iterdir()]} == before
    assert render_dir not in kept.parents
    assert finding_scores.newest_render(settings) == render_dir
    [total] = llm_usage.summarise(settings).totals
    assert (total.model, total.calls, total.output_tokens) == ("claude-opus-5-5", 1, 40_000)


def test_measure_fails_if_anything_touches_the_answers_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings, render_dir = _measure_setup(tmp_path)

    def provider_that_writes_answers(s: RefSettings, render: Path, model: str) -> Path:
        s.answers_path.write_text("overwritten")
        return render / "reply.json"

    monkeypatch.setitem(finding_scores.ANSWER_PROVIDERS, "api", provider_that_writes_answers)

    with pytest.raises(RuntimeError, match=r"answers\.jsonl"):
        finding_scores.measure(settings, render_dir, "claude-opus-5-5")


def test_ranking_follows_weighted_score_then_confidence_then_breadth_then_share_then_key(
    tmp_path: Path,
) -> None:
    # (company, service, confidence, finding_type, score); score None means unscored.
    rows = [
        ("a.com", "a1", "Low", "x", 12),  # 12 x 0.4 = 4.8
        ("b.com", "b1", "High", "x", 4),  # 4.0
        ("c.com", "c1", "High", "x", 12),  # 12.0: its Low service's 3 doesn't drag it down
        ("c.com", "c2", "Low", "y", 3),
        ("d.com", "d1", "High", "x", 7),  # 7.0, High
        ("e.com", "e1", "Medium", "x", 10),  # 7.0, Medium
        ("f.com", "f1", "High", "heartbleed_vulnerable", 6),  # one fault reported twice
        ("f.com", "f1", "High", "CVE-2014-0160", 6),
        ("g.com", "g1", "High", "x", 6),  # two different faults
        ("g.com", "g1", "High", "y", 6),
        ("h.com", "h1", "High", "x", 5),  # 1 of 1 visible services has a finding
        ("i.com", "i1", "High", "x", 5),  # 1 of 2
        ("j.com", "j1", "High", "x", 3),
        ("k.com", "k1", "High", "x", 3),
        ("z.com", "z1", "High", "x", None),
    ]
    con = duckdb.connect()
    con.execute(
        "CREATE TABLE r (company_key VARCHAR, service_key VARCHAR, confidence VARCHAR, "
        "finding_type VARCHAR, score INTEGER)"
    )
    con.executemany("INSERT INTO r VALUES (?, ?, ?, ?, ?)", rows)
    con.execute("INSERT INTO r VALUES ('i.com', 'i2', 'High', NULL, NULL)")
    for table, query in {
        "attribution": "SELECT DISTINCT service_key, company_key, 'domain' AS company_kind, "
        "company_key AS company_name, confidence, 'scan_hostname' AS route, "
        "'test' AS attributor FROM r",
        "finding": "SELECT service_key, finding_type, 'exposure' AS kind, NULL AS evidence_text, "
        "score, 'test' AS finding_scorer, 'm' AS answers_model FROM r "
        "WHERE finding_type IS NOT NULL",
    }.items():
        (tmp_path / table).mkdir()
        con.execute(f"COPY ({query}) TO '{tmp_path / table / 'data.parquet'}' (FORMAT PARQUET)")

    worst = company.worst_x_confidence_v1(con, tmp_path).order("rank NULLS LAST")
    assert [r[0] for r in worst.select("company_key").fetchall()] == [
        "c.com", "d.com", "e.com", "g.com", "f.com", "h.com", "i.com",
        "a.com", "b.com", "j.com", "k.com", "z.com",
    ]  # fmt: skip
    assert worst.filter("company_key = 'z.com'").select("rank").fetchall() == [(None,)]

    summed = company.sum_x_confidence_v1(con, tmp_path).filter("company_key = 'f.com'")
    assert summed.select("company_score").fetchall() == [(12,)]


FTP_ANONYMOUS = next(r for r in SIGNAL_RECORDS if '"d27145be' in r)
SMBGHOST = next(r for r in SIGNAL_RECORDS if '"64f41291' in r)


def scanned_as(line: str, hostname: str, **changes: object) -> str:
    record = json.loads(line)
    record["_shodan"]["options"] = {"hostname": hostname}
    record.update(changes)
    return json.dumps(record)


def gold_rows(root: Path, name: str, columns: str) -> list[tuple[object, ...]]:
    path = root / "data" / "gold" / name / "*" / "*.parquet"
    return duckdb.execute(f"SELECT {columns} FROM read_parquet('{path}') ORDER BY ALL").fetchall()


def test_gold_end_to_end_scores_ranks_and_reruns_cleanly(tmp_path: Path) -> None:
    manifest = run(
        tmp_path,
        [
            scanned_as(RDP, "remote.acmefreight.com"),
            scanned_as(FTP_ANONYMOUS, "files.otherco.com"),
            scanned_as(SMBGHOST, "share.cdnshop.com", tags=["cdn"]),
            scanned_as(
                variant(SMBGHOST, 9, ip_str="176.43.141.149", ip=2955644309), "share.thirdco.com"
            ),
        ],
    )
    asdb = tmp_path / "ref" / "asdb" / "as_of=2026-03"
    asdb.mkdir(parents=True)
    (asdb / "2026-03_categorized_ases.csv").write_text(
        "ASN,Category 1 - Layer 1,Category 1 - Layer 2\nAS0,Service,Other\n"
    )
    kev = tmp_path / "kev.json"
    kev.write_text(json.dumps({"catalogVersion": "t", "vulnerabilities": [{"cveID": "X"}]}))
    settings = Settings(
        data_root=tmp_path / "data",
        ref_root=tmp_path / "ref",
        answers_path=tmp_path / "answers.jsonl",
        kev_path=kev,
    )

    gold.build(manifest, settings)
    assert gold_rows(tmp_path, "finding", "DISTINCT score") == [(None,)]
    assert gold_rows(tmp_path, "company", "DISTINCT rank") == [(None,)]

    settings.answers_path.write_text(
        finding_scores.Answer(
            item_id="rdp_exposed",
            kind="exposure",
            status="answered",
            exploitation="active",
            automatable="yes",
            technical_impact="total",
            model=settings.answers_model,
            prompt_version=settings.prompt_version,
            run_via="claude_code",
            run_date="2026-11-01",
            input_hash="h",
        ).model_dump_json()
        + "\n"
    )
    gold.build(manifest, settings)
    findings = gold_rows(tmp_path, "finding", "finding_type, score")
    assert gold_rows(tmp_path, "finding", "count(*) FILTER (WHERE finding_type = 'CVE-2020-0796')")[
        0
    ] == (1,), "the CVE counts once: on thirdco, never on the CDN-tagged copy"
    assert ("rdp_exposed", 12) in findings
    assert ("ftp_anonymous", None) in findings
    assert gold_rows(tmp_path, "company", "company_scorer, company_key, rank") == [
        ("sum_x_confidence_v1", "acmefreight.com", 1),
        ("sum_x_confidence_v1", "otherco.com", None),
        ("sum_x_confidence_v1", "thirdco.com", None),
        ("worst_x_confidence_v1", "acmefreight.com", 1),
        ("worst_x_confidence_v1", "otherco.com", None),
        ("worst_x_confidence_v1", "thirdco.com", None),
    ]
    unlabelled = "attributor IS NULL OR finding_scorer IS NULL OR answers_model IS NULL"
    assert gold_rows(tmp_path, "company", f"count(*) FILTER (WHERE {unlabelled})") == [(0,)]

    on_company = (
        "SELECT f.service_key, f.finding_type FROM read_parquet('{g}/finding/*/*.parquet') f "
        "JOIN read_parquet('{g}/attribution/*/*.parquet') a USING (service_key) "
        "WHERE a.company_key IS NOT NULL ORDER BY ALL"
    ).format(g=tmp_path / "data" / "gold")
    assert gold_rows(tmp_path, "company_finding", "service_key, finding_type") == (
        duckdb.execute(on_company).fetchall()
    )
    assert gold_rows(
        tmp_path, "company", "DISTINCT company_key, confidence, confidence_route, top_finding_type"
    )[0] == ("acmefreight.com", "High", "scan_hostname", "rdp_exposed")
    assert gold_rows(
        tmp_path, "company_finding", "finding_type, cve_summary IS NOT NULL, answer_status"
    ) == [
        ("CVE-2020-0796", True, None),
        ("ftp_anonymous", False, None),
        ("rdp_exposed", False, "answered"),
        ("rdp_standard_security", False, None),
    ]

    tables = ("attribution", "finding", "company", "company_finding")
    counts = {t: gold_rows(tmp_path, t, "count(*)") for t in tables}
    gold.build(manifest, settings)
    assert {t: gold_rows(tmp_path, t, "count(*)") for t in counts} == counts
