import csv
import gzip
import io
import json
import re
from collections.abc import Iterator
from pathlib import Path

import duckdb
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from api.auth import hasher
from api.main import create_app
from api.settings import ApiSettings
from pipeline import eval, gold, llm_usage
from pipeline.meta import Manifest, read_manifest, report_stamp, write_json
from pipeline.publish import publish
from pipeline.ref.finding_scores import Answer
from pipeline.settings import Settings
from tests.helpers import run, variant

RECORDS = (Path(__file__).parent / "fixtures" / "signal_records.jsonl").read_text().splitlines()
PASSWORD = "correct horse"
FORMULA = '=HYPERLINK("http://evil.example","Click")'


def record(shodan_id: str, hostname: str | None = None, **changes: object) -> str:
    return scanned(next(r for r in RECORDS if f'"{shodan_id}' in r), hostname, **changes)


def scanned(line: str, hostname: str | None, **changes: object) -> str:
    parsed = json.loads(line)
    if hostname:
        parsed["_shodan"]["options"] = {"hostname": hostname}
    parsed.update(changes)
    return json.dumps(parsed)


def answer(item_id: str, exploitation: str, automatable: str, impact: str) -> str:
    return (
        Answer(
            item_id=item_id,
            kind="exposure",
            status="answered",
            exploitation=exploitation,
            automatable=automatable,
            technical_impact=impact,
            salesperson_line=f"line for {item_id}",
            model="claude-opus-5-5",
            prompt_version="v1",
            run_via="claude_code",
            run_date="2026-11-01",
            input_hash="h",
        ).model_dump_json()
        + "\n"
    )


@pytest.fixture(scope="module")
def scan(tmp_path_factory: pytest.TempPathFactory) -> tuple[Settings, Manifest]:
    """A tiny scan through gold, with one company per case the API must handle."""
    root = tmp_path_factory.mktemp("scan")
    smbghost = next(r for r in RECORDS if '"64f41291' in r)
    FTP = next(r for r in RECORDS if '"d27145be' in r)
    manifest = run(
        root,
        [
            record("51215953", "remote.acmefreight.com"),  # High, scored
            record("d27145be", "files.otherco.com"),  # High, lower score
            record("2aec7dfa", "db.breached.com", tags=["database", "compromised"]),
            record("889b057f"),  # reverse DNS only: Medium
            scanned(
                variant(FTP, 10, ip_str="173.254.68.66", ip=2919121986), "ftp.breached.com"
            ),  # breached's second service: first under the sum scorer, not the worst
            scanned(
                variant(smbghost, 9, ip_str="176.43.141.149", ip=2955644309), "share.thirdco.com"
            ),  # an unscored CVE only: no rank
            variant(
                next(r for r in RECORDS if '"51215953' in r),
                11,
                ip_str="115.243.88.183",
                ip=1945327799,
                asn="AS64500",
                org=FORMULA,
            ),  # a company-owned network, named after its scan `org` string
        ],
        networks=[("AS0", ["NSP"]), ("AS64500", ["Enterprise"])],
    )
    asdb = root / "ref" / "asdb" / "as_of=2026-03"
    asdb.mkdir(parents=True)
    (asdb / "2026-03_categorized_ases.csv").write_text(
        "ASN,Category 1 - Layer 1,Category 1 - Layer 2\nAS0,Service,Other\n"
    )
    kev = root / "kev.json"
    kev.write_text(json.dumps({"catalogVersion": "t", "vulnerabilities": [{"cveID": "X"}]}))
    answers = root / "answers.jsonl"
    answers.write_text(
        answer("rdp_exposed", "active", "yes", "total")
        + answer("ftp_anonymous", "poc", "no", "partial")
        + answer("tag_compromised", "active", "yes", "total")
        + answer("mysql_exposed", "poc", "no", "partial")
    )
    settings = Settings(
        data_root=root / "data",
        ref_root=root / "ref",
        answers_path=answers,
        kev_path=kev,
        publish_root=root / "publish",
        # Never the repo's own reports: those describe the real scan.
        eval_root=root / "eval",
        llm_usage_path=root / "calls.jsonl",
        llm_usage_report=root / "llm_usage.json",
    )
    log = gold.build(manifest, settings)
    assert not [c for c in log.checks if c.blocking and not c.passed]
    final = read_manifest(settings.data_root, manifest.file_id)
    assert final is not None
    return settings, final


@pytest.fixture(scope="module")
def published(scan: tuple[Settings, Manifest]) -> Path:
    return publish(*scan)


def app_on(publish_root: Path) -> TestClient:
    settings = ApiSettings(
        publish_root=publish_root,
        app_users={"rep": hasher.hash(PASSWORD)},
        session_secret=SecretStr("test secret"),
        cookie_secure=False,
        login_max_failures=3,
    )
    return TestClient(create_app(settings))


@pytest.fixture
def client(published: Path) -> Iterator[TestClient]:
    with app_on(published) as c:
        yield c


def log_in(client: TestClient) -> None:
    response = client.post("/api/auth/login", json={"username": "rep", "password": PASSWORD})
    assert response.status_code == 204


PUBLIC = {"/api/health", "/api/auth/login", "/api/auth/logout"}


def test_every_data_route_refuses_a_request_without_a_session(client: TestClient) -> None:
    # The OpenAPI schema lists every route, however deeply its router is included, so a new
    # route that misses the login router fails here.
    paths = client.get("/openapi.json").json()["paths"]
    protected = [(m, p) for p, ops in paths.items() if p not in PUBLIC for m in ops]
    assert protected, "the walk found no protected route, so it would pass vacuously"
    for method, path in protected:
        concrete = re.sub(r"\{[^}]+\}", "x", path)
        assert client.request(method, concrete).status_code == 401, f"{method} {path}"


def test_login_reveals_nothing_about_which_usernames_exist(client: TestClient) -> None:
    wrong_password = client.post("/api/auth/login", json={"username": "rep", "password": "x"})
    unknown_user = client.post("/api/auth/login", json={"username": "nobody", "password": "x"})
    assert wrong_password.status_code == unknown_user.status_code == 401
    assert wrong_password.json() == unknown_user.json()


def test_a_tampered_session_cookie_is_refused(client: TestClient) -> None:
    log_in(client)
    assert client.get("/api/auth/me").json() == {"username": "rep"}
    cookie = client.cookies["session"]
    client.cookies.clear()
    client.cookies["session"] = cookie[:-2] + ("A" if cookie[-2] != "A" else "B") + cookie[-1]
    assert client.get("/api/auth/me").status_code == 401


def test_failed_logins_lock_out_one_client_ip_not_everyone(client: TestClient) -> None:
    attacker, colleague = {"fly-client-ip": "1.1.1.1"}, {"fly-client-ip": "2.2.2.2"}
    right = {"username": "rep", "password": PASSWORD}
    for _ in range(3):
        bad = client.post("/api/auth/login", json={**right, "password": "x"}, headers=attacker)
        assert bad.status_code == 401
    assert client.post("/api/auth/login", json=right, headers=attacker).status_code == 429
    assert client.post("/api/auth/login", json=right, headers=colleague).status_code == 204


def companies(client: TestClient, **params: str | int) -> list[str]:
    response = client.get("/api/companies", params={"limit": 200, **params})
    assert response.status_code == 200, response.text
    return [c["company_key"] for c in response.json()["items"]]


def test_list_order_is_gold_rank_under_each_scorer(client: TestClient, published: Path) -> None:
    log_in(client)
    orders = {}
    for scorer in ("worst_x_confidence_v1", "sum_x_confidence_v1"):
        gold_order = duckdb.execute(
            f"SELECT company_key FROM '{published}/company.parquet' "
            "WHERE company_scorer = ? ORDER BY rank NULLS LAST, company_key",
            [scorer],
        ).fetchall()
        orders[scorer] = companies(client, scorer=scorer)
        assert orders[scorer] == [k for (k,) in gold_order]
    assert orders["worst_x_confidence_v1"] != orders["sum_x_confidence_v1"]
    last = client.get("/api/companies", params={"limit": 200}).json()["items"][-1]
    assert (last["company_key"], last["rank"]) == ("thirdco.com", None)


def test_each_filter_keeps_only_matching_companies(client: TestClient) -> None:
    log_in(client)
    everyone = companies(client)
    high = client.get("/api/companies", params={"confidence": "High", "limit": 200}).json()
    assert {c["confidence"] for c in high["items"]} == {"High"}
    assert len(high["items"]) < len(everyone), "the fixture needs a non-High company"
    assert set(companies(client, finding_type="ftp_anonymous")) == {"otherco.com", "breached.com"}
    assert companies(client, already_breached="true") == ["breached.com"]


def test_csv_holds_the_list_in_the_same_order(client: TestClient) -> None:
    log_in(client)
    params = {"scorer": "sum_x_confidence_v1", "attacked_in_the_wild": "true"}
    response = client.get("/api/companies.csv", params=params)
    assert response.status_code == 200
    rows = list(csv.DictReader(io.StringIO(response.text)))
    assert [r["company_key"] for r in rows] == companies(client, **params)
    assert {r["scorer"] for r in rows} == {"sum_x_confidence_v1"}


def test_csv_cells_cannot_run_as_spreadsheet_formulas(client: TestClient) -> None:
    log_in(client)
    rows = list(csv.DictReader(io.StringIO(client.get("/api/companies.csv").text)))
    names = {r["company_key"]: r["company_name"] for r in rows}
    assert names["AS64500"] == "'" + FORMULA


def test_company_page_shows_every_finding_gold_has_for_the_company(
    client: TestClient, published: Path
) -> None:
    log_in(client)
    keys = duckdb.execute(
        f"SELECT DISTINCT company_key FROM '{published}/company.parquet' ORDER BY 1"
    ).fetchall()
    for (key,) in keys:
        page = client.get(f"/api/companies/{key}")
        assert page.status_code == 200, key
        shown = sorted(
            (f["finding_type"], s["ip"], s["port"])
            for f in page.json()["findings"]
            for s in f["services"]
        )
        in_gold = duckdb.execute(
            f"SELECT finding_type, ip, port FROM '{published}/company_finding.parquet' "
            "WHERE company_key = ? ORDER BY ALL",
            [key],
        ).fetchall()
        assert shown == [tuple(r) for r in in_gold], key
    unscored = client.get("/api/companies/thirdco.com").json()
    assert unscored["rank"] is None
    assert [f["score"] for f in unscored["findings"]] == [None]
    assert client.get("/api/companies/nobody.example").status_code == 404


def test_how_we_know_marks_a_report_never_run_as_not_run(client: TestClient) -> None:
    log_in(client)
    page = client.get("/api/how-we-know")
    assert page.status_code == 200, page.text
    body = page.json()
    sections = ("attribution_cases", "finding_scores", "ranking", "llm_usage")
    assert {body[s]["status"] for s in sections} == {"not_run"}
    assert body["attribution_coverage"]["metrics"]


def test_how_we_know_serves_each_report_as_the_pipeline_wrote_it(
    scan: tuple[Settings, Manifest], tmp_path: Path
) -> None:
    base, manifest = scan
    epss = tmp_path / "epss.csv.gz"
    with gzip.open(epss, "wt") as f:
        f.write("#model_version:t,score_date:t\ncve,epss,percentile\nX,0.5,0.5\n")
    victims = tmp_path / "ref" / "ransomware_live" / "as_of=2026-10-31" / "victims_2026-10.json"
    victims.parent.mkdir(parents=True)
    victims.write_text(json.dumps({"victims": [{"website": "https://www.breached.com/"}]}))
    settings = base.model_copy(
        update={
            "ref_root": tmp_path / "ref",
            "epss_path": epss,
            "eval_root": tmp_path / "eval",
            "llm_usage_path": tmp_path / "calls.jsonl",
            "llm_usage_report": tmp_path / "llm_usage.json",
            "publish_root": tmp_path / "publish",
        }
    )
    con = duckdb.connect()
    eval.load_cases(con, settings.attribution_cases)
    write_json(
        settings.eval_root / "attribution.json",
        eval.score_attribution(con, settings.attributor, report_stamp("test")),
    )
    write_json(settings.eval_root / "finding_scores_check.json", eval.check_answers(settings))
    write_json(
        eval.ranking_report_path(settings.data_root, manifest.file_id),
        eval.compare_rankings(settings, manifest.file_id),
    )
    llm_usage.record(
        settings,
        use_case="u",
        model="m",
        kind="count_tokens",
        outcome="ok",
        request_id=None,
        usage=None,
        input_tokens=5,
        seconds=1.0,
        prompt_version="v1",
        input_hash="h",
        items=1,
    )
    llm_usage.summarise(settings)
    publish(settings, manifest)

    with app_on(settings.publish_root) as client:
        log_in(client)
        body = client.get("/api/how-we-know").json()
    for section, name in (
        ("attribution_cases", "attribution"),
        ("finding_scores", "finding_scores_check"),
        ("ranking", "ranking"),
        ("llm_usage", "llm_usage"),
    ):
        written = json.loads((settings.publish_root / "eval" / f"{name}.json").read_text())
        assert (body[section]["status"], body[section]["report"]) == ("ok", written), section
    # The fixture's breached.com is a victim, so the match above was not compared empty.
    assert [c["company_key"] for c in body["ranking"]["report"]["victims"]["companies"]] == [
        "breached.com"
    ]
