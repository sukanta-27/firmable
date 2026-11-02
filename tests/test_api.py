import json
import re
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from api.auth import hasher
from api.main import create_app
from api.settings import ApiSettings
from pipeline import gold
from pipeline.meta import read_manifest
from pipeline.publish import publish
from pipeline.ref.finding_scores import Answer
from pipeline.settings import Settings
from tests.helpers import run, variant

RECORDS = (Path(__file__).parent / "fixtures" / "signal_records.jsonl").read_text().splitlines()
PASSWORD = "correct horse"


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
def published(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A tiny scan through gold and publish, with one company per case the API must handle."""
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
        ],
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
    )
    log = gold.build(manifest, settings)
    assert not [c for c in log.checks if c.blocking and not c.passed]
    final = read_manifest(settings.data_root, manifest.file_id)
    assert final is not None
    return publish(settings, final)


@pytest.fixture
def client(published: Path) -> Iterator[TestClient]:
    settings = ApiSettings(
        publish_root=published,
        app_users={"rep": hasher.hash(PASSWORD)},
        session_secret=SecretStr("test secret"),
        cookie_secure=False,
        login_max_failures=3,
    )
    with TestClient(create_app(settings)) as c:
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
