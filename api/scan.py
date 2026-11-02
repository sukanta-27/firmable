import json
from datetime import datetime

from fastapi import APIRouter, Request
from pydantic import BaseModel

from api.settings import ApiSettings

router = APIRouter()


class ScanInfo(BaseModel):
    file_id: str
    records: int | None
    received_at: datetime
    published_at: datetime
    gold_code_version: str | None
    attributor: str
    finding_scorer: str
    answers_model: str
    prompt_version: str
    company_scorers: list[str]
    asdb_as_of: str
    kev_catalog_version: str


@router.get("/scan")
def scan(request: Request) -> ScanInfo:
    """Which scan and which strategies the pages show, read from the published folder."""
    settings: ApiSettings = request.app.state.settings
    root = settings.publish_root
    manifest = json.loads((root / "manifest.json").read_text())
    published = json.loads((root / "publish.json").read_text())
    refs = json.loads((root / "gold_run.json").read_text())["refs"]
    return ScanInfo(
        file_id=manifest["file_id"],
        records=manifest.get("records"),
        received_at=manifest["received_at"],
        published_at=published["published_at"],
        gold_code_version=manifest.get("gold_code_version"),
        attributor=refs["attributor"],
        finding_scorer=refs["finding_scorer"],
        answers_model=refs["answers_model"],
        prompt_version=refs["prompt_version"],
        company_scorers=refs["company_scorers"].split(","),
        asdb_as_of=refs["asdb_as_of"],
        kev_catalog_version=refs["kev_catalog_version"],
    )
