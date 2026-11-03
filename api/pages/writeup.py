from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter()

# The same file is published as a claude.ai artifact, which supplies the document shell
# itself and wants the file without one, so the shell is added here instead.
SHELL = (
    '<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
    '<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">\n'
    '<meta name="robots" content="noindex, nofollow">\n'
)
PAGE = SHELL + (Path(__file__).parent.parent / "writeup.html").read_text()


@router.get("/writeup", response_class=HTMLResponse)
def writeup() -> HTMLResponse:
    return HTMLResponse(PAGE)
