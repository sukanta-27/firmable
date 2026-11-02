from pathlib import Path
from urllib.parse import urlencode, urlsplit

from fastapi import Request
from fastapi.templating import Jinja2Templates

from api import scan
from api.settings import ApiSettings

templates = Jinja2Templates(directory=Path(__file__).parent.parent / "templates")

# The badge and its explanation per (confidence, route). Low comes only from several domains
# claiming one service, whatever the route, so it has one wording.
BADGES = {
    ("High", "scan_hostname"): (
        "High · from scan hostname",
        "We reached this service through the company's own hostname.",
    ),
    ("High", "server_name"): (
        "High · server names itself",
        "The server told us its company domain itself, in a Windows login or directory reply.",
    ),
    ("Medium", "reverse_dns"): (
        "Medium · from reverse DNS",
        "The address's reverse-DNS name is under the company's domain. Hosting providers often "
        "set these, so it may be a server they run for the company. Check before calling.",
    ),
    ("Medium", "network"): (
        "Medium · their own network",
        "The address block is registered to the organisation itself. We didn't see a domain name.",
    ),
}
LOW_BADGE = (
    "Low · several domains share this service",
    "Several different domains point at this service, so it may be shared hosting. Make sure "
    "you're calling the right one.",
)

UNSCORED_LINE = "We found a problem here that we haven't assessed yet."
BREAK_IN_TYPES = ("ransom_note", "tag_compromised")


def badge(confidence: str, route: str | None) -> tuple[str, str]:
    if confidence == "Low":
        return LOW_BADGE
    return BADGES.get((confidence, route or ""), (confidence, ""))


templates.env.globals.update(badge=badge, UNSCORED_LINE=UNSCORED_LINE)
templates.env.filters["num"] = lambda n: f"{n:,}"


class LoginRequired(Exception):
    """A page asked for without a valid session; the handler sends the browser to log in."""


def page_user(request: Request) -> str:
    settings: ApiSettings = request.app.state.settings
    username = request.session.get("user")
    if not isinstance(username, str) or username not in settings.app_users:
        raise LoginRequired
    return username


def safe_next(target: str | None) -> str:
    """Only a path on this site: `//host` and `/\\host` are read by browsers as another host."""
    if not target or not target.startswith("/") or target.startswith("//") or "\\" in target:
        return "/"
    return target


def login_url(request: Request) -> str:
    # An HTMX request's own URL is the fragment it asked for; the page the person is on is in
    # HX-Current-URL, and that's where they should land after logging in.
    current = request.headers.get("hx-current-url")
    if current:
        parts = urlsplit(current)
        here = parts.path + (f"?{parts.query}" if parts.query else "")
    else:
        here = request.url.path + (f"?{request.url.query}" if request.url.query else "")
    query = {"next": safe_next(here)}
    # A first visit carries no cookie; saying "you were logged out" to it would be wrong.
    if current or "session" in request.cookies:
        query["reason"] = "expired"
    return "/login?" + urlencode(query)


def page_context(request: Request, user: str) -> dict[str, object]:
    return {"user": user, "scan": scan.scan(request)}
