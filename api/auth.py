import threading
import time
from collections import defaultdict, deque
from typing import Literal

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel

from api.settings import ApiSettings

router = APIRouter(prefix="/api/auth")
hasher = PasswordHasher()
# Verified against when the username is unknown, so a wrong name costs the same time as a
# wrong password and the reply's timing doesn't reveal which usernames exist.
UNKNOWN_USER_HASH = hasher.hash("no such user")


class Login(BaseModel):
    username: str
    password: str


class Me(BaseModel):
    username: str


class Throttle:
    """Failed logins per client IP, in memory. Correct only with one server process, which is
    why the app runs as a single worker on a single machine."""

    def __init__(self) -> None:
        self.failures: defaultdict[str, deque[float]] = defaultdict(deque)
        self.lock = threading.Lock()

    def refused(self, ip: str, limit: int, window_seconds: float) -> bool:
        with self.lock:
            recent = self.failures[ip]
            while recent and recent[0] < time.monotonic() - window_seconds:
                recent.popleft()
            return len(recent) >= limit

    def failed(self, ip: str) -> None:
        with self.lock:
            self.failures[ip].append(time.monotonic())

    def succeeded(self, ip: str) -> None:
        with self.lock:
            self.failures.pop(ip, None)


def client_ip(request: Request) -> str:
    # Behind Fly's proxy every socket comes from the proxy, so keying on it would let one
    # person's failed logins lock everyone out. Fly sets Fly-Client-IP to the real address.
    forwarded = request.headers.get("fly-client-ip")
    if forwarded:
        return forwarded
    return request.client.host if request.client else "unknown"


def current_user(request: Request) -> str:
    settings: ApiSettings = request.app.state.settings
    username = request.session.get("user")
    # Checked against the configured users too, so removing someone from APP_USERS ends
    # their session at the next request instead of when the cookie expires.
    if not isinstance(username, str) or username not in settings.app_users:
        raise HTTPException(status_code=401, detail="not logged in")
    return username


def attempt_login(
    request: Request, username: str, password: str
) -> Literal["ok", "wrong", "throttled"]:
    """Checks the throttle and the password, and starts the session on success."""
    settings: ApiSettings = request.app.state.settings
    throttle: Throttle = request.app.state.throttle
    ip = client_ip(request)
    window = settings.login_window_minutes * 60
    if throttle.refused(ip, settings.login_max_failures, window):
        return "throttled"
    known = username in settings.app_users
    try:
        hasher.verify(settings.app_users.get(username, UNKNOWN_USER_HASH), password)
        valid = known
    except VerificationError:
        valid = False
    if not valid:
        throttle.failed(ip)
        return "wrong"
    throttle.succeeded(ip)
    request.session["user"] = username
    return "ok"


@router.post("/login", status_code=204)
def login(body: Login, request: Request) -> Response:
    outcome = attempt_login(request, body.username, body.password)
    if outcome == "throttled":
        raise HTTPException(status_code=429, detail="too many failed logins; try again later")
    if outcome == "wrong":
        raise HTTPException(status_code=401, detail="wrong username or password")
    return Response(status_code=204)


@router.post("/logout", status_code=204)
def logout(request: Request) -> Response:
    request.session.clear()
    return Response(status_code=204)


me_router = APIRouter(prefix="/auth")


@me_router.get("/me")
def me(request: Request) -> Me:
    return Me(username=current_user(request))
