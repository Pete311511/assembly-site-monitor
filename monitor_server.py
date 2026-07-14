from __future__ import annotations

import base64
import csv
import hashlib
import html
import json
import os
import re
import secrets
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


APP_NAME = "Assembly Site Monitor"
HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8787"))
CHECK_INTERVAL_SECONDS = int(os.environ.get("CHECK_INTERVAL_SECONDS", "60"))
REQUEST_TIMEOUT_SECONDS = 35
SLOW_SECONDS = 8
VERY_SLOW_SECONDS = 20
MONITOR_USERNAME = os.environ.get("MONITOR_USERNAME", "assembly")
MONITOR_PASSWORD = os.environ.get("MONITOR_PASSWORD", "")
DATA_DIR = Path(os.environ.get("MONITOR_DATA_DIR", Path(__file__).resolve().parent / "monitor-data"))
HISTORY_FILE = DATA_DIR / "history.jsonl"
INCIDENT_FILE = DATA_DIR / "incidents.jsonl"
STATE_FILE = DATA_DIR / "state.json"


CHECKS = [
    {
        "id": "home",
        "label": "Homepage",
        "url": "https://assemblyfestival.com/",
        "kind": "page",
        "expect_title": "Home | Assembly Festival",
        "critical": True,
    },
    {
        "id": "whats-on",
        "label": "What's On",
        "url": "https://assemblyfestival.com/whats-on",
        "kind": "page",
        "expect_title": "What's On | Assembly Festival | Edinburgh Fringe 2026",
        "critical": True,
    },
    {
        "id": "venues",
        "label": "Venues",
        "url": "https://assemblyfestival.com/venues",
        "kind": "page",
        "expect_title": "Our Venues | Assembly Festival",
        "critical": True,
    },
    {
        "id": "access",
        "label": "Access",
        "url": "https://assemblyfestival.com/access",
        "kind": "page",
        "expect_title": "Access | Assembly Festival",
        "critical": False,
    },
    {
        "id": "faqs",
        "label": "FAQs",
        "url": "https://assemblyfestival.com/faqs",
        "kind": "page",
        "expect_title": "FAQs | Assembly Festival",
        "critical": False,
    },
    {
        "id": "api-home",
        "label": "API: home page",
        "url": "https://assemblyfestival.com/api/pages/home",
        "kind": "api",
        "critical": True,
    },
    {
        "id": "api-whats-on",
        "label": "API: what's on page",
        "url": "https://assemblyfestival.com/api/pages/whats-on",
        "kind": "api",
        "critical": True,
    },
    {
        "id": "api-alerts",
        "label": "API: alerts",
        "url": "https://assemblyfestival.com/api/alerts",
        "kind": "api",
        "critical": False,
    },
    {
        "id": "api-sponsors",
        "label": "API: sponsors",
        "url": "https://assemblyfestival.com/api/sponsors",
        "kind": "api",
        "critical": False,
    },
    {
        "id": "api-partners",
        "label": "API: partners",
        "url": "https://assemblyfestival.com/api/partners",
        "kind": "api",
        "critical": False,
    },
    {
        "id": "shows-search",
        "label": "Shows loading",
        "url": "https://assemblyfestival.com/api/projects/search?limit=12&page=1",
        "kind": "projects-search",
        "critical": True,
    },
    {
        "id": "ticket-availability",
        "label": "Ticket availability",
        "url": "https://assemblyfestival.com/api/projects/search?limit=8&page=1",
        "kind": "ticket-availability",
        "critical": True,
    },
    {
        "id": "cms-health",
        "label": "CMS health",
        "url": "https://assemblyfestival.pazaz.studio/server/health",
        "kind": "cms",
        "critical": True,
    },
]


BAD_MARKERS = [
    (re.compile(r"<p>\s*Error\s*</p>", re.I), "Visible page error"),
    (re.compile(r"NuxtError", re.I), "Nuxt error in page state"),
    (re.compile(r"intermediate value\) is not iterable", re.I), "Nuxt iterable server error"),
    (re.compile(r"Bad Gateway|origin_bad_gateway|cloudflare_error", re.I), "Bad gateway / Cloudflare origin error"),
    (re.compile(r"Internal Server Error", re.I), "Internal server error"),
]


@dataclass
class Result:
    id: str
    label: str
    url: str
    kind: str
    critical: bool
    status: str
    http_status: int | None
    response_ms: int | None
    bytes: int
    title: str
    message: str
    checked_at: str


class Monitor:
    def __init__(self) -> None:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self.latest: dict[str, Result] = {}
        self.history: list[dict[str, Any]] = []
        self.incidents: list[dict[str, Any]] = []
        self.build: dict[str, Any] = {}
        self.running = True
        self.last_run_started: str | None = None
        self.last_run_finished: str | None = None
        self.load_state()

    def load_state(self) -> None:
        if STATE_FILE.exists():
            try:
                self.build = json.loads(STATE_FILE.read_text(encoding="utf-8")).get("build", {})
            except Exception:
                self.build = {}
        if INCIDENT_FILE.exists():
            lines = INCIDENT_FILE.read_text(encoding="utf-8", errors="ignore").splitlines()[-200:]
            self.incidents = [json.loads(line) for line in lines if line.strip()]
        if HISTORY_FILE.exists():
            lines = HISTORY_FILE.read_text(encoding="utf-8", errors="ignore").splitlines()[-500:]
            self.history = [json.loads(line) for line in lines if line.strip()]

    def save_state(self) -> None:
        STATE_FILE.write_text(json.dumps({"build": self.build}, indent=2), encoding="utf-8")

    def append_jsonl(self, path: Path, item: dict[str, Any]) -> None:
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(item, ensure_ascii=False) + "\n")

    def run_forever(self) -> None:
        while self.running:
            self.run_once()
            time.sleep(CHECK_INTERVAL_SECONDS)

    def run_once(self) -> None:
        started = utc_now()
        self.last_run_started = started
        results = [check_endpoint(check) for check in CHECKS]
        build = detect_build_fingerprint(results)
        finished = utc_now()

        with self.lock:
            old_status = {key: value.status for key, value in self.latest.items()}
            self.latest = {result.id: result for result in results}
            self.last_run_finished = finished

            summary = {
                "checked_at": finished,
                "overall": overall_status(results),
                "results": [asdict(result) for result in results],
                "build": build,
            }
            self.history.append(summary)
            self.history = self.history[-500:]
            self.append_jsonl(HISTORY_FILE, summary)

            for result in results:
                previous = old_status.get(result.id)
                if result.status in {"down", "broken"} and previous != result.status:
                    self.record_incident("site-problem", result.label, result.message, result)
                elif result.status == "slow" and previous not in {"slow", "down", "broken"}:
                    self.record_incident("slow-response", result.label, result.message, result)
                elif previous in {"down", "broken", "slow"} and result.status == "ok":
                    self.record_incident("recovered", result.label, "Recovered", result)

            if build.get("fingerprint") and build.get("fingerprint") != self.build.get("fingerprint"):
                message = "Frontend asset fingerprint changed"
                if self.build.get("fingerprint"):
                    message = "Possible deploy detected: frontend asset fingerprint changed"
                self.record_incident("deploy-change", "Frontend build", message, None, extra=build)
                self.build = build
                self.save_state()

    def record_incident(
        self,
        event_type: str,
        label: str,
        message: str,
        result: Result | None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        item = {
            "time": utc_now(),
            "type": event_type,
            "label": label,
            "message": message,
            "status": result.status if result else None,
            "http_status": result.http_status if result else None,
            "response_ms": result.response_ms if result else None,
            "url": result.url if result else None,
            "extra": extra or {},
        }
        self.incidents.append(item)
        self.incidents = self.incidents[-200:]
        self.append_jsonl(INCIDENT_FILE, item)

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            results = [asdict(result) for result in self.latest.values()]
            return {
                "app": APP_NAME,
                "now": utc_now(),
                "interval_seconds": CHECK_INTERVAL_SECONDS,
                "last_run_started": self.last_run_started,
                "last_run_finished": self.last_run_finished,
                "overall": overall_status(list(self.latest.values())),
                "results": results,
                "history": self.history[-120:],
                "incidents": self.incidents[-80:],
                "build": self.build,
            }


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def fetch(url: str) -> tuple[int | None, bytes, dict[str, str], str | None, int]:
    start = time.perf_counter()
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Assembly Festival Monitor/1.0",
            "Accept": "application/json,text/html,*/*",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            body = response.read()
            elapsed_ms = int((time.perf_counter() - start) * 1000)
            return response.status, body, dict(response.headers.items()), None, elapsed_ms
    except urllib.error.HTTPError as exc:
        body = exc.read() if exc.fp else b""
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        return exc.code, body, dict(exc.headers.items()), None, elapsed_ms
    except (urllib.error.URLError, TimeoutError, socket.timeout) as exc:
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        return None, b"", {}, str(exc), elapsed_ms


def check_endpoint(check: dict[str, Any]) -> Result:
    if check["kind"] == "projects-search":
        return check_projects_search(check)
    if check["kind"] == "ticket-availability":
        return check_ticket_availability(check)

    status_code, body, _headers, error, elapsed_ms = fetch(check["url"])
    text = body[:600000].decode("utf-8", errors="ignore")
    title = extract_title(text)
    status = "ok"
    message = "OK"

    if error:
        status = "down"
        message = f"Request failed: {error}"
    elif status_code is None:
        status = "down"
        message = "No HTTP response"
    elif status_code >= 500:
        status = "down"
        message = f"HTTP {status_code}"
    elif status_code >= 400:
        status = "broken"
        message = f"HTTP {status_code}"

    if status == "ok":
        for pattern, marker_message in BAD_MARKERS:
            if pattern.search(text):
                status = "broken"
                message = marker_message
                break

    if status == "ok" and check["kind"] == "api":
        try:
            parsed = json.loads(text) if text.strip() else None
            if isinstance(parsed, dict) and parsed.get("error"):
                status = "broken"
                message = parsed.get("message") or parsed.get("statusMessage") or "API returned an error"
        except json.JSONDecodeError:
            status = "broken"
            message = "API did not return valid JSON"

    if status == "ok" and check["kind"] == "cms":
        try:
            parsed = json.loads(text)
            cms_status = parsed.get("status")
            if cms_status and cms_status != "ok":
                status = "warn"
                message = f"CMS health is {cms_status}"
        except json.JSONDecodeError:
            status = "broken"
            message = "CMS health did not return valid JSON"

    expected_title = check.get("expect_title")
    if status == "ok" and expected_title and title and html.unescape(title).strip() != expected_title:
        status = "warn"
        message = f"Unexpected title: {html.unescape(title).strip()}"

    if status == "ok" and elapsed_ms >= VERY_SLOW_SECONDS * 1000:
        status = "slow"
        message = f"Very slow: {elapsed_ms / 1000:.1f}s"
    elif status == "ok" and elapsed_ms >= SLOW_SECONDS * 1000:
        status = "slow"
        message = f"Slow: {elapsed_ms / 1000:.1f}s"

    return Result(
        id=check["id"],
        label=check["label"],
        url=check["url"],
        kind=check["kind"],
        critical=bool(check.get("critical")),
        status=status,
        http_status=status_code,
        response_ms=elapsed_ms,
        bytes=len(body),
        title=html.unescape(title).strip(),
        message=message,
        checked_at=utc_now(),
    )


def check_projects_search(check: dict[str, Any]) -> Result:
    status_code, body, _headers, error, elapsed_ms = fetch(check["url"])
    text = body.decode("utf-8", errors="ignore")
    status = "ok"
    message = "OK"
    total = 0
    loaded = 0
    with_performances = 0
    with_price = 0

    if error:
        status = "down"
        message = f"Request failed: {error}"
    elif status_code is None:
        status = "down"
        message = "No HTTP response"
    elif status_code >= 500:
        status = "down"
        message = f"HTTP {status_code}"
    elif status_code >= 400:
        status = "broken"
        message = f"HTTP {status_code}"
    else:
        try:
            parsed = json.loads(text)
            rows = parsed.get("data") or []
            meta = parsed.get("meta") or {}
            total = int(meta.get("total") or 0)
            loaded = len(rows)
            with_performances = sum(1 for row in rows if row.get("performances"))
            with_price = sum(1 for row in rows if row.get("price_from"))
            if not isinstance(rows, list):
                status = "broken"
                message = "Show search did not return a list"
            elif total < 1 or loaded < 1:
                status = "broken"
                message = "No shows returned from search"
            elif with_performances < 1:
                status = "broken"
                message = f"{total} shows found but no performances in sample"
            elif with_price < 1:
                status = "warn"
                message = f"{total} shows found, but sample has no price-from values"
            else:
                message = f"{total} shows found; {with_performances}/{loaded} sample shows have performances"
        except Exception as exc:
            status = "broken"
            message = f"Show search JSON failed: {exc}"

    if status == "ok" and elapsed_ms >= VERY_SLOW_SECONDS * 1000:
        status = "slow"
        message = f"Very slow: {elapsed_ms / 1000:.1f}s; {message}"
    elif status == "ok" and elapsed_ms >= SLOW_SECONDS * 1000:
        status = "slow"
        message = f"Slow: {elapsed_ms / 1000:.1f}s; {message}"

    return Result(
        id=check["id"],
        label=check["label"],
        url=check["url"],
        kind=check["kind"],
        critical=bool(check.get("critical")),
        status=status,
        http_status=status_code,
        response_ms=elapsed_ms,
        bytes=len(body),
        title="",
        message=message,
        checked_at=utc_now(),
    )


def check_ticket_availability(check: dict[str, Any]) -> Result:
    status_code, body, _headers, error, elapsed_ms = fetch(check["url"])
    text = body.decode("utf-8", errors="ignore")
    status = "ok"
    message = "OK"
    tested = 0
    ok_count = 0
    first_problem = ""

    if error:
        status = "down"
        message = f"Show search failed before ticket test: {error}"
    elif status_code is None:
        status = "down"
        message = "Show search gave no HTTP response"
    elif status_code >= 500:
        status = "down"
        message = f"Show search HTTP {status_code}"
    elif status_code >= 400:
        status = "broken"
        message = f"Show search HTTP {status_code}"
    else:
        try:
            parsed = json.loads(text)
            rows = parsed.get("data") or []
            candidates = []
            for row in rows:
                performances = row.get("performances") or []
                if row.get("slug") and performances:
                    candidates.append((row.get("name") or row["slug"], row["slug"], performances[0]))
                if len(candidates) >= 3:
                    break

            if not candidates:
                status = "broken"
                message = "No shows with performance IDs found"
            else:
                total_ms = elapsed_ms
                for name, slug, performance_id in candidates:
                    tested += 1
                    availability_url = f"https://assemblyfestival.com/api/projects/{slug}/performances/{performance_id}"
                    perf_status, perf_body, _perf_headers, perf_error, perf_ms = fetch(availability_url)
                    total_ms += perf_ms
                    perf_text = perf_body.decode("utf-8", errors="ignore")
                    if perf_error:
                        first_problem = first_problem or f"{name}: request failed"
                        continue
                    if perf_status != 200:
                        problem = extract_api_error(perf_text) or f"HTTP {perf_status}"
                        first_problem = first_problem or f"{name}: {problem}"
                        continue
                    try:
                        perf_data = json.loads(perf_text)
                    except json.JSONDecodeError:
                        first_problem = first_problem or f"{name}: invalid JSON"
                        continue
                    prices = perf_data.get("prices") if isinstance(perf_data, dict) else None
                    if not prices:
                        first_problem = first_problem or f"{name}: no ticket prices returned"
                        continue
                    available_prices = [
                        price for price in prices
                        if not price.get("hideFullPrice")
                        and price.get("seatPercentageRemaining", 1) != 0
                        and price.get("seats")
                    ]
                    if not available_prices:
                        first_problem = first_problem or f"{name}: prices returned but no available seats"
                        continue
                    ok_count += 1

                elapsed_ms = total_ms
                if ok_count == tested:
                    message = f"{ok_count}/{tested} sample performances returned available ticket prices"
                elif ok_count > 0:
                    status = "warn"
                    message = f"{ok_count}/{tested} sample performances OK; first issue: {first_problem}"
                else:
                    status = "broken"
                    message = f"0/{tested} sample performances returned bookable prices; first issue: {first_problem}"
        except Exception as exc:
            status = "broken"
            message = f"Ticket availability check failed: {exc}"

    if status == "ok" and elapsed_ms >= VERY_SLOW_SECONDS * 1000:
        status = "slow"
        message = f"Very slow: {elapsed_ms / 1000:.1f}s; {message}"
    elif status == "ok" and elapsed_ms >= SLOW_SECONDS * 1000:
        status = "slow"
        message = f"Slow: {elapsed_ms / 1000:.1f}s; {message}"

    return Result(
        id=check["id"],
        label=check["label"],
        url=check["url"],
        kind=check["kind"],
        critical=bool(check.get("critical")),
        status=status,
        http_status=status_code,
        response_ms=elapsed_ms,
        bytes=len(body),
        title="",
        message=message,
        checked_at=utc_now(),
    )


def extract_api_error(text: str) -> str:
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return parsed.get("message") or parsed.get("statusMessage") or ""
    except json.JSONDecodeError:
        pass
    if "Bad Gateway" in text:
        return "Bad Gateway"
    return ""


def extract_title(text: str) -> str:
    match = re.search(r"<title>(.*?)</title>", text, re.I | re.S)
    return re.sub(r"\s+", " ", match.group(1)).strip() if match else ""


def detect_build_fingerprint(results: list[Result]) -> dict[str, Any]:
    home = next((result for result in results if result.id == "home" and result.status in {"ok", "slow", "warn"}), None)
    if not home:
        return {}
    status_code, body, _headers, error, _elapsed = fetch("https://assemblyfestival.com/")
    if error or status_code != 200:
        return {}
    text = body.decode("utf-8", errors="ignore")
    assets = sorted(set(re.findall(r"""(?:src|href)=["']([^"']*/_nuxt/[^"']+)["']""", text)))
    normalized_assets = [urllib.parse.urljoin("https://assemblyfestival.com/", item) for item in assets]
    fingerprint = hashlib.sha256("\n".join(normalized_assets).encode("utf-8")).hexdigest()[:16]
    return {
        "checked_at": utc_now(),
        "fingerprint": fingerprint,
        "asset_count": len(normalized_assets),
        "assets": normalized_assets[:60],
    }


def overall_status(results: list[Result]) -> str:
    if not results:
        return "checking"
    critical = [result for result in results if result.critical]
    if any(result.status in {"down", "broken"} for result in critical):
        return "red"
    if any(result.status in {"down", "broken"} for result in results):
        return "amber"
    if any(result.status in {"slow", "warn"} for result in results):
        return "amber"
    return "green"


monitor = Monitor()


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/healthz":
            self.send_json({"status": "ok", "time": utc_now()})
            return
        if not self.is_authorized():
            self.request_auth()
            return
        if parsed.path in {"/", "/dashboard"}:
            self.send_html(DASHBOARD_HTML)
        elif parsed.path == "/api/status":
            self.send_json(monitor.snapshot())
        elif parsed.path == "/api/check-now":
            threading.Thread(target=monitor.run_once, daemon=True).start()
            self.send_json({"queued": True, "time": utc_now()})
        elif parsed.path == "/incidents.csv":
            self.send_csv()
        else:
            self.send_error(404)

    def log_message(self, format: str, *args: Any) -> None:
        return

    def is_authorized(self) -> bool:
        if not MONITOR_PASSWORD:
            return True
        header = self.headers.get("Authorization", "")
        if not header.startswith("Basic "):
            return False
        try:
            decoded = base64.b64decode(header.split(" ", 1)[1]).decode("utf-8")
            username, password = decoded.split(":", 1)
        except Exception:
            return False
        return secrets.compare_digest(username, MONITOR_USERNAME) and secrets.compare_digest(password, MONITOR_PASSWORD)

    def request_auth(self) -> None:
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="Assembly Site Monitor"')
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"Authentication required")

    def send_html(self, body: str) -> None:
        encoded = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def send_json(self, data: Any) -> None:
        encoded = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def send_csv(self) -> None:
        snapshot = monitor.snapshot()
        rows = snapshot["incidents"]
        output = []
        header = ["time", "type", "label", "message", "status", "http_status", "response_ms", "url"]
        output.append(",".join(header))
        for row in rows:
            output.append(",".join(csv_escape(row.get(key)) for key in header))
        body = "\n".join(output)
        encoded = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header("Content-Disposition", "attachment; filename=assembly-site-incidents.csv")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


def csv_escape(value: Any) -> str:
    if value is None:
        value = ""
    text = str(value)
    if any(char in text for char in [",", '"', "\n"]):
        return '"' + text.replace('"', '""') + '"'
    return text


DASHBOARD_HTML = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Assembly Site Monitor</title>
  <style>
    :root {
      color-scheme: light dark;
      --bg: #101114;
      --panel: #181b20;
      --panel-2: #20242b;
      --text: #f3f5f7;
      --muted: #a9b0bb;
      --border: #343a44;
      --green: #24c45e;
      --amber: #ffb020;
      --red: #ff4d4d;
      --blue: #65a6ff;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: Arial, Helvetica, sans-serif;
      background: var(--bg);
      color: var(--text);
    }
    header {
      padding: 20px;
      border-bottom: 1px solid var(--border);
      display: flex;
      justify-content: space-between;
      gap: 16px;
      align-items: flex-start;
      flex-wrap: wrap;
    }
    h1 { margin: 0 0 6px; font-size: 26px; font-weight: 700; }
    h2 { margin: 0 0 12px; font-size: 16px; }
    p { margin: 0; color: var(--muted); }
    button, a.button {
      border: 1px solid var(--border);
      background: var(--panel-2);
      color: var(--text);
      padding: 10px 12px;
      border-radius: 6px;
      cursor: pointer;
      text-decoration: none;
      display: inline-flex;
      gap: 8px;
      align-items: center;
      font-weight: 700;
    }
    button:hover, a.button:hover { border-color: var(--blue); }
    main {
      padding: 20px;
      display: grid;
      gap: 18px;
    }
    .top {
      display: grid;
      grid-template-columns: minmax(220px, 320px) 1fr;
      gap: 18px;
    }
    .panel {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 16px;
    }
    .status-board {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
      gap: 10px;
    }
    .tile {
      background: var(--panel-2);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 12px;
      min-height: 112px;
      display: grid;
      gap: 8px;
    }
    .tile strong { display: block; font-size: 14px; }
    .meta { color: var(--muted); font-size: 12px; line-height: 1.4; }
    .lamp {
      width: 18px;
      height: 18px;
      border-radius: 50%;
      display: inline-block;
      box-shadow: 0 0 18px currentColor;
    }
    .lamp.ok { color: var(--green); background: var(--green); }
    .lamp.warn, .lamp.slow { color: var(--amber); background: var(--amber); }
    .lamp.down, .lamp.broken { color: var(--red); background: var(--red); }
    .lamp.checking { color: var(--blue); background: var(--blue); }
    .summary {
      display: grid;
      gap: 10px;
      align-content: start;
    }
    .big-light {
      border-radius: 8px;
      padding: 18px;
      background: var(--panel-2);
      border: 1px solid var(--border);
    }
    .big-light .word { font-size: 38px; font-weight: 800; letter-spacing: .03em; }
    .big-light.green { color: var(--green); }
    .big-light.amber { color: var(--amber); }
    .big-light.red { color: var(--red); }
    .big-light.checking { color: var(--blue); }
    .stats {
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 10px;
    }
    .stat {
      background: var(--panel-2);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 12px;
    }
    .stat b { display: block; font-size: 22px; }
    .chart {
      display: flex;
      align-items: end;
      gap: 3px;
      min-height: 92px;
      padding-top: 8px;
    }
    .bar {
      flex: 1;
      min-width: 3px;
      border-radius: 3px 3px 0 0;
      background: var(--green);
      opacity: .9;
    }
    .bar.slow, .bar.warn { background: var(--amber); }
    .bar.down, .bar.broken { background: var(--red); }
    .bar.checking { background: var(--blue); }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }
    th, td {
      text-align: left;
      padding: 9px 8px;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
    }
    th { color: var(--muted); font-weight: 700; }
    .nowrap { white-space: nowrap; }
    .incident-type {
      border-radius: 999px;
      padding: 3px 8px;
      background: var(--panel-2);
      border: 1px solid var(--border);
      font-size: 12px;
      white-space: nowrap;
    }
    .footer-note {
      color: var(--muted);
      font-size: 12px;
      line-height: 1.5;
    }
    @media (max-width: 820px) {
      .top { grid-template-columns: 1fr; }
      .stats { grid-template-columns: 1fr; }
      table { font-size: 12px; }
      th:nth-child(4), td:nth-child(4) { display: none; }
    }
  </style>
</head>
<body>
  <header>
    <div>
      <h1>Assembly Site Monitor</h1>
      <p>Independent checks for pages, APIs, CMS health, slow responses, visible errors and possible deploy changes.</p>
    </div>
    <div>
      <button id="checkNow">Check now</button>
      <a class="button" href="/incidents.csv">Export incidents</a>
    </div>
  </header>
  <main>
    <section class="top">
      <div class="summary">
        <div id="overall" class="big-light checking">
          <div class="word">CHECKING</div>
          <p id="overallText">Waiting for first run...</p>
        </div>
        <div class="stats">
          <div class="stat"><span class="meta">Checks</span><b id="checkCount">0</b></div>
          <div class="stat"><span class="meta">Problems</span><b id="problemCount">0</b></div>
          <div class="stat"><span class="meta">Slowest</span><b id="slowest">-</b></div>
          <div class="stat"><span class="meta">Last check</span><b id="lastCheck">-</b></div>
        </div>
      </div>
      <div class="panel">
        <h2>Status lights</h2>
        <div id="board" class="status-board"></div>
      </div>
    </section>
    <section class="panel">
      <h2>Response time history</h2>
      <div id="chart" class="chart" aria-label="Recent response history"></div>
      <p class="footer-note">Bars show average response time for recent check rounds. Amber means slow or warning. Red means broken/down.</p>
    </section>
    <section class="panel">
      <h2>Incident log</h2>
      <table>
        <thead><tr><th>Time</th><th>Type</th><th>Check</th><th>Message</th><th>HTTP</th><th>Speed</th></tr></thead>
        <tbody id="incidents"><tr><td colspan="6" class="meta">No incidents recorded yet.</td></tr></tbody>
      </table>
    </section>
    <section class="panel">
      <h2>Build fingerprint</h2>
      <p id="buildInfo" class="footer-note">Waiting for build fingerprint...</p>
    </section>
  </main>
  <script>
    const board = document.getElementById('board');
    const overall = document.getElementById('overall');
    const overallText = document.getElementById('overallText');
    const checkCount = document.getElementById('checkCount');
    const problemCount = document.getElementById('problemCount');
    const slowest = document.getElementById('slowest');
    const lastCheck = document.getElementById('lastCheck');
    const incidents = document.getElementById('incidents');
    const chart = document.getElementById('chart');
    const buildInfo = document.getElementById('buildInfo');

    function niceTime(value) {
      if (!value) return '-';
      return new Date(value).toLocaleString('en-GB', { hour12: false });
    }

    function statusWord(value) {
      if (value === 'green') return 'GREEN';
      if (value === 'amber') return 'AMBER';
      if (value === 'red') return 'RED';
      return 'CHECKING';
    }

    function resultClass(status) {
      if (status === 'ok') return 'ok';
      if (status === 'slow' || status === 'warn') return status;
      if (status === 'down' || status === 'broken') return status;
      return 'checking';
    }

    function ms(value) {
      if (value === null || value === undefined) return '-';
      if (value >= 1000) return (value / 1000).toFixed(1) + 's';
      return value + 'ms';
    }

    async function load() {
      const response = await fetch('/api/status', { cache: 'no-store' });
      const data = await response.json();
      render(data);
    }

    function render(data) {
      const results = data.results || [];
      overall.className = 'big-light ' + (data.overall || 'checking');
      overall.querySelector('.word').textContent = statusWord(data.overall);
      overallText.textContent = data.overall === 'green'
        ? 'All monitored checks are currently healthy.'
        : data.overall === 'amber'
          ? 'Something is slow or warning. Keep an eye on this.'
          : data.overall === 'red'
            ? 'A critical check is failing. Capture this and escalate.'
            : 'Waiting for first check to finish.';

      checkCount.textContent = results.length;
      const bad = results.filter(item => ['down', 'broken', 'slow', 'warn'].includes(item.status));
      problemCount.textContent = bad.length;
      const slowestResult = results.slice().sort((a, b) => (b.response_ms || 0) - (a.response_ms || 0))[0];
      slowest.textContent = slowestResult ? ms(slowestResult.response_ms) : '-';
      lastCheck.textContent = niceTime(data.last_run_finished);

      board.innerHTML = results.map(item => `
        <article class="tile">
          <div><span class="lamp ${resultClass(item.status)}"></span></div>
          <strong>${escapeHtml(item.label)}</strong>
          <div class="meta">${escapeHtml(item.message)}<br>HTTP ${item.http_status || '-'} · ${ms(item.response_ms)} · ${item.bytes || 0} bytes</div>
        </article>
      `).join('');

      const recent = (data.history || []).slice(-60);
      const maxMs = Math.max(1000, ...recent.map(round => averageMs(round.results || [])));
      chart.innerHTML = recent.map(round => {
        const average = averageMs(round.results || []);
        const height = Math.max(4, Math.round((average / maxMs) * 92));
        return `<div class="bar ${round.overall === 'red' ? 'down' : round.overall === 'amber' ? 'slow' : 'ok'}" style="height:${height}px" title="${niceTime(round.checked_at)} · ${ms(Math.round(average))} average"></div>`;
      }).join('');

      const incidentRows = (data.incidents || []).slice().reverse();
      incidents.innerHTML = incidentRows.length ? incidentRows.map(item => `
        <tr>
          <td class="nowrap">${niceTime(item.time)}</td>
          <td><span class="incident-type">${escapeHtml(item.type)}</span></td>
          <td>${escapeHtml(item.label || '-')}</td>
          <td>${escapeHtml(item.message || '-')}</td>
          <td class="nowrap">${item.http_status || '-'}</td>
          <td class="nowrap">${ms(item.response_ms)}</td>
        </tr>
      `).join('') : '<tr><td colspan="6" class="meta">No incidents recorded yet.</td></tr>';

      if (data.build && data.build.fingerprint) {
        buildInfo.textContent = `Current fingerprint ${data.build.fingerprint}, based on ${data.build.asset_count || 0} Nuxt assets. Last checked ${niceTime(data.build.checked_at)}. A change here usually means a frontend deploy or asset rebuild.`;
      } else {
        buildInfo.textContent = 'No build fingerprint captured yet.';
      }
    }

    function averageMs(results) {
      const values = results.map(item => item.response_ms).filter(value => Number.isFinite(value));
      if (!values.length) return 0;
      return values.reduce((sum, value) => sum + value, 0) / values.length;
    }

    function escapeHtml(value) {
      return String(value ?? '').replace(/[&<>"']/g, char => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;'
      }[char]));
    }

    document.getElementById('checkNow').addEventListener('click', async () => {
      await fetch('/api/check-now', { cache: 'no-store' });
      setTimeout(load, 1500);
    });

    load();
    setInterval(load, 10000);
  </script>
</body>
</html>
"""


def main() -> None:
    threading.Thread(target=monitor.run_forever, daemon=True).start()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    shown_host = "127.0.0.1" if HOST in {"0.0.0.0", ""} else HOST
    print(f"{APP_NAME} running at http://{shown_host}:{PORT}")
    print(f"Checks run every {CHECK_INTERVAL_SECONDS} seconds. Press Ctrl+C to stop.")
    if MONITOR_PASSWORD:
        print(f"Password protection enabled for user: {MONITOR_USERNAME}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        monitor.running = False


if __name__ == "__main__":
    main()
