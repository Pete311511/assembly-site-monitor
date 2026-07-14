from __future__ import annotations

import hashlib
import html
import json
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


STATUS_FILE = Path("docs/status.json")
REQUEST_TIMEOUT_SECONDS = 35
SLOW_SECONDS = 8
VERY_SLOW_SECONDS = 20
MAX_HISTORY = 120
MAX_INCIDENTS = 120


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


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def fetch(url: str) -> tuple[int | None, bytes, str | None, int]:
    start = time.perf_counter()
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Assembly Festival Monitor/1.0 GitHub Actions",
            "Accept": "application/json,text/html,*/*",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            body = response.read()
            return response.status, body, None, int((time.perf_counter() - start) * 1000)
    except urllib.error.HTTPError as exc:
        body = exc.read() if exc.fp else b""
        return exc.code, body, None, int((time.perf_counter() - start) * 1000)
    except (urllib.error.URLError, TimeoutError, socket.timeout) as exc:
        return None, b"", str(exc), int((time.perf_counter() - start) * 1000)


def result(check: dict[str, Any], status: str, http_status: int | None, response_ms: int | None, body: bytes, message: str, title: str = "") -> dict[str, Any]:
    return {
        "id": check["id"],
        "label": check["label"],
        "url": check["url"],
        "kind": check["kind"],
        "critical": bool(check.get("critical")),
        "status": status,
        "http_status": http_status,
        "response_ms": response_ms,
        "bytes": len(body),
        "title": html.unescape(title).strip(),
        "message": message,
        "checked_at": utc_now(),
    }


def check_endpoint(check: dict[str, Any]) -> dict[str, Any]:
    if check["kind"] == "projects-search":
        return check_projects_search(check)
    if check["kind"] == "ticket-availability":
        return check_ticket_availability(check)

    status_code, body, error, elapsed_ms = fetch(check["url"])
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

    return result(check, status, status_code, elapsed_ms, body, message, title)


def check_projects_search(check: dict[str, Any]) -> dict[str, Any]:
    status_code, body, error, elapsed_ms = fetch(check["url"])
    text = body.decode("utf-8", errors="ignore")
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

    return result(check, status, status_code, elapsed_ms, body, message)


def check_ticket_availability(check: dict[str, Any]) -> dict[str, Any]:
    status_code, body, error, elapsed_ms = fetch(check["url"])
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
                    perf_status, perf_body, perf_error, perf_ms = fetch(availability_url)
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

    return result(check, status, status_code, elapsed_ms, body, message)


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


def detect_build_fingerprint(home_result: dict[str, Any]) -> dict[str, Any]:
    if home_result.get("status") not in {"ok", "slow", "warn"}:
        return {}
    status_code, body, error, _elapsed = fetch("https://assemblyfestival.com/")
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


def overall_status(results: list[dict[str, Any]]) -> str:
    if not results:
        return "checking"
    critical = [result for result in results if result.get("critical")]
    if any(result["status"] in {"down", "broken"} for result in critical):
        return "red"
    if any(result["status"] in {"down", "broken"} for result in results):
        return "amber"
    if any(result["status"] in {"slow", "warn"} for result in results):
        return "amber"
    return "green"


def load_previous() -> dict[str, Any]:
    if STATUS_FILE.exists():
        try:
            return json.loads(STATUS_FILE.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


def incident(event_type: str, item: dict[str, Any], message: str | None = None, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "time": utc_now(),
        "type": event_type,
        "label": item.get("label"),
        "message": message or item.get("message"),
        "status": item.get("status"),
        "http_status": item.get("http_status"),
        "response_ms": item.get("response_ms"),
        "url": item.get("url"),
        "extra": extra or {},
    }


def main() -> None:
    STATUS_FILE.parent.mkdir(parents=True, exist_ok=True)
    previous = load_previous()
    previous_results = {item["id"]: item for item in previous.get("results", [])}
    previous_build = previous.get("build") or {}
    incidents = list(previous.get("incidents", []))[-MAX_INCIDENTS:]

    results = [check_endpoint(check) for check in CHECKS]
    overall = overall_status(results)
    build = detect_build_fingerprint(next((item for item in results if item["id"] == "home"), {}))

    for item in results:
        previous_status = previous_results.get(item["id"], {}).get("status")
        if item["status"] in {"down", "broken"} and previous_status != item["status"]:
            incidents.append(incident("site-problem", item))
        elif item["status"] == "slow" and previous_status not in {"slow", "down", "broken"}:
            incidents.append(incident("slow-response", item))
        elif previous_status in {"down", "broken", "slow"} and item["status"] == "ok":
            incidents.append(incident("recovered", item, "Recovered"))

    if build.get("fingerprint") and build.get("fingerprint") != previous_build.get("fingerprint"):
        message = "Frontend asset fingerprint changed"
        if previous_build.get("fingerprint"):
            message = "Possible deploy detected: frontend asset fingerprint changed"
        incidents.append({
            "time": utc_now(),
            "type": "deploy-change",
            "label": "Frontend build",
            "message": message,
            "status": None,
            "http_status": None,
            "response_ms": None,
            "url": None,
            "extra": build,
        })
    elif not build:
        build = previous_build

    history = list(previous.get("history", []))[-MAX_HISTORY:]
    history.append({
        "checked_at": utc_now(),
        "overall": overall,
        "results": results,
        "build": build,
    })

    payload = {
        "app": "Assembly Site Monitor",
        "now": utc_now(),
        "overall": overall,
        "last_run_finished": utc_now(),
        "results": results,
        "incidents": incidents[-MAX_INCIDENTS:],
        "history": history[-MAX_HISTORY:],
        "build": build,
    }
    STATUS_FILE.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Overall: {overall}")
    for item in results:
        print(f"{item['label']}: {item['status']} - {item['message']}")


if __name__ == "__main__":
    main()
