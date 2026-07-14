# Assembly Site Monitor

This is a monitoring dashboard for `assemblyfestival.com`. It can run locally
on a PC, or on a cloud host so the team can check it even when your PC is off.

## What it checks

- Main public pages
- Key Nuxt/API routes
- Show search/listing data
- Sample performance ticket availability/prices
- Directus/CMS health
- Visible page error markers
- Cloudflare/bad gateway markers
- Slow response times
- Frontend asset fingerprint changes, which may indicate a deploy

The ticket availability check does not add anything to a basket or complete a
transaction. It confirms that the site can load sample performance ticket
types/prices, which is the step customers need before they can buy.

## How to run

### Local PC

Open PowerShell in this folder and run:

```powershell
.\start-monitor.ps1
```

Then open:

```text
http://127.0.0.1:8787
```

Leave the PowerShell window open while you want monitoring to run.

### Cloud / always-on use

For monitoring that keeps running when your PC is off, deploy this folder to an
always-on web host. Good options are:

- Render paid/starter web service
- Railway
- Fly.io
- A small VPS
- Any host that can run a Python web process or Docker container

Avoid free services that sleep when idle, because the monitor will stop checking
while the service is asleep.

Set these environment variables on the host:

```text
HOST=0.0.0.0
PORT=<use the host default if it provides one>
MONITOR_USERNAME=assembly
MONITOR_PASSWORD=<choose a strong password>
CHECK_INTERVAL_SECONDS=60
```

If `MONITOR_PASSWORD` is set, the dashboard asks for a username and password.
If it is blank, the dashboard is public.

This folder includes:

```text
Procfile
runtime.txt
Dockerfile
render.yaml
```

Those files make it easier to deploy on common cloud hosts.

The cloud health-check URL is:

```text
/healthz
```

Use persistent storage if the host offers it. Without persistent storage, the
dashboard still monitors live status, but older incident history may reset when
the service restarts.

## Evidence files

The dashboard writes evidence into:

```text
monitor-data/history.jsonl
monitor-data/incidents.jsonl
```

You can also export the incident log from the dashboard as CSV.

## Status meanings

- Green: healthy
- Amber: slow, warning, or non-critical problem
- Red: critical page/API/CMS problem

The monitor runs every 60 seconds.
