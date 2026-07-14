# Assembly Site Monitor - Free GitHub Version

This version runs on GitHub Actions and publishes a dashboard through GitHub
Pages.

## What to upload

Upload everything in this folder to the root of your GitHub repository:

```text
.github/workflows/monitor.yml
docs/index.html
docs/status.json
scripts/check_site.py
README.md
```

## GitHub Pages setting

In GitHub:

```text
Settings -> Pages
Source: Deploy from a branch
Branch: main
Folder: /docs
```

## How it works

- GitHub runs the monitor every 5 minutes.
- The monitor checks Assembly pages, APIs, show listings and ticket availability.
- It updates `docs/status.json`.
- The dashboard at GitHub Pages reads that file.

GitHub's free scheduled checks are not guaranteed to run exactly every 5
minutes, but this is the best fully free option.
