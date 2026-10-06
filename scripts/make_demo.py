"""Builds the demo report shown in the README (docs/report.png).

Creates a throwaway repo with planted *fake* credentials and common mistakes,
scans it, and writes docs/demo-report.html. Screenshot it with:

    chrome --headless=new --window-size=1100,1500 --screenshot=docs/report.png docs/demo-report.html

Run from the repo root: python scripts/make_demo.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from haetae.report import render_html  # noqa: E402
from haetae.scanner import scan  # noqa: E402
from tests.helpers import FAKE_AWS_KEY, FAKE_GITHUB_TOKEN, TempRepo  # noqa: E402


def main() -> None:
    repo = TempRepo()
    try:
        repo.write(".gitignore", "node_modules\n")
        repo.write("src/config.js", f"export const aws = '{FAKE_AWS_KEY}';\n")
        repo.write("src/db.js", "export const find = (id) => pool.query(`SELECT * FROM users WHERE id = ${id}`);\n")
        repo.write("src/server.js", "app.use(cors());\napp.listen(3000);\n")
        repo.write(".env", "DATABASE_URL=postgres://localhost/app\n")
        repo.commit("initial")
        repo.write("scripts/deploy.sh", f"TOKEN={FAKE_GITHUB_TOKEN}\n")
        repo.commit("deploy script")
        repo.delete("scripts/deploy.sh")
        repo.commit("remove token")

        result = scan(repo.root, history=True, offline=True)
        result.root = "/home/demo/acme-app"
        result.skipped = [n.replace(str(repo.root), "/home/demo/acme-app") for n in result.skipped]
        out = ROOT / "docs" / "demo-report.html"
        out.parent.mkdir(exist_ok=True)
        out.write_text(render_html(result), encoding="utf-8")
        print(f"wrote {out} ({len(result.findings)} findings)")
    finally:
        repo.cleanup()


if __name__ == "__main__":
    main()
