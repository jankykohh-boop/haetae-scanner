"""C2 — known vulnerabilities in dependencies, via the public OSV database (osv.dev).

Only package names and versions leave the machine; never code or file contents.
One finding per vulnerable package (not per advisory), ranked by the worst
advisory, with dev-only dependencies one step lower than what ships to users.
"""

from __future__ import annotations

import json
import math
import re
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from .. import __version__
from ..models import Finding, Severity

CHECK = "C2"
OSV_API = "https://api.osv.dev/v1"
TIMEOUT = 20


@dataclass
class Package:
    ecosystem: str        # "npm" or "PyPI"
    name: str
    version: str
    manifest: str         # repo-relative path of the file that pinned it
    dev: bool = False
    direct: bool | None = None   # None when the manifest can't tell

    def key(self) -> tuple[str, str, str]:
        return (self.ecosystem, self.name, self.version)


@dataclass
class Collected:
    packages: list[Package] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


# ------------------------------------------------------------------ parsing

def _norm_pypi(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _parse_package_lock(path: Path, rel: str) -> list[Package]:
    data = json.loads(path.read_text(encoding="utf-8"))
    out: list[Package] = []
    if "packages" in data:                       # lockfileVersion 2 and 3
        root = data["packages"].get("", {})
        direct = set(root.get("dependencies", {})) | set(root.get("devDependencies", {}))
        for key, meta in data["packages"].items():
            if not key or "version" not in meta or meta.get("link"):
                continue
            name = key.rsplit("node_modules/", 1)[-1]
            out.append(Package("npm", name, meta["version"], rel, bool(meta.get("dev")), name in direct and key == f"node_modules/{name}"))
    else:                                        # lockfileVersion 1
        def walk(deps: dict, top: bool):
            for name, meta in deps.items():
                if "version" in meta:
                    out.append(Package("npm", name, meta["version"], rel, bool(meta.get("dev")), top or None))
                walk(meta.get("dependencies", {}), False)
        walk(data.get("dependencies", {}), True)
    return out


EXACT_NPM = re.compile(r"^=?v?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-]+)?)$")


def _parse_package_json(path: Path, rel: str, notes: list[str]) -> list[Package]:
    data = json.loads(path.read_text(encoding="utf-8"))
    out, loose = [], 0
    for section, dev in (("dependencies", False), ("devDependencies", True)):
        for name, spec in (data.get(section) or {}).items():
            m = EXACT_NPM.match(str(spec).strip())
            if m:
                out.append(Package("npm", name, m.group(1), rel, dev, True))
            else:
                loose += 1
    if loose:
        notes.append(f"C2: {loose} dependencies in {rel} use version ranges and no lockfile was found, "
                     "so they were not checked (commit package-lock.json to check them)")
    return out


REQ_PIN = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._\-]*)(?:\[[^\]]*\])?\s*==\s*([^\s;#,]+)")


def _parse_requirements(path: Path, rel: str, notes: list[str]) -> list[Package]:
    out, loose = [], 0
    dev = bool(re.search(r"dev|test|lint|doc", path.name, re.I))
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "-", "git+", "http")):
            continue
        m = REQ_PIN.match(line)
        if m:
            out.append(Package("PyPI", _norm_pypi(m.group(1)), m.group(2), rel, dev, True))
        else:
            loose += 1
    if loose:
        notes.append(f"C2: {loose} requirements in {rel} are not pinned with == and were not checked")
    return out


def _parse_pipfile_lock(path: Path, rel: str) -> list[Package]:
    data = json.loads(path.read_text(encoding="utf-8"))
    out = []
    for section, dev in (("default", False), ("develop", True)):
        for name, meta in (data.get(section) or {}).items():
            version = str(meta.get("version", "")).lstrip("=")
            if version:
                out.append(Package("PyPI", _norm_pypi(name), version, rel, dev, None))
    return out


def _parse_poetry_lock(path: Path, rel: str, notes: list[str]) -> list[Package]:
    try:
        import tomllib
    except ImportError:          # Python 3.10
        notes.append(f"C2: {rel} skipped (reading poetry.lock needs Python 3.11+)")
        return []
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    return [
        Package("PyPI", _norm_pypi(p["name"]), str(p["version"]), rel, p.get("category") == "dev", None)
        for p in data.get("package", []) if "name" in p and "version" in p
    ]


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]   # drop the XML namespace


def _child(el, name):
    return next((c for c in el if _local(c.tag) == name), None)


def _parse_pom(path: Path, rel: str, notes: list[str]) -> list[Package]:
    """Direct dependencies of a Maven pom.xml, resolving ${property} versions from <properties>.

    Python's bundled expat refuses external entities and caps entity expansion, so a
    hostile pom can't read files or blow up memory.
    """
    root = ET.parse(path).getroot()
    props = {}
    pr = _child(root, "properties")
    if pr is not None:
        props = {_local(c.tag): (c.text or "").strip() for c in pr}
    v = _child(root, "version")
    if v is not None and v.text:
        props.setdefault("project.version", v.text.strip())

    def resolve(text):
        text = (text or "").strip()
        for _ in range(5):                       # nested properties, bounded
            m = re.search(r"\$\{([^}]+)\}", text)
            if not m or m.group(1) not in props:
                break
            text = text.replace(m.group(0), props[m.group(1)])
        return text

    out, unresolved = [], 0
    deps = _child(root, "dependencies")
    for dep in (deps if deps is not None else []):
        fields = {_local(c.tag): (c.text or "").strip() for c in dep}
        group, artifact, version = fields.get("groupId"), fields.get("artifactId"), resolve(fields.get("version"))
        if not (group and artifact):
            continue
        if not version or "${" in version or version.startswith(("[", "(")):
            unresolved += 1            # managed by a parent/BOM, or a range: can't know the exact version
            continue
        out.append(Package("Maven", f"{group}:{artifact}", version, rel,
                           fields.get("scope") in ("test", "provided"), True))
    if unresolved:
        notes.append(f"C2: {unresolved} dependencies in {rel} get their version from a parent POM, BOM or range "
                     "and were not checked (a gradle.lockfile or `mvn dependency:list` output would pin them)")
    return out


def _parse_gradle_lock(path: Path, rel: str) -> list[Package]:
    out = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("empty="):
            continue
        coords, _, configs = line.partition("=")
        parts = coords.split(":")
        if len(parts) != 3:
            continue
        dev = bool(configs) and all("test" in c.lower() for c in configs.split(","))
        out.append(Package("Maven", f"{parts[0]}:{parts[1]}", parts[2], rel, dev, None))
    return out


def collect(files: list[tuple[str, Path]]) -> Collected:
    """Find manifests among the scanned files and pull out pinned packages."""
    result = Collected()
    by_dir: dict[str, set[str]] = {}
    for rel, _ in files:
        d, _, name = rel.rpartition("/")
        by_dir.setdefault(d, set()).add(name)

    for rel, path in files:
        d, _, name = rel.rpartition("/")
        try:
            if name == "package-lock.json" or name == "npm-shrinkwrap.json":
                result.packages += _parse_package_lock(path, rel)
            elif name == "package.json" and not ({"package-lock.json", "npm-shrinkwrap.json"} & by_dir[d]):
                result.packages += _parse_package_json(path, rel, result.notes)
            elif re.fullmatch(r"requirements[\w\-.]*\.txt", name):
                result.packages += _parse_requirements(path, rel, result.notes)
            elif name == "Pipfile.lock":
                result.packages += _parse_pipfile_lock(path, rel)
            elif name == "poetry.lock":
                result.packages += _parse_poetry_lock(path, rel, result.notes)
            elif name == "pom.xml":
                result.packages += _parse_pom(path, rel, result.notes)
            elif name == "gradle.lockfile":
                result.packages += _parse_gradle_lock(path, rel)
        except (ValueError, KeyError, TypeError, ET.ParseError) as e:
            result.notes.append(f"C2: could not read {rel} ({e.__class__.__name__}); its dependencies were not checked")

    # same package+version pinned in several places: check it once
    seen: dict[tuple, Package] = {}
    for p in result.packages:
        prev = seen.get(p.key())
        if prev is None:
            seen[p.key()] = p
        else:  # production use wins over dev-only; direct wins over transitive
            prev.dev = prev.dev and p.dev
            prev.direct = prev.direct or p.direct
    result.packages = list(seen.values())
    return result


# ------------------------------------------------------------------ OSV

class OSVClient:
    """Thin wrapper over the OSV REST API. Tests swap this for a fake."""

    def _post(self, url: str, body: dict) -> dict:
        req = urllib.request.Request(
            url, data=json.dumps(body).encode(), method="POST",
            headers={"Content-Type": "application/json", "User-Agent": f"haetae/{__version__}"},
        )
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return json.load(resp)

    def _get(self, url: str) -> dict:
        req = urllib.request.Request(url, headers={"User-Agent": f"haetae/{__version__}"})
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return json.load(resp)

    def query(self, packages: list[Package]) -> list[list[str]]:
        """Vulnerability IDs affecting each package, in the same order."""
        ids: list[list[str]] = []
        for i in range(0, len(packages), 1000):
            chunk = packages[i:i + 1000]
            body = {"queries": [{"package": {"ecosystem": p.ecosystem, "name": p.name}, "version": p.version} for p in chunk]}
            res = self._post(f"{OSV_API}/querybatch", body)
            ids += [[v["id"] for v in r.get("vulns", [])] for r in res.get("results", [])]
        return ids

    def details(self, vuln_ids: list[str]) -> dict[str, dict]:
        with ThreadPoolExecutor(max_workers=8) as pool:
            docs = pool.map(lambda v: self._get(f"{OSV_API}/vulns/{v}"), vuln_ids)
            return dict(zip(vuln_ids, docs))


# ------------------------------------------------------------------ severity

_GHSA = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH, "MODERATE": Severity.MEDIUM,
         "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}

_W = {
    "AV": {"N": .85, "A": .62, "L": .55, "P": .2}, "AC": {"L": .77, "H": .44},
    "UI": {"N": .85, "R": .62}, "CIA": {"H": .56, "L": .22, "N": 0.0},
}


def _roundup(x: float) -> float:
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3_score(vector: str) -> float | None:
    """Base score from a CVSS v3.x vector string (FIRST spec formula)."""
    try:
        m = dict(part.split(":") for part in vector.split("/")[1:])
        changed = m["S"] == "C"
        pr = {"N": .85, "L": .68 if changed else .62, "H": .5 if changed else .27}[m["PR"]]
        iss = 1 - (1 - _W["CIA"][m["C"]]) * (1 - _W["CIA"][m["I"]]) * (1 - _W["CIA"][m["A"]])
        impact = 7.52 * (iss - .029) - 3.25 * (iss - .02) ** 15 if changed else 6.42 * iss
        expl = 8.22 * _W["AV"][m["AV"]] * _W["AC"][m["AC"]] * pr * _W["UI"][m["UI"]]
    except (KeyError, ValueError):
        return None
    if impact <= 0:
        return 0.0
    return _roundup(min((1.08 if changed else 1) * (impact + expl), 10))


def _from_score(score: float) -> Severity:
    if score >= 9:
        return Severity.CRITICAL
    if score >= 7:
        return Severity.HIGH
    if score >= 4:
        return Severity.MEDIUM
    return Severity.LOW if score > 0 else Severity.INFO


def vuln_severity(doc: dict) -> Severity:
    label = (doc.get("database_specific") or {}).get("severity")
    if isinstance(label, str) and label.upper() in _GHSA:
        return _GHSA[label.upper()]
    for sev in doc.get("severity", []):
        if sev.get("type") == "CVSS_V3":
            score = cvss3_score(sev.get("score", ""))
            if score is not None:
                return _from_score(score)
    return Severity.MEDIUM     # unknown: don't hide it, don't overstate it


def _version_key(v: str) -> tuple:
    return tuple(int(p) if p.isdigit() else -1 for p in re.split(r"[.\-+]", v) if p)


def fixed_version(doc: dict, pkg: Package) -> str | None:
    """Smallest fixed version above the installed one: usually a patch on the same
    release line, so the advice never forces a needless major upgrade."""
    best = None
    for aff in doc.get("affected", []):
        p = aff.get("package", {})
        name = _norm_pypi(p.get("name", "")) if pkg.ecosystem == "PyPI" else p.get("name")
        if p.get("ecosystem") != pkg.ecosystem or name != pkg.name:
            continue
        for rng in aff.get("ranges", []):
            for ev in rng.get("events", []):
                fix = ev.get("fixed")
                if fix and _version_key(fix) > _version_key(pkg.version):
                    if best is None or _version_key(fix) < _version_key(best):
                        best = fix
    return best


# ------------------------------------------------------------------ check

def _cves(doc: dict) -> list[str]:
    ids = [doc.get("id", "")] + list(doc.get("aliases", []))
    return [i for i in ids if i.startswith("CVE-")]


def _label(vuln_id: str, doc: dict) -> str:
    """'CVE-2023-1234 (GHSA-xxxx)': the CVE is what people search for, the advisory is the source."""
    cves = [c for c in _cves(doc) if c != vuln_id]
    return f"{cves[0]} ({vuln_id})" if cves else vuln_id


def check(files: list[tuple[str, Path]], *, offline: bool = False, client: OSVClient | None = None):
    """Returns (findings, notes)."""
    collected = collect(files)
    notes = list(collected.notes)
    pkgs = collected.packages
    if not pkgs:
        if not notes:
            notes.append("C2: no lockfiles or pinned dependencies found")
        return [], notes
    if offline:
        return [], notes + [f"C2: skipped ({len(pkgs)} dependencies) because --offline was set"]

    client = client or OSVClient()
    try:
        ids = client.query(pkgs)
        unique = sorted({i for row in ids for i in row})
        docs = client.details(unique) if unique else {}
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
        return [], notes + [f"C2: skipped, could not reach osv.dev ({e.__class__.__name__}); "
                            f"{len(pkgs)} dependencies were NOT checked"]

    findings = []
    for pkg, vuln_ids in zip(pkgs, ids):
        if not vuln_ids:
            continue
        rated = sorted(((vuln_severity(docs.get(v, {})), v) for v in vuln_ids), reverse=True)
        worst = rated[0][0]
        severity = Severity(max(worst - 1, Severity.LOW)) if pkg.dev else worst
        fixes = [f for f in (fixed_version(docs.get(v, {}), pkg) for v in vuln_ids) if f]
        target = max(fixes, key=_version_key) if fixes else None

        listed = ", ".join(_label(v, docs.get(v, {})) for _, v in rated[:3]) + (
            f" and {len(rated) - 3} more" if len(rated) > 3 else "")
        scope = "dev-only" if pkg.dev else ("direct" if pkg.direct else "transitive" if pkg.direct is False else "")
        msg = (f"{pkg.name} {pkg.version} has {len(vuln_ids)} known "
               f"vulnerabilit{'y' if len(vuln_ids) == 1 else 'ies'} ({listed})"
               + (f"; {scope} dependency" if scope else ""))
        why = (f"The worst advisory is rated {worst.label()}. "
               + ("It's only used in development, so it's ranked one step lower." if pkg.dev
                  else "Attackers actively scan for apps running known-vulnerable versions."))
        if target:
            fix = f"Upgrade {pkg.name} to {target} or later."
            if _version_key(target)[:1] > _version_key(pkg.version)[:1]:
                fix += (f" That's a major-version upgrade: the {pkg.version.split('.')[0]}.x line no longer gets "
                        "every security fix, so plan and test it rather than bumping blindly.")
            if pkg.direct is False:
                fix += " It's a transitive dependency, so upgrade the package that pulls it in, or add an override."
        else:
            fix = f"No fixed version is published yet. Read the advisories ({rated[0][1]}) and consider replacing {pkg.name}."
        findings.append(Finding(
            check=CHECK, rule="Vulnerable dependency", severity=severity, path=pkg.manifest, line=None,
            message=msg, why=why, fix=fix,
            extra={"package": pkg.name, "version": pkg.version, "ecosystem": pkg.ecosystem,
                   "advisories": [v for _, v in rated],
                   "cves": sorted({c for _, v in rated for c in _cves(docs.get(v, {}))}),
                   "fixed_in": target, "dev": pkg.dev},
        ))
    checked = f"C2: checked {len(pkgs)} dependencies against osv.dev"
    return findings, notes + [checked]
