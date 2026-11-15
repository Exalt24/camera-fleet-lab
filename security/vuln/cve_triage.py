#!/usr/bin/env python3
"""CVE triage for the lab's own components: look up known CVEs, add exploitation data, rank them, say what to do.

The inventory is built from the compose file, the Dockerfiles and the pinned requirements. For each component the tool asks
  NVD 2.0      https://services.nvd.nist.gov/rest/json/cves/2.0     the CVEs whose affected range includes the component's version
  CISA KEV     the Known Exploited Vulnerabilities catalogue JSON   is the CVE known to be exploited in the wild
  FIRST EPSS   https://api.first.org/data/v1/epss                   the probability of exploitation in the next 30 days
and ranks every finding by one stated rule:

  1  known exploited (KEV yes), then KEV unknown (the catalogue did not load), then KEV no
  2  EPSS, highest first (a CVE with no EPSS value sorts after every CVE that has one)
  3  CVSS base score, highest first (v3.1, else v3.0, else v4.0, else v2; a missing score sorts last)
  4  reachable from outside the lab network before internal, according to docker-compose.yml
  5  CVE id, so equal findings always come out in the same order

A lookup that fails is reported as UNKNOWN for that component, never as "no CVEs found". With --offline (the default) the tool reads
saved real responses from snapshots/ and needs no network; --live fetches and --save-snapshots refreshes them.

    python security/vuln/cve_triage.py --offline --out docs/security/vuln
    python security/vuln/cve_triage.py --live --resolve-images --save-snapshots --out docs/security/vuln
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
SNAPSHOTS = HERE / "snapshots"

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CPE_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
NVD_MIN_INTERVAL_S = 6.5          # the keyless limit is 5 requests per 30 s; 6.5 s apart stays under it
NVD_PAGE = 2000
USER_AGENT = "camera-fleet-lab-cve-triage/1.0"


class LookupFailed(Exception):
    """A lookup did not give a usable answer. The reason is printed in the report."""


class ParseError(LookupFailed):
    """A response arrived but did not have the shape the API documents."""


# ------------------------------------------------------------------------------------------------------- inventory
@dataclass
class Component:
    name: str                      # display name
    version: str                   # the version looked up (upstream version, no distro suffix)
    vendor: str                    # CPE vendor
    product: str                   # CPE product
    services: list[str]            # compose services that run it
    source: str                    # where the version came from
    part: str = "a"                # CPE part: a (application) or o (operating system)
    note: str = ""

    @property
    def cpe(self) -> str:
        return f"cpe:2.3:{self.part}:{self.vendor}:{self.product}:{self.version}:*:*:*:*:*:*:*"

    @property
    def cpe_product(self) -> str:
        return f"cpe:2.3:{self.part}:{self.vendor}:{self.product}"

    @property
    def slug(self) -> str:
        return re.sub(r"[^a-z0-9]+", "-", f"{self.name}-{self.version}".lower()).strip("-")


def load_compose(path: Path) -> dict:
    import yaml
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def service_exposure(compose: dict) -> dict[str, dict]:
    """Per service: reachable when the compose file publishes a port for it, else internal. The rule is about the service's
    published ports only; it does not know which process inside the container listens on which port."""
    out: dict[str, dict] = {}
    for name, svc in (compose.get("services") or {}).items():
        ports = [str(p) for p in (svc.get("ports") or [])]
        mode = svc.get("network_mode")
        out[name] = {
            "reachable": bool(ports),
            "ports": ports,
            "profiles": svc.get("profiles", []),
            "network_mode": mode,
            "detail": ("publishes " + ", ".join(ports)) if ports else "no published port; reachable only on the lab's Docker networks",
        }
    # a service sharing another service's network namespace is as reachable as that one
    for name, svc in (compose.get("services") or {}).items():
        m = svc.get("network_mode") or ""
        if m.startswith("service:") and m.split(":", 1)[1] in out and out[m.split(":", 1)[1]]["reachable"]:
            out[name]["reachable"] = True
    return out


# Which image or package maps to which NVD CPE. The version comes from the file named in `source`; an entry here only says what the
# product is called in the NVD dictionary.
IMAGE_CPES = {
    "mariadb": ("MariaDB", "mariadb", "mariadb"),
    "wazuh/wazuh-manager": ("Wazuh manager", "wazuh", "wazuh"),
    "quay.io/keycloak/keycloak": ("Keycloak", "redhat", "keycloak"),
    "quay.io/oauth2-proxy/oauth2-proxy": ("oauth2-proxy", "oauth2_proxy_project", "oauth2_proxy"),
    "bluenviron/mediamtx": ("MediaMTX", "bluenviron", "mediamtx"),
}
PIP_CPES = {
    "fastapi": ("FastAPI", "tiangolo", "fastapi"),
    "uvicorn": ("Uvicorn", "encode", "uvicorn"),
    "sqlalchemy": ("SQLAlchemy", "sqlalchemy", "sqlalchemy"),
    "aiomysql": ("aiomysql", "aiomysql_project", "aiomysql"),
}
PKG_CPES = {   # distro packages the Dockerfiles install: (display, vendor, product)
    "wireguard-tools": ("WireGuard tools", "wireguard", "wireguard-tools"),
    "iptables": ("iptables", "netfilter", "iptables"),
    "ffmpeg": ("FFmpeg", "ffmpeg", "ffmpeg"),
}


def clean_version(v: str) -> str:
    """'v7.15.6' -> '7.15.6', '1.0.20210914-1.1' -> '1.0.20210914', '2:1.2.3+dfsg' -> '1.2.3'."""
    v = v.strip().lstrip("vV")
    v = re.sub(r"^\d+:", "", v)
    v = re.split(r"[-+~]", v, maxsplit=1)[0]
    return v


def parse_requirements(path: Path) -> dict[str, str]:
    """name -> version for every `name==version` line. A range such as `sqlalchemy[asyncio]>=2.1.8,<2.2` is not a pin, so it is
    skipped here and its resolved version comes from the image snapshot."""
    pins = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        m = re.match(r"^\s*([A-Za-z0-9_.\-]+)(\[[^\]]*\])?\s*==\s*([^\s#;]+)", line)
        if m:
            pins[m.group(1).lower()] = m.group(3)
    return pins


def parse_dockerfile_from(path: Path) -> str | None:
    for line in path.read_text(encoding="utf-8").splitlines():
        m = re.match(r"^\s*FROM\s+(\S+)", line, re.I)
        if m:
            return m.group(1)
    return None


def image_ref_parts(ref: str) -> tuple[str, str]:
    name, _, tag = ref.partition(":")
    return name, tag or "latest"


def build_inventory(root: Path, resolved: dict) -> list[Component]:
    """Build the component list from the repo's own files. `resolved` holds versions that no file pins (a floating tag, a distro
    package), taken from the images themselves by --resolve-images and saved in snapshots/image_versions.json."""
    compose = load_compose(root / "docker-compose.yml")
    comps: list[Component] = []

    def add(name, version, vendor, product, services, source, part="a", note=""):
        version = clean_version(version)
        if not version or not re.match(r"^\d", version):
            return
        for c in comps:
            if (c.vendor, c.product, c.version) == (vendor, product, version):
                c.services = sorted(set(c.services) | set(services))
                return
        comps.append(Component(name, version, vendor, product, sorted(services), source, part, note))

    # images named in the compose file
    for sname, svc in (compose.get("services") or {}).items():
        ref = svc.get("image")
        if not ref:
            continue
        iname, tag = image_ref_parts(ref)
        if iname in IMAGE_CPES:
            disp, vendor, product = IMAGE_CPES[iname]
            key = f"image:{ref}"
            if re.match(r"^v?\d+(\.\d+){2,}", tag):
                add(disp, tag, vendor, product, [sname], f"docker-compose.yml image tag {ref}")
            elif key in resolved:
                add(disp, resolved[key], vendor, product, [sname], f"docker-compose.yml image {ref} (floating tag), version read from the pulled image",
                    note=f"the tag `{tag}` floats; the version is whatever the image held on the day it was resolved")
    # images the Dockerfiles build on, and the pinned requirements
    for sname, svc in (compose.get("services") or {}).items():
        build = svc.get("build")
        if not build:
            continue
        ctx = root / (build if isinstance(build, str) else build.get("context", "."))
        df = ctx / "Dockerfile"
        if not df.exists():
            continue
        base = parse_dockerfile_from(df)
        if base and base.startswith("python:") and f"python:{base}" in resolved:
            add("Python", resolved[f"python:{base}"], "python", "python", [sname], f"{ctx.name}/Dockerfile FROM {base} (floating tag), version read from the image")
        if base and base.startswith("alpine:"):
            key = f"alpine:{base}"
            if key in resolved:
                add("Alpine Linux", resolved[key], "alpinelinux", "alpine_linux", [sname], f"{ctx.name}/Dockerfile FROM {base}", part="o")
        req = ctx / "requirements.txt"
        if req.exists():
            pins = parse_requirements(req)
            for pkg, (disp, vendor, product) in PIP_CPES.items():
                if pkg in pins:
                    add(disp, pins[pkg], vendor, product, [sname], f"{ctx.name}/requirements.txt pin {pkg}=={pins[pkg]}")
                elif f"pip:{sname}:{pkg}" in resolved:
                    add(disp, resolved[f"pip:{sname}:{pkg}"], vendor, product, [sname], f"{ctx.name}/requirements.txt range, version read from the built image")
        text = df.read_text(encoding="utf-8")
        for pkg, (disp, vendor, product) in PKG_CPES.items():
            if re.search(rf"\b{re.escape(pkg)}\b", text) and f"pkg:{sname}:{pkg}" in resolved:
                add(disp, resolved[f"pkg:{sname}:{pkg}"], vendor, product, [sname], f"{ctx.name}/Dockerfile installs {pkg}; version read from the built image")
    return sorted(comps, key=lambda c: (c.name.lower(), c.version))


def resolve_images(root: Path, project: str) -> dict:
    """Ask the running containers of a compose project which versions they hold (floating tags and distro packages are not pinned
    in any file). Needs Docker and the project up."""
    def sh(*cmd, timeout=60):
        r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
        return (r.stdout or "").strip()

    def exec_in(service, *cmd):
        return sh("docker", "compose", "-p", project, "--profile", "iam", "--profile", "security", "exec", "-T", service, *cmd)

    out: dict[str, str] = {}
    v = exec_in("hub", "python", "--version")
    if m := re.search(r"Python (\d+\.\d+\.\d+)", v):
        out["python:python:3.13-slim"] = m.group(1)
    v = exec_in("mariadb", "mariadbd", "--version")
    if m := re.search(r"Ver (\d+\.\d+\.\d+)", v):
        out["image:mariadb:11"] = m.group(1)
    v = exec_in("camera", "/mediamtx", "--version")
    if m := re.search(r"v?(\d+\.\d+\.\d+)", v):
        out["image:bluenviron/mediamtx:latest-ffmpeg"] = m.group(1)
    v = exec_in("edge", "cat", "/etc/alpine-release")
    if re.match(r"\d+\.\d+\.\d+", v):
        out["alpine:alpine:3.20"] = v
    v = exec_in("hub", "dpkg-query", "-W", "-f", "${Version}", "wireguard-tools")
    if v:
        out["pkg:hub:wireguard-tools"] = v
    v = exec_in("hub", "dpkg-query", "-W", "-f", "${Version}", "iptables")
    if v:
        out["pkg:hub:iptables"] = v
    v = exec_in("hub", "dpkg-query", "-W", "-f", "${Version}", "ffmpeg")
    if v:
        out["pkg:hub:ffmpeg"] = v
    for pkg in ("iptables", "wireguard-tools"):
        v = exec_in("edge", "apk", "list", "-I", pkg)
        if m := re.search(re.escape(pkg) + r"-(\d[\w.]*)-r\d+", v):
            out[f"pkg:edge:{pkg}"] = m.group(1)
    for pkg in ("sqlalchemy",):
        v = exec_in("hub", "python", "-c", "import importlib.metadata as m;print(m.version('SQLAlchemy'))")
        if re.match(r"\d+\.\d+", v):
            out[f"pip:hub:{pkg}"] = v
    return out


# ------------------------------------------------------------------------------------------------------------ lookups
class RateLimiter:
    def __init__(self, min_interval: float, clock=time.monotonic, sleep=time.sleep) -> None:
        self.min_interval, self.clock, self.sleep = min_interval, clock, sleep
        self.last: float | None = None

    def wait(self) -> None:
        now = self.clock()
        if self.last is not None and now - self.last < self.min_interval:
            self.sleep(self.min_interval - (now - self.last))
        self.last = self.clock()


def http_get_json(url: str, params: dict | None = None, timeout: float = 60.0) -> dict:
    full = url + ("?" + urllib.parse.urlencode(params) if params else "")
    req = urllib.request.Request(full, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as err:
        raise LookupFailed(f"HTTP {err.code} from {url}") from err
    except (urllib.error.URLError, TimeoutError, OSError) as err:
        raise LookupFailed(f"network error from {url}: {err}") from err
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as err:
        raise ParseError(f"the answer from {url} is not JSON") from err


class Fetcher:
    """Live lookups with the NVD rate limit and a few retries on the answers an overloaded API gives (403, 429, 503, a dropped connection)."""

    def __init__(self, get=http_get_json, limiter: RateLimiter | None = None, sleep=time.sleep, retries: int = 4) -> None:
        self.get, self.sleep, self.retries = get, sleep, retries
        self.nvd_limiter = limiter or RateLimiter(NVD_MIN_INTERVAL_S)

    def _retrying(self, label: str, call, wait_s: float):
        last = None
        for attempt in range(1, self.retries + 1):
            try:
                return call()
            except ParseError:
                raise
            except LookupFailed as err:
                last = err
                if attempt < self.retries:
                    self.sleep(wait_s * attempt)
        raise LookupFailed(f"{label}: gave up after {self.retries} attempts ({last})")

    def product_known(self, component: Component) -> int:
        """How many entries the NVD CPE dictionary holds for the product. Zero means the product has no CPE, so a CVE search by CPE can
        say nothing about it and the component must be reported UNKNOWN rather than clean."""
        def call():
            self.nvd_limiter.wait()
            return self.get(CPE_URL, {"cpeMatchString": f"cpe:2.3:{component.part}:{component.vendor}:{component.product}:*", "resultsPerPage": 1})
        doc = self._retrying(f"NVD CPE dictionary {component.vendor}:{component.product}", call, wait_s=10.0)
        if not isinstance(doc, dict) or not isinstance(doc.get("totalResults"), int):
            raise ParseError("the NVD CPE dictionary answer has no `totalResults` number")
        return doc["totalResults"]

    def nvd(self, component: Component) -> dict:
        """All pages of CVEs whose affected range includes the component's version, merged into one NVD-shaped document.

        virtualMatchString with versionStart and versionEnd both set to the version asks for the CVEs that apply to exactly that version,
        including ones NVD states as a range (versionEndExcluding). cpeName is not used: it only matches versions the CPE dictionary lists,
        and a new release is not in it yet."""
        known = self.product_known(component)
        if known == 0:
            raise LookupFailed(f"the NVD dictionary has no CPE product {component.vendor}:{component.product}, so a CVE search by CPE cannot assess it; "
                               "its own project advisories would have to be read")
        vulns: list = []
        start, total = 0, None
        first: dict | None = None
        while total is None or start < total:
            def call(start=start):
                self.nvd_limiter.wait()
                return self.get(NVD_URL, {"virtualMatchString": component.cpe_product, "versionStart": component.version, "versionStartType": "including",
                                          "versionEnd": component.version, "versionEndType": "including", "resultsPerPage": NVD_PAGE, "startIndex": start})
            page = self._retrying(f"NVD {component.name} {component.version}", call, wait_s=10.0)
            check_nvd_shape(page)
            first = first or page
            total = int(page["totalResults"])
            vulns.extend(page["vulnerabilities"])
            if not page["vulnerabilities"]:
                break
            start += len(page["vulnerabilities"])
        merged = dict(first or {})
        merged["vulnerabilities"] = vulns
        merged["resultsPerPage"] = len(vulns)
        merged["_cpe_dictionary_entries"] = known
        return merged

    def kev(self) -> dict:
        doc = self._retrying("CISA KEV", lambda: self.get(KEV_URL), wait_s=5.0)
        check_kev_shape(doc)
        return doc

    def epss(self, cves: list[str]) -> list[dict]:
        pages = []
        for i in range(0, len(cves), 100):
            chunk = cves[i:i + 100]
            doc = self._retrying("FIRST EPSS", lambda c=chunk: self.get(EPSS_URL, {"cve": ",".join(c)}), wait_s=5.0)
            check_epss_shape(doc)
            pages.append(doc)
        return pages


# ---------------------------------------------------------------------------------------------------------- parsers
def check_nvd_shape(doc) -> None:
    if not isinstance(doc, dict) or not isinstance(doc.get("vulnerabilities"), list) or not isinstance(doc.get("totalResults"), int):
        raise ParseError("the NVD answer has no `vulnerabilities` list and `totalResults` number")


def check_kev_shape(doc) -> None:
    if not isinstance(doc, dict) or not isinstance(doc.get("vulnerabilities"), list):
        raise ParseError("the KEV catalogue has no `vulnerabilities` list")


def check_epss_shape(doc) -> None:
    if not isinstance(doc, dict) or not isinstance(doc.get("data"), list):
        raise ParseError("the EPSS answer has no `data` list")


@dataclass
class Cve:
    id: str
    summary: str
    published: str
    cvss: float | None
    cvss_version: str | None
    severity: str | None
    configurations: list = field(default_factory=list)


CVSS_ORDER = (("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV40", "4.0"), ("cvssMetricV2", "2.0"))


def parse_nvd(doc) -> list[Cve]:
    """CVE records from one NVD 2.0 answer. An item with no usable id is skipped; a document with the wrong shape raises ParseError."""
    check_nvd_shape(doc)
    out = []
    for item in doc["vulnerabilities"]:
        cve = item.get("cve") if isinstance(item, dict) else None
        if not isinstance(cve, dict) or not re.match(r"^CVE-\d{4}-\d{4,}$", str(cve.get("id", ""))):
            continue
        desc = next((d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
        score = ver = sev = None
        metrics = cve.get("metrics") or {}
        for key, label in CVSS_ORDER:
            entries = metrics.get(key) or []
            if not entries:
                continue
            entry = next((e for e in entries if e.get("type") == "Primary"), entries[0])
            data = entry.get("cvssData") or {}
            try:
                score = float(data["baseScore"])
            except (KeyError, TypeError, ValueError):
                continue
            ver = label
            sev = (data.get("baseSeverity") or entry.get("baseSeverity") or "").upper() or None
            break
        out.append(Cve(cve["id"], desc.strip(), str(cve.get("published", ""))[:10], score, ver, sev, cve.get("configurations") or []))
    return out


def parse_kev(doc) -> dict[str, dict]:
    check_kev_shape(doc)
    out = {}
    for v in doc["vulnerabilities"]:
        if isinstance(v, dict) and re.match(r"^CVE-\d{4}-\d{4,}$", str(v.get("cveID", ""))):
            out[v["cveID"]] = {"date_added": v.get("dateAdded"), "due": v.get("dueDate"), "ransomware": v.get("knownRansomwareCampaignUse"),
                               "action": v.get("requiredAction")}
    return out


def parse_epss(docs) -> dict[str, tuple[float, float]]:
    """cve -> (epss, percentile). Accepts one answer or a list of them. A row that is not a number is skipped, not guessed."""
    out = {}
    for doc in (docs if isinstance(docs, list) else [docs]):
        check_epss_shape(doc)
        for row in doc["data"]:
            try:
                out[str(row["cve"])] = (float(row["epss"]), float(row["percentile"]))
            except (KeyError, TypeError, ValueError):
                continue
    return out


def vkey(v: str) -> tuple | None:
    parts = re.findall(r"\d+", clean_version(v))
    return tuple(int(p) for p in parts) if parts else None


def fixed_version(cve: Cve, component: Component) -> str | None:
    """The smallest `versionEndExcluding` above the component's version in a cpeMatch for the same product, if NVD names one."""
    mine = vkey(component.version)
    best: tuple | None = None
    best_text = None
    if mine is None:
        return None

    def walk(nodes):
        for node in nodes or []:
            yield from node.get("cpeMatch", []) or []
            yield from walk(node.get("nodes"))

    for conf in cve.configurations:
        for m in walk(conf.get("nodes")):
            if not m.get("vulnerable"):
                continue
            parts = str(m.get("criteria", "")).split(":")
            if len(parts) < 6 or (parts[3], parts[4]) != (component.vendor, component.product):
                continue
            end = m.get("versionEndExcluding")
            if not end or re.match(r"^\d{4}-\d{2}-\d{2}", str(end)):   # some entries bound a range by a date, which is not a release number
                continue
            k = vkey(end)
            start = vkey(m["versionStartIncluding"]) if m.get("versionStartIncluding") else None
            if k is None or k <= mine or (start is not None and mine < start):
                continue
            if best is None or k < best:
                best, best_text = k, end
    return best_text


def _cpe_matches(cve: Cve, component: Component):
    """Every cpeMatch in the CVE's configurations that names the component's product."""
    def walk(nodes):
        for node in nodes or []:
            yield from node.get("cpeMatch", []) or []
            yield from walk(node.get("nodes"))
    for conf in cve.configurations:
        for m in walk(conf.get("nodes")):
            parts = str(m.get("criteria", "")).split(":")
            if len(parts) >= 6 and (parts[3], parts[4]) == (component.vendor, component.product):
                yield m, parts


def _covers(m: dict, parts: list[str], mine: tuple) -> bool:
    """Does this cpeMatch include the component's version? A bound that cannot be read as a number is ignored, which widens the match
    (a finding is kept rather than dropped on a version string the tool does not understand)."""
    ver = parts[5]
    if ver == "-":
        return False
    if ver != "*":
        return vkey(ver) == mine and (len(parts) < 7 or parts[6] in ("*", "-"))
    for key in ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding"):
        if not m.get(key):
            continue
        bound = vkey(m[key])
        if bound is None:
            continue
        if key == "versionStartIncluding" and mine < bound:
            return False
        if key == "versionStartExcluding" and mine <= bound:
            return False
        if key == "versionEndIncluding" and mine > bound:
            return False
        if key == "versionEndExcluding" and mine >= bound:
            return False
    return True


def applicability(cve: Cve, component: Component) -> str:
    """Why a CVE NVD returned for this component is or is not a finding.

    'vulnerable'     an entry marked vulnerable covers the component's version: a finding.
    'platform'       the only entries that cover it are vulnerable=false, which NVD uses for the system the vulnerable software runs on (a
                     CVE in Django that needs Python 3.9.5 or later matches every Python 3.9.5 or later). The vulnerable software is
                     something else; whether it is installed here is a check for a person.
    'outside-range'  the entries for this product are all ranges that stop short of the version (NVD's version filter treats the end of a
                     range as inclusive, so a release that is the first fixed one, MariaDB 11.8.9 against `before 11.8.9`, still comes back).
    When the version cannot be read, or the CVE names the product in no way the tool can evaluate, it stays a finding."""
    mine = vkey(component.version)
    if mine is None:
        return "vulnerable"
    entries = list(_cpe_matches(cve, component))
    if not entries:
        return "vulnerable"
    covered = [m for m, parts in entries if _covers(m, parts, mine)]
    if not covered:
        return "outside-range"
    if not any(m.get("vulnerable") for m in covered):
        return "platform"
    return "vulnerable"


# ----------------------------------------------------------------------------------------------------------- ranking
@dataclass
class Finding:
    id: str
    component: str
    version: str
    services: list[str]
    cvss: float | None
    cvss_version: str | None
    severity: str | None
    epss: float | None
    epss_percentile: float | None
    kev: bool | None               # True, False, or None when the KEV catalogue did not load
    exposure: str                  # "reachable" or "internal"
    fixed_in: str | None
    remediation: str
    summary: str = ""
    published: str = ""
    kev_detail: dict | None = None
    rank: int = 0


def rank_key(f: Finding):
    """The ranking rule, as a sort key. Smaller sorts first."""
    kev_group = 0 if f.kev is True else (1 if f.kev is None else 2)
    epss = -f.epss if f.epss is not None else float("inf")
    cvss = -f.cvss if f.cvss is not None else float("inf")
    reach = 0 if f.exposure == "reachable" else 1
    return (kev_group, epss, cvss, reach, f.id)


def rank(findings: list[Finding]) -> list[Finding]:
    ordered = sorted(findings, key=rank_key)
    for i, f in enumerate(ordered, 1):
        f.rank = i
    return ordered


def remediation_text(component: Component, fixed: str | None, kev: bool | None) -> str:
    base = f"upgrade {component.name} from {component.version} to {fixed} or later" if fixed else \
        f"no fixed version is named in the NVD data for {component.name} {component.version}; read the vendor advisory, then upgrade or mitigate"
    if kev is True:
        base += " (known exploited: do this first)"
    return base


@dataclass
class ComponentResult:
    component: Component
    status: str                    # "ok" or "failed"
    detail: str = ""
    cve_count: int = 0
    exposure: str = "internal"
    exposure_detail: str = ""
    excluded: list = field(default_factory=list)          # CVEs NVD returned that are not findings, each with the reason


def component_exposure(component: Component, exposures: dict[str, dict]) -> tuple[str, str]:
    reach = [s for s in component.services if exposures.get(s, {}).get("reachable")]
    if reach:
        return "reachable", f"service {', '.join(reach)}: {exposures[reach[0]]['detail']}"
    return "internal", "services " + ", ".join(component.services) + ": no published port"


def triage(components: list[Component], nvd_docs: dict[str, object], kev_doc, epss_docs, exposures: dict[str, dict]):
    """The pure part: saved or fetched answers in, ranked findings and per-component status out.

    nvd_docs maps a component slug to its NVD answer, or to a LookupFailed carrying the reason. kev_doc and epss_docs may be a
    LookupFailed too. Nothing here touches the network."""
    kev_map: dict[str, dict] | None
    kev_note = ""
    try:
        if isinstance(kev_doc, Exception):
            raise kev_doc
        kev_map = parse_kev(kev_doc)
    except LookupFailed as err:
        kev_map, kev_note = None, f"the KEV catalogue lookup failed: {err}"
    epss_map: dict[str, tuple[float, float]] | None
    epss_note = ""
    try:
        if isinstance(epss_docs, Exception):
            raise epss_docs
        epss_map = parse_epss(epss_docs)
    except LookupFailed as err:
        epss_map, epss_note = None, f"the EPSS lookup failed: {err}"

    results: list[ComponentResult] = []
    findings: list[Finding] = []
    for comp in components:
        exp, exp_detail = component_exposure(comp, exposures)
        doc = nvd_docs.get(comp.slug)
        if doc is None:
            results.append(ComponentResult(comp, "failed", "no NVD answer was recorded for this component", 0, exp, exp_detail))
            continue
        try:
            if isinstance(doc, Exception):
                raise doc
            cves = parse_nvd(doc)
        except LookupFailed as err:
            results.append(ComponentResult(comp, "failed", str(err), 0, exp, exp_detail))
            continue
        excluded = []
        kept = []
        for c in cves:
            why = applicability(c, comp)
            if why == "vulnerable":
                kept.append(c)
            else:
                excluded.append({"id": c.id, "reason": why, "cvss": c.cvss, "kev": None if kev_map is None else (c.id in kev_map), "summary": c.summary[:200]})
        cves = kept
        results.append(ComponentResult(comp, "ok", "", len(cves), exp, exp_detail, excluded))
        for cve in cves:
            fixed = fixed_version(cve, comp)
            kev = None if kev_map is None else (cve.id in kev_map)
            ep = epss_map.get(cve.id) if epss_map is not None else None
            findings.append(Finding(cve.id, comp.name, comp.version, comp.services, cve.cvss, cve.cvss_version, cve.severity,
                                    ep[0] if ep else None, ep[1] if ep else None, kev, exp, fixed, remediation_text(comp, fixed, kev),
                                    cve.summary, cve.published, kev_map.get(cve.id) if kev_map and cve.id in kev_map else None))
    return rank(findings), results, {"kev": kev_note, "epss": epss_note}


# ------------------------------------------------------------------------------------------------------------ report
def finding_json(f: Finding) -> dict:
    d = asdict(f)
    d["kev"] = "yes" if f.kev is True else ("no" if f.kev is False else "unknown")
    return d


def render_markdown(findings: list[Finding], results: list[ComponentResult], notes: dict, meta: dict, top: int = 25) -> str:
    L = []
    L.append("# CVE triage of the lab's components")
    L.append("")
    L.append(f"Run: {meta['when']} ({meta['mode']}). Sources: NVD 2.0 (per component, by CPE), CISA KEV catalogue, FIRST EPSS. "
             f"{meta.get('snapshot_note', '')}".rstrip())
    L.append("")
    L.append("Ranking rule, in order: known exploited (KEV yes, then KEV unknown, then no); EPSS, highest first; CVSS base score, highest first "
             "(v3.1, else v3.0, else v4.0, else v2); reachable from outside the lab network before internal (docker-compose.yml, published ports); CVE id.")
    L.append("")
    failed = [r for r in results if r.status == "failed"]
    n_ex = sum(len(r.excluded) for r in results)
    L.append(f"{len(results)} components looked up, {len(results) - len(failed)} answered, {len(failed)} UNKNOWN. {len(findings)} findings in all"
             + (f", and {n_ex} more CVEs that NVD returned but that do not apply (listed apart, with the reason)." if n_ex else "."))
    for key in ("kev", "epss"):
        if notes.get(key):
            L.append("")
            L.append(f"**{notes[key]}.** KEV and EPSS columns for these findings read `unknown`, not `no`.")
    L.append("")
    L.append("## Components")
    L.append("")
    L.append("| Component | Version | Services | Exposure | NVD lookup | CVEs |")
    L.append("|---|---|---|---|---|---|")
    for r in results:
        c = r.component
        status = "ok" if r.status == "ok" else f"**UNKNOWN: {r.detail}**"
        cves = str(r.cve_count) if r.status == "ok" else "not known"
        L.append(f"| {c.name} | {c.version} | {', '.join(c.services)} | {r.exposure} | {status} | {cves} |")
    L.append("")
    if failed:
        L.append("A component marked UNKNOWN was not checked. It is not a clean result.")
        L.append("")
    for reason, title, blurb in (
        ("platform", "Matched only as a platform (not findings)",
         "NVD matched these CVEs to the component only as the system the vulnerable software runs on (the entry is marked `vulnerable: false`). "
         "They are not counted above. Whether the vulnerable software named in the CVE is installed here is a check for a person, so each one is listed with its KEV flag."),
        ("outside-range", "Returned by NVD, but the version is outside every affected range (not findings)",
         "NVD's version filter counts the end of a range as inclusive, so a release that is the first fixed one still comes back. The tool compares the "
         "version with each range itself and sets these aside; they are listed so the count can be checked.")):
        rows = [(r.component, p) for r in results for p in r.excluded if p["reason"] == reason]
        if not rows:
            continue
        L.append(f"## {title}")
        L.append("")
        L.append(blurb)
        L.append("")
        L.append("| CVE | Component | CVSS | KEV | What the CVE is about |")
        L.append("|---|---|---|---|---|")
        for comp, p in rows:
            kev = "yes" if p["kev"] is True else ("no" if p["kev"] is False else "unknown")
            cvss = f"{p['cvss']:.1f}" if p["cvss"] is not None else "n/a"
            L.append(f"| {p['id']} | {comp.name} {comp.version} | {cvss} | {kev} | {p['summary']} |")
        L.append("")
    L.append(f"## Top {min(top, len(findings))} findings")
    L.append("")
    L.append("| # | CVE | Component | CVSS | EPSS | KEV | Exposure | Remediation |")
    L.append("|---|---|---|---|---|---|---|---|")
    for f in findings[:top]:
        cvss = f"{f.cvss:.1f} (v{f.cvss_version})" if f.cvss is not None else "n/a"
        epss = f"{f.epss:.4f}" if f.epss is not None else "n/a"
        kev = "yes" if f.kev is True else ("no" if f.kev is False else "unknown")
        L.append(f"| {f.rank} | {f.id} | {f.component} {f.version} | {cvss} | {epss} | {kev} | {f.exposure} | {f.remediation} |")
    L.append("")
    return "\n".join(L) + "\n"


# --------------------------------------------------------------------------------------------------------- snapshots
def save_json(path: Path, doc) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=1, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def read_snapshots(components: list[Component], snap: Path):
    nvd: dict[str, object] = {}
    for c in components:
        p = snap / "nvd" / f"{c.slug}.json"
        if not p.exists():
            nvd[c.slug] = LookupFailed(f"no saved NVD answer for {c.slug} in the snapshot")
            continue
        try:
            nvd[c.slug] = load_json(p)
            if isinstance(nvd[c.slug], dict) and nvd[c.slug].get("_lookup_failed"):
                nvd[c.slug] = LookupFailed(str(nvd[c.slug]["_lookup_failed"]))
        except (OSError, ValueError) as err:
            nvd[c.slug] = ParseError(f"the saved NVD answer for {c.slug} is not readable ({err})")
    try:
        kev = load_json(snap / "kev.json")
    except (OSError, ValueError) as err:
        kev = LookupFailed(f"no readable KEV snapshot ({err})")
    try:
        epss = load_json(snap / "epss.json")
    except (OSError, ValueError) as err:
        epss = LookupFailed(f"no readable EPSS snapshot ({err})")
    return nvd, kev, epss


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--offline", action="store_true", help="read saved responses from snapshots/ (the default)")
    mode.add_argument("--live", action="store_true", help="ask NVD, CISA and FIRST now")
    ap.add_argument("--save-snapshots", action="store_true", help="with --live: save every raw answer under snapshots/")
    ap.add_argument("--resolve-images", action="store_true", help="read floating-tag and package versions from a running compose project")
    ap.add_argument("--project", default="cfl-iam", help="compose project name for --resolve-images")
    ap.add_argument("--out", default=str(ROOT / "docs" / "security" / "vuln"))
    ap.add_argument("--snapshots", default=str(SNAPSHOTS))
    ap.add_argument("--compose-root", default=str(ROOT))
    ap.add_argument("--top", type=int, default=25)
    args = ap.parse_args(argv)
    root, snap, out = Path(args.compose_root), Path(args.snapshots), Path(args.out)

    if args.resolve_images:
        resolved = resolve_images(root, args.project)
        save_json(snap / "image_versions.json", resolved)
        print(f"resolved {len(resolved)} versions from the running {args.project} containers")
    else:
        try:
            resolved = load_json(snap / "image_versions.json")
        except (OSError, ValueError):
            resolved = {}
    components = build_inventory(root, resolved)
    save_json(snap / "inventory.json", [{**asdict(c), "cpe": c.cpe, "slug": c.slug} for c in components])
    exposures = service_exposure(load_compose(root / "docker-compose.yml"))
    print(f"inventory: {len(components)} components")

    if args.live:
        fetcher = Fetcher()
        nvd: dict[str, object] = {}
        for c in components:
            try:
                nvd[c.slug] = fetcher.nvd(c)
                print(f"  NVD  {c.name} {c.version}: {len(nvd[c.slug]['vulnerabilities'])} CVEs", flush=True)
            except LookupFailed as err:
                nvd[c.slug] = err
                print(f"  NVD  {c.name} {c.version}: LOOKUP FAILED: {err}", flush=True)
        try:
            kev = fetcher.kev()
            print(f"  KEV  {len(kev['vulnerabilities'])} catalogue entries")
        except LookupFailed as err:
            kev = err
            print(f"  KEV  LOOKUP FAILED: {err}")
        ids = sorted({c.id for v in nvd.values() if not isinstance(v, Exception) for c in parse_nvd(v)})
        try:
            epss = fetcher.epss(ids) if ids else [{"data": []}]
            print(f"  EPSS {sum(len(p['data']) for p in epss)} scores for {len(ids)} CVEs")
        except LookupFailed as err:
            epss = err
            print(f"  EPSS LOOKUP FAILED: {err}")
        if args.save_snapshots:
            for c in components:
                v = nvd[c.slug]
                save_json(snap / "nvd" / f"{c.slug}.json", {"_lookup_failed": str(v)} if isinstance(v, Exception) else v)
            if not isinstance(kev, Exception):
                save_json(snap / "kev.json", kev)
            if not isinstance(epss, Exception):
                save_json(snap / "epss.json", epss)
            save_json(snap / "MANIFEST.json", {"fetched": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "nvd": NVD_URL, "kev": KEV_URL, "epss": EPSS_URL,
                                               "components": len(components), "note": "raw answers; a component whose lookup failed holds {_lookup_failed: reason}"})
        meta = {"when": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()), "mode": "live lookups"}
    else:
        nvd, kev, epss = read_snapshots(components, snap)
        try:
            fetched = load_json(snap / "MANIFEST.json")["fetched"]
        except (OSError, ValueError, KeyError):
            fetched = "unknown time"
        meta = {"when": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()), "mode": "offline, from saved responses",
                "snapshot_note": f"The saved responses were fetched {fetched}."}

    findings, results, notes = triage(components, nvd, kev, epss, exposures)
    out.mkdir(parents=True, exist_ok=True)
    report = {"meta": meta, "rule": "kev > epss > cvss > reachable > id",
              "components": [{**asdict(r.component), "cpe": r.component.cpe, "lookup": r.status, "lookup_detail": r.detail,
                              "cve_count": r.cve_count if r.status == "ok" else None, "excluded": r.excluded, "exposure": r.exposure, "exposure_detail": r.exposure_detail} for r in results],
              "notes": notes, "findings": [finding_json(f) for f in findings]}
    save_json(out / "cve_triage.json", report)
    (out / "cve_triage.md").write_text(render_markdown(findings, results, notes, meta, args.top), encoding="utf-8", newline="\n")
    failed = sum(1 for r in results if r.status == "failed")
    kev_hits = sum(1 for f in findings if f.kev is True)
    print(f"{len(findings)} findings; {kev_hits} known exploited; {failed} of {len(results)} components UNKNOWN (lookup failed)")
    for f in findings[:10]:
        print(f"  #{f.rank:<3} {f.id}  {f.component} {f.version}  cvss={f.cvss} epss={f.epss} kev={'yes' if f.kev is True else 'no' if f.kev is False else '?'}  {f.exposure}")
    print(f"wrote {out / 'cve_triage.md'} and {out / 'cve_triage.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
