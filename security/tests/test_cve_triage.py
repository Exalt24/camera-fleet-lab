"""Tests for security/vuln/cve_triage.py: parsing of saved real NVD, KEV and EPSS answers, the ranking rule (ties included), the exposure
rule against the real compose file, and the failure paths: a failed lookup is UNKNOWN and never clean, a garbled answer does not crash.

The fixtures in tests/fixtures/vuln/ are real answers from the live run of 2026-11-15 (copied from security/vuln/snapshots/): the NVD answers
for Python 3.13.18, Alpine 3.20.10 and the first three MariaDB 11.8.9 CVEs, an excerpt of the CISA KEV catalogue (its header, four entries and the
one OpenSSH entry that NVD ties to Alpine), and the whole FIRST EPSS answer for the 59 CVEs of that run.

The module under test is loaded from CVE_TRIAGE_PATH when set, so run_mutations.py can run these same tests against a copy with one
behaviour removed and require a red run.
    python -m pytest security/tests/test_cve_triage.py -q
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
FIX = HERE / "fixtures" / "vuln"
TARGET = Path(os.environ.get("CVE_TRIAGE_PATH") or ROOT / "security" / "vuln" / "cve_triage.py")

spec = importlib.util.spec_from_file_location("cve_triage_under_test", TARGET)
ct = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = ct
spec.loader.exec_module(ct)


def fx(name):
    return json.loads((FIX / name).read_text(encoding="utf-8"))


def finding(id, cvss=None, epss=None, kev=False, exposure="internal"):
    return ct.Finding(id, "c", "1", ["s"], cvss, "3.1" if cvss is not None else None, None, epss, None, kev, exposure, None, "r")


def ids(findings):
    return [f.id for f in ct.rank(findings)]


COMP = ct.Component("Python", "3.13.18", "python", "python", ["hub"], "test")
ALPINE = ct.Component("Alpine Linux", "3.20.10", "alpinelinux", "alpine_linux", ["edge"], "test", part="o")
MARIADB = ct.Component("MariaDB", "11.8.9", "mariadb", "mariadb", ["mariadb"], "test")
PY_DOC = "nvd_python_3.13.18.json"
EXPOSURES = {"hub": {"reachable": True, "detail": "publishes 127.0.0.1:8100:8000"}, "mariadb": {"reachable": False, "detail": "none"}}


# ---- parsing real answers -------------------------------------------------------------------------------------------
def test_parse_real_nvd_answer_gives_ids_scores_and_dates():
    cves = {c.id: c for c in ct.parse_nvd(fx(PY_DOC))}
    assert set(cves) == {"CVE-2026-3087", "CVE-2020-29396", "CVE-2021-32052"}
    c = cves["CVE-2026-3087"]
    assert c.cvss == 7.5 and c.cvss_version == "3.1" and c.published.startswith("2026")
    assert "unpack_archive" in c.summary


def test_the_real_nvd_answers_split_into_a_finding_and_two_platform_matches():
    by = {c.id: ct.applicability(c, COMP) for c in ct.parse_nvd(fx(PY_DOC))}
    assert by == {"CVE-2026-3087": "vulnerable", "CVE-2020-29396": "platform", "CVE-2021-32052": "platform"}


def test_the_boundary_release_is_outside_the_range_but_the_release_before_it_is_not():
    cves = ct.parse_nvd(fx("nvd_mariadb_excerpt.json"))
    assert {ct.applicability(c, MARIADB) for c in cves} == {"outside-range"}            # 11.8.9 is the first fixed release
    older = ct.Component("MariaDB", "11.8.8", "mariadb", "mariadb", ["mariadb"], "test")
    assert {ct.applicability(c, older) for c in cves} == {"vulnerable"}
    assert {ct.fixed_version(c, older) for c in cves} == {"11.8.9"}
    assert ct.fixed_version(cves[0], ct.Component("MariaDB", "10.6.5", "mariadb", "mariadb", ["mariadb"], "test")) == "10.6.28"


def test_parse_real_kev_answer_reads_the_known_exploited_entries():
    kev = ct.parse_kev(fx("kev_excerpt.json"))
    assert len(kev) >= 3
    first = next(iter(kev.values()))
    assert first["date_added"] and "ransomware" in first


def test_the_known_exploited_openssh_cve_that_nvd_ties_to_alpine_is_a_platform_match_not_a_finding():
    findings, results, _ = ct.triage([ALPINE], {ALPINE.slug: fx("nvd_alpine_3.20.10.json")}, fx("kev_excerpt.json"), fx("epss_real.json"), EXPOSURES)
    assert findings == []
    ex = results[0].excluded
    assert [(e["id"], e["reason"], e["kev"]) for e in ex] == [("CVE-2026-123158", "platform", True)]
    md = ct.render_markdown(findings, results, {"kev": "", "epss": ""}, {"when": "t", "mode": "m"})
    assert "Matched only as a platform" in md and "CVE-2026-123158" in md


def test_a_real_range_boundary_cve_set_is_listed_apart_not_ranked():
    findings, results, _ = ct.triage([MARIADB], {MARIADB.slug: fx("nvd_mariadb_excerpt.json")}, fx("kev_excerpt.json"), fx("epss_real.json"), EXPOSURES)
    assert findings == [] and len(results[0].excluded) == 3 and {e["reason"] for e in results[0].excluded} == {"outside-range"}


def test_parse_real_epss_answer_gives_a_probability_and_a_percentile():
    epss = ct.parse_epss(fx("epss_real.json"))
    assert epss and all(0.0 <= e <= 1.0 and 0.0 <= p <= 1.0 for e, p in epss.values())


# ---- garbled answers never crash and never read as "nothing found" ----------------------------------------------------
@pytest.mark.parametrize("bad", [None, "text", [], {}, {"vulnerabilities": "x", "totalResults": 1}, {"vulnerabilities": [], "totalResults": "many"}])
def test_a_garbled_nvd_answer_raises_a_parse_error_not_a_crash(bad):
    with pytest.raises(ct.ParseError):
        ct.parse_nvd(bad)


@pytest.mark.parametrize("bad", [None, "x", {"data": "no"}, {}])
def test_garbled_kev_and_epss_answers_raise_parse_errors(bad):
    with pytest.raises(ct.ParseError):
        ct.parse_kev(bad)
    with pytest.raises(ct.ParseError):
        ct.parse_epss(bad)


def test_odd_items_inside_a_good_nvd_answer_are_skipped_not_fatal():
    doc = {"totalResults": 3, "vulnerabilities": ["junk", {"cve": {"id": "not-a-cve"}}, {"cve": {"id": "CVE-2020-0001", "descriptions": [], "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": "high"}}]}}}]}
    cves = ct.parse_nvd(doc)
    assert [c.id for c in cves] == ["CVE-2020-0001"] and cves[0].cvss is None


def test_an_epss_row_that_is_not_a_number_is_skipped():
    epss = ct.parse_epss({"data": [{"cve": "CVE-2020-1", "epss": "n/a", "percentile": "0.5"}, {"cve": "CVE-2020-2", "epss": "0.5", "percentile": "0.9"}]})
    assert list(epss) == ["CVE-2020-2"]


def test_a_garbled_answer_for_one_component_makes_that_component_unknown_and_leaves_the_others():
    good = fx(PY_DOC)
    other = ct.Component("Uvicorn", "0.54.0", "encode", "uvicorn", ["hub"], "test")
    findings, results, _ = ct.triage([COMP, other], {COMP.slug: good, other.slug: {"nonsense": True}}, fx("kev_excerpt.json"), fx("epss_real.json"), EXPOSURES)
    status = {r.component.name: r.status for r in results}
    assert status == {"Python": "ok", "Uvicorn": "failed"}
    assert findings and all(f.component == "Python" for f in findings)


# ---- a failed lookup is UNKNOWN, never clean -------------------------------------------------------------------------
def test_the_real_python_answer_gives_one_finding_with_its_epss_and_exposure():
    findings, _, _ = ct.triage([COMP], {COMP.slug: fx(PY_DOC)}, fx("kev_excerpt.json"), fx("epss_real.json"), EXPOSURES)
    assert [f.id for f in findings] == ["CVE-2026-3087"]
    f = findings[0]
    assert f.cvss == 7.5 and f.epss is not None and 0 < f.epss < 1 and f.kev is False and f.exposure == "reachable" and f.rank == 1


def test_a_failed_nvd_lookup_is_reported_unknown_not_as_zero_cves():
    findings, results, _ = ct.triage([COMP], {COMP.slug: ct.LookupFailed("HTTP 503 from NVD")}, fx("kev_excerpt.json"), fx("epss_real.json"), EXPOSURES)
    assert findings == []
    assert results[0].status == "failed" and "503" in results[0].detail and results[0].cve_count == 0
    md = ct.render_markdown(findings, results, {"kev": "", "epss": ""}, {"when": "t", "mode": "m"})
    assert "UNKNOWN: HTTP 503 from NVD" in md and "not known" in md and "It is not a clean result" in md


def test_a_component_with_no_recorded_answer_is_unknown_too():
    _, results, _ = ct.triage([COMP], {}, fx("kev_excerpt.json"), fx("epss_real.json"), EXPOSURES)
    assert results[0].status == "failed"


def test_a_failed_kev_lookup_leaves_kev_unknown_on_every_finding():
    findings, _, notes = ct.triage([COMP], {COMP.slug: fx(PY_DOC)}, ct.LookupFailed("HTTP 403"), fx("epss_real.json"), EXPOSURES)
    assert findings and all(f.kev is None for f in findings)
    assert "KEV catalogue lookup failed" in notes["kev"]
    assert all(ct.finding_json(f)["kev"] == "unknown" for f in findings)
    md = ct.render_markdown(findings, [], notes, {"when": "t", "mode": "m"})
    assert "read `unknown`, not `no`" in md


def test_a_failed_epss_lookup_leaves_epss_empty_not_zero():
    findings, _, notes = ct.triage([COMP], {COMP.slug: fx(PY_DOC)}, fx("kev_excerpt.json"), ct.LookupFailed("HTTP 429"), EXPOSURES)
    assert findings and all(f.epss is None for f in findings)
    assert "EPSS lookup failed" in notes["epss"]


def test_a_successful_lookup_with_no_cves_is_clean_and_says_so():
    empty = {"totalResults": 0, "vulnerabilities": []}
    findings, results, _ = ct.triage([COMP], {COMP.slug: empty}, fx("kev_excerpt.json"), fx("epss_real.json"), EXPOSURES)
    assert findings == [] and results[0].status == "ok" and results[0].cve_count == 0


# ---- the ranking rule ------------------------------------------------------------------------------------------------
def test_known_exploited_outranks_every_other_field():
    f = [finding("CVE-2020-0001", cvss=10.0, epss=0.99, kev=False, exposure="reachable"), finding("CVE-2020-0002", cvss=1.0, epss=0.0001, kev=True, exposure="internal")]
    assert ids(f) == ["CVE-2020-0002", "CVE-2020-0001"]


def test_epss_outranks_cvss():
    f = [finding("CVE-2020-0001", cvss=9.8, epss=0.01), finding("CVE-2020-0002", cvss=5.0, epss=0.50)]
    assert ids(f) == ["CVE-2020-0002", "CVE-2020-0001"]


def test_cvss_outranks_exposure_when_epss_ties():
    f = [finding("CVE-2020-0001", cvss=5.0, epss=0.2, exposure="reachable"), finding("CVE-2020-0002", cvss=7.0, epss=0.2, exposure="internal")]
    assert ids(f) == ["CVE-2020-0002", "CVE-2020-0001"]


def test_reachable_breaks_a_tie_on_everything_else():
    f = [finding("CVE-2020-0001", cvss=7.0, epss=0.2, exposure="internal"), finding("CVE-2020-0002", cvss=7.0, epss=0.2, exposure="reachable")]
    assert ids(f) == ["CVE-2020-0002", "CVE-2020-0001"]


def test_a_full_tie_is_broken_by_id_whatever_the_input_order():
    a, b, c = (lambda: finding("CVE-2020-0003", 5.0, 0.1), lambda: finding("CVE-2020-0001", 5.0, 0.1), lambda: finding("CVE-2020-0002", 5.0, 0.1))
    assert ids([a(), b(), c()]) == ids([c(), a(), b()]) == ["CVE-2020-0001", "CVE-2020-0002", "CVE-2020-0003"]


def test_two_known_exploited_findings_are_ordered_by_epss_then_cvss():
    f = [finding("CVE-2020-0001", cvss=9.0, epss=0.1, kev=True), finding("CVE-2020-0002", cvss=5.0, epss=0.9, kev=True), finding("CVE-2020-0003", cvss=9.9, epss=0.1, kev=True)]
    assert ids(f) == ["CVE-2020-0002", "CVE-2020-0003", "CVE-2020-0001"]


def test_a_missing_epss_or_cvss_sorts_after_a_present_one():
    f = [finding("CVE-2020-0001", cvss=9.0, epss=None), finding("CVE-2020-0002", cvss=1.0, epss=0.0001)]
    assert ids(f) == ["CVE-2020-0002", "CVE-2020-0001"]
    g = [finding("CVE-2020-0001", cvss=None, epss=0.2), finding("CVE-2020-0002", cvss=0.1, epss=0.2)]
    assert ids(g) == ["CVE-2020-0002", "CVE-2020-0001"]


def test_unknown_kev_ranks_between_known_exploited_and_not_exploited():
    f = [finding("CVE-2020-0001", 9.0, 0.9, kev=False), finding("CVE-2020-0002", 5.0, 0.1, kev=None), finding("CVE-2020-0003", 1.0, 0.01, kev=True)]
    assert ids(f) == ["CVE-2020-0003", "CVE-2020-0002", "CVE-2020-0001"]


def test_ranks_are_numbered_from_one_in_order():
    ranked = ct.rank([finding("CVE-2020-0002", 5.0), finding("CVE-2020-0001", 9.0)])
    assert [f.rank for f in ranked] == [1, 2]


# ---- exposure from the real compose file -----------------------------------------------------------------------------
def test_exposure_follows_the_published_ports_in_the_real_compose_file():
    exp = ct.service_exposure(ct.load_compose(ROOT / "docker-compose.yml"))
    for reachable in ("hub", "keycloak", "oauth2-proxy"):
        assert exp[reachable]["reachable"] is True, reachable
    for internal in ("mariadb", "camera", "edge", "wazuh", "fleet-exporter"):
        assert exp[internal]["reachable"] is False, internal


def test_a_service_sharing_a_reachable_services_network_is_reachable():
    compose = {"services": {"a": {"ports": ["127.0.0.1:1:1"]}, "b": {"network_mode": "service:a"}, "c": {"network_mode": "service:d"}, "d": {}}}
    exp = ct.service_exposure(compose)
    assert exp["b"]["reachable"] is True and exp["c"]["reachable"] is False


def test_a_component_is_reachable_when_any_of_its_services_is():
    comp = ct.Component("X", "1", "v", "p", ["mariadb", "hub"], "t")
    assert ct.component_exposure(comp, EXPOSURES)[0] == "reachable"
    assert ct.component_exposure(ct.Component("X", "1", "v", "p", ["mariadb"], "t"), EXPOSURES)[0] == "internal"


def test_the_findings_carry_the_components_exposure():
    findings, _, _ = ct.triage([COMP], {COMP.slug: fx(PY_DOC)}, fx("kev_excerpt.json"), fx("epss_real.json"), EXPOSURES)
    assert findings and {f.exposure for f in findings} == {"reachable"}


# ---- remediation and the version logic -------------------------------------------------------------------------------
def test_versions_compare_as_numbers_not_text():
    assert ct.vkey("0.9") < ct.vkey("0.10") and ct.vkey("1.0.20210914-1.1") == (1, 0, 20210914) and ct.vkey("none") is None


def test_clean_version_strips_the_v_the_epoch_and_the_distro_suffix():
    assert ct.clean_version("v7.15.6") == "7.15.6" and ct.clean_version("2:1.2.3+dfsg-1") == "1.2.3" and ct.clean_version("1.0.20210914-1.1") == "1.0.20210914"


FASTAPI = ct.Component("FastAPI", "0.65.0", "tiangolo", "fastapi", ["hub"], "t")


def _cve_with(matches):
    return ct.Cve("CVE-2020-0001", "", "2020-01-01", 5.0, "3.1", "MEDIUM", [{"nodes": [{"cpeMatch": matches}]}])


def test_fixed_version_is_the_smallest_end_excluding_above_the_installed_version():
    m = lambda end, **kw: {"vulnerable": True, "criteria": "cpe:2.3:a:tiangolo:fastapi:*:*:*:*:*:*:*:*", "versionEndExcluding": end, **kw}
    assert ct.fixed_version(_cve_with([m("0.70.0"), m("0.65.2")]), FASTAPI) == "0.65.2"


def test_a_date_is_never_named_as_the_fixed_version():
    # seen in the real FFmpeg answers: a range ended by 2025-01-13, which is not a release
    m = {"vulnerable": True, "criteria": "cpe:2.3:a:tiangolo:fastapi:*:*:*:*:*:*:*:*", "versionEndExcluding": "2025-01-13"}
    assert ct.fixed_version(_cve_with([m]), FASTAPI) is None


def test_fixed_version_ignores_other_products_and_ranges_that_do_not_contain_the_version():
    other = {"vulnerable": True, "criteria": "cpe:2.3:a:someone:else:*:*:*:*:*:*:*:*", "versionEndExcluding": "9.9"}
    before = {"vulnerable": True, "criteria": "cpe:2.3:a:tiangolo:fastapi:*:*:*:*:*:*:*:*", "versionStartIncluding": "0.70.0", "versionEndExcluding": "0.80.0"}
    behind = {"vulnerable": True, "criteria": "cpe:2.3:a:tiangolo:fastapi:*:*:*:*:*:*:*:*", "versionEndExcluding": "0.60.0"}
    not_vuln = {"vulnerable": False, "criteria": "cpe:2.3:a:tiangolo:fastapi:*:*:*:*:*:*:*:*", "versionEndExcluding": "0.66.0"}
    assert ct.fixed_version(_cve_with([other, before, behind, not_vuln]), FASTAPI) is None


def test_remediation_names_the_fixed_version_or_says_there_is_none():
    assert "to 0.65.2 or later" in ct.remediation_text(FASTAPI, "0.65.2", False)
    text = ct.remediation_text(FASTAPI, None, True)
    assert "no fixed version is named" in text and "known exploited" in text


# ---- live lookups: rate limit, retries, pagination ---------------------------------------------------------------------
def test_the_nvd_rate_limiter_keeps_requests_apart():
    now = [0.0]
    sleeps = []
    lim = ct.RateLimiter(6.5, clock=lambda: now[0], sleep=lambda s: (sleeps.append(s), now.__setitem__(0, now[0] + s)))
    for _ in range(4):
        lim.wait()
        now[0] += 0.5                      # the request itself takes half a second
    assert len(sleeps) == 3 and all(abs(s - 6.0) < 1e-9 for s in sleeps)
    assert ct.NVD_MIN_INTERVAL_S >= 6.0    # 5 requests per 30 s is one every 6 s


def _fetcher(get, sleeps=None):
    return ct.Fetcher(get=get, limiter=ct.RateLimiter(0, clock=lambda: 0.0, sleep=lambda s: None), sleep=(sleeps.append if sleeps is not None else (lambda s: None)), retries=3)


def test_a_503_is_retried_and_a_later_good_answer_is_used():
    calls = []

    def get(url, params=None):
        calls.append(url)
        if url == ct.CPE_URL:
            return {"totalResults": 5}
        if sum(1 for u in calls if u == ct.NVD_URL) < 2:
            raise ct.LookupFailed("HTTP 503")
        return {"totalResults": 0, "vulnerabilities": []}
    doc = _fetcher(get).nvd(COMP)
    assert doc["vulnerabilities"] == [] and calls.count(ct.NVD_URL) == 2


def test_giving_up_after_the_retries_raises_lookup_failed_with_the_reason():
    def get(url, params=None):
        raise ct.LookupFailed("HTTP 503")
    sleeps = []
    with pytest.raises(ct.LookupFailed, match="gave up after 3 attempts"):
        _fetcher(get, sleeps).nvd(COMP)
    assert len(sleeps) == 2                 # waited between the attempts, not after the last


def test_a_product_the_dictionary_does_not_know_is_a_lookup_failure_not_zero_cves():
    def get(url, params=None):
        return {"totalResults": 0} if url == ct.CPE_URL else pytest.fail("the CVE search ran for a product with no CPE")
    with pytest.raises(ct.LookupFailed, match="no CPE product"):
        _fetcher(get).nvd(COMP)


def test_nvd_pages_are_merged():
    v = lambda i: {"cve": {"id": f"CVE-2020-{i:04d}", "descriptions": [], "metrics": {}}}

    def get(url, params=None):
        if url == ct.CPE_URL:
            return {"totalResults": 1}
        start = params["startIndex"]
        return {"totalResults": 3, "vulnerabilities": [v(1), v(2)] if start == 0 else [v(3)]}
    doc = _fetcher(get).nvd(COMP)
    assert [x["cve"]["id"] for x in doc["vulnerabilities"]] == ["CVE-2020-0001", "CVE-2020-0002", "CVE-2020-0003"]


def test_the_nvd_query_asks_for_exactly_the_installed_version():
    seen = {}

    def get(url, params=None):
        if url == ct.CPE_URL:
            return {"totalResults": 1}
        seen.update(params)
        return {"totalResults": 0, "vulnerabilities": []}
    _fetcher(get).nvd(COMP)
    assert seen["virtualMatchString"] == "cpe:2.3:a:python:python" and seen["versionStart"] == seen["versionEnd"] == "3.13.18"


# ---- the inventory and the whole offline run -------------------------------------------------------------------------
def test_the_inventory_comes_from_the_compose_file_and_the_pinned_requirements():
    resolved = {"python:python:3.13-slim": "3.13.9", "image:mariadb:11": "11.8.3", "image:bluenviron/mediamtx:latest-ffmpeg": "1.15.0"}
    comps = {c.name: c for c in ct.build_inventory(ROOT, resolved)}
    # read from the file so a routine fastapi bump does not break this test
    fastapi_pin = next(l.split("==")[1].split()[0] for l in (ROOT / "hub" / "requirements.txt").read_text(encoding="utf-8").splitlines() if l.startswith("fastapi=="))
    assert comps["Wazuh manager"].version == "4.14.10" and comps["Keycloak"].version == "26.8.2" and comps["oauth2-proxy"].version == "7.15.6"
    assert comps["FastAPI"].version == fastapi_pin and comps["Uvicorn"].version == "0.54.0" and comps["aiomysql"].version == "0.3.2"
    assert comps["MariaDB"].version == "11.8.3" and comps["Python"].version == "3.13.9"
    assert comps["oauth2-proxy"].cpe == "cpe:2.3:a:oauth2_proxy_project:oauth2_proxy:7.15.6:*:*:*:*:*:*:*"
    assert comps["FastAPI"].cpe == f"cpe:2.3:a:tiangolo:fastapi:{fastapi_pin}:*:*:*:*:*:*:*"


def test_requirements_pins_are_read_and_ranges_are_not_treated_as_pins(tmp_path):
    f = tmp_path / "r.txt"
    f.write_text("fastapi==0.162.0\nsqlalchemy[asyncio]>=2.1.8,<2.2\npytest==9.2.0  # test\n", encoding="utf-8")
    assert ct.parse_requirements(f) == {"fastapi": "0.162.0", "pytest": "9.2.0"}


def test_the_offline_run_writes_a_report_with_every_field_for_each_finding(tmp_path):
    snap = tmp_path / "snap"
    (snap / "nvd").mkdir(parents=True)
    comps = ct.build_inventory(ROOT, {"python:python:3.13-slim": "3.13.18"})
    (snap / "image_versions.json").write_text(json.dumps({"python:python:3.13-slim": "3.13.18"}), encoding="utf-8")
    py = next(c for c in comps if c.name == "Python")
    (snap / "nvd" / f"{py.slug}.json").write_text(json.dumps(fx(PY_DOC)), encoding="utf-8")
    (snap / "kev.json").write_text(json.dumps(fx("kev_excerpt.json")), encoding="utf-8")
    (snap / "epss.json").write_text(json.dumps(fx("epss_real.json")), encoding="utf-8")
    out = tmp_path / "out"
    assert ct.main(["--offline", "--snapshots", str(snap), "--out", str(out), "--compose-root", str(ROOT)]) == 0
    report = json.loads((out / "cve_triage.json").read_text(encoding="utf-8"))
    assert report["findings"]
    for f in report["findings"]:
        assert {"id", "component", "version", "cvss", "epss", "kev", "exposure", "remediation"} <= set(f)
        assert f["kev"] in ("yes", "no", "unknown") and f["exposure"] in ("reachable", "internal")
    # every component but Python had no saved answer, so each one is UNKNOWN in the report rather than missing
    unknown = [c for c in report["components"] if c["lookup"] == "failed"]
    assert len(unknown) == len(report["components"]) - 1
    assert "UNKNOWN" in (out / "cve_triage.md").read_text(encoding="utf-8")
