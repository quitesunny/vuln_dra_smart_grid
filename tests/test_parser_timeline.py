import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
import build_pairs as BP
import nvd_parse as P
from timeline import Timeline, month_ends

PROBE = os.path.join(ROOT, "data", "raw", "_probe")


def load(cid):
    cve = json.load(open(os.path.join(PROBE, f"cves_{cid}.json"), encoding="utf8"))["vulnerabilities"][0]["cve"]
    hist = [json.load(open(os.path.join(PROBE, f"cvehistory_{cid}.json"), encoding="utf8"))]
    return cve, hist


ALL = ["CVE-2004-0230", "CVE-2005-2531", "CVE-2005-3669", "CVE-2025-5822", "CVE-2026-101990", "CVE-2026-8989"]


@pytest.fixture(scope="module")
def data():
    cves, hist = {}, {}
    for cid in ALL:
        cves[cid], hist[cid] = load(cid)
    lookup, _ = BP.build_lookup(cves)
    return cves, hist, lookup


def test_norm_vector_strips_prefix():
    assert P.norm_vector("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H") == "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
    assert P.norm_vector("AV:N/AC:L/Au:N/C:N/I:N/A:P") == "AV:N/AC:L/Au:N/C:N/I:N/A:P"
    assert P.norm_vector(None) is None
    assert P.norm_vector("") is None


def test_history_cvss_events_types_and_sources(data):
    _, hist, _ = data
    ev = P.cvss_events(hist["CVE-2025-5822"])
    assert [(e["version"], e["source"], e["action"]) for e in ev] == [
        ("3.0", "zdi-disclosures@trendmicro.com", "Added"),
        ("3.1", "nvd@nist.gov", "Added"),
    ]
    assert ev[1]["new_vector"] == "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
    assert ev[1]["created"] == "2025-09-10T14:46:51.023"


def test_history_v4_mapping(data):
    _, hist, _ = data
    ev = P.cvss_events(hist["CVE-2026-101990"])
    assert {e["version"] for e in ev} == {"4.0", "3.1"}
    assert all(e["source"] == "sirt@juniper.net" for e in ev)


def test_legacy_initial_analysis_has_no_cvss_detail(data):
    _, hist, _ = data
    assert P.cvss_events(hist["CVE-2004-0230"]) == []
    assert P.cvss_events(hist["CVE-2005-3669"]) == []
    assert P.history_change_count(hist["CVE-2005-3669"]) == 99


def test_current_metrics_nvd_primary(data):
    cves, _, _ = data
    m = P.nvd_primary(cves["CVE-2025-5822"], "3.1")
    assert m["baseScore"] == 8.8 and m["vector"] == "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
    assert P.nvd_primary(cves["CVE-2025-5822"], "3.0") is None
    assert P.nvd_primary(cves["CVE-2026-101990"], "3.1") is None
    assert P.nvd_primary(cves["CVE-2004-0230"], "2.0")["baseScore"] == 5.0


def test_pair_never_revised_kept_with_zero_diff(data):
    cves, hist, lookup = data
    pairs, excl = BP.pairs_for_cve("CVE-2025-5822", cves["CVE-2025-5822"], hist["CVE-2025-5822"], lookup)
    assert excl == []
    assert len(pairs) == 1
    p = pairs[0]
    assert (p["cvss_version"], p["first_score"], p["current_score"], p["score_diff"], p["revision_count"]) == \
           ("3.1", 8.8, 8.8, 0.0, 0)
    assert p["first_score_date"] == "2025-09-10T14:46:51.023" and p["last_revision_date"] == ""


def test_pair_only_nvd_version_compared(data):
    cves, hist, lookup = data
    pairs, _ = BP.pairs_for_cve("CVE-2026-8989", cves["CVE-2026-8989"], hist["CVE-2026-8989"], lookup)
    assert [(p["cvss_version"], p["first_score"], p["current_score"]) for p in pairs] == [("3.1", 6.8, 6.8)]


def test_legacy_cve_excluded_with_reason(data):
    cves, hist, lookup = data
    pairs, excl = BP.pairs_for_cve("CVE-2004-0230", cves["CVE-2004-0230"], hist["CVE-2004-0230"], lookup)
    assert pairs == []
    assert [(e["cvss_version"], e["reason"]) for e in excl] == [("2.0", "history_has_no_nvd_score_event")]


def test_cna_only_cve_excluded(data):
    cves, hist, lookup = data
    pairs, excl = BP.pairs_for_cve("CVE-2026-101990", cves["CVE-2026-101990"], hist["CVE-2026-101990"], lookup)
    assert pairs == []
    assert [e["reason"] for e in excl] == ["no_nvd_primary_metric_and_no_nvd_cvss_event"]


def test_score_at_before_and_after_first_nvd_score(data):
    cves, hist, lookup = data
    tl = Timeline(cves, hist, lookup)
    assert tl.score_at("CVE-2025-5822", "2025-08-31T23:59:59.999", "3.1")["state"] == "not_yet_scored"
    r = tl.score_at("CVE-2025-5822", "2025-09-30T23:59:59.999", "3.1")
    assert (r["state"], r["score"], r["source"]) == ("scored", 8.8, "nvd@nist.gov")
    assert tl.score_at("CVE-2025-5822", "2025-09-10T14:46:51.022", "3.1")["state"] == "not_yet_scored"
    assert tl.score_at("CVE-2025-5822", "2025-09-10T14:46:51.023", "3.1")["state"] == "scored"


def test_score_at_ignores_non_nvd_source(data):
    cves, hist, lookup = data
    tl = Timeline(cves, hist, lookup)
    assert tl.score_at("CVE-2025-5822", "2026-01-31T23:59:59", "3.0")["state"] == "no_nvd_events"
    assert tl.score_at("CVE-2026-101990", "2026-10-31T23:59:59", "3.1")["state"] == "no_nvd_events"


def test_score_at_final_state_matches_current(data):
    cves, hist, lookup = data
    tl = Timeline(cves, hist, lookup)
    for cid, v in [("CVE-2025-5822", "3.1"), ("CVE-2026-8989", "3.1")]:
        r = tl.score_at(cid, "9999-12-31T23:59:59", v)
        cur = P.nvd_primary(cves[cid], v)
        assert r["vector"] == cur["vector"] and r["score"] == cur["baseScore"]


def test_month_ends_window():
    m = month_ends("2024-11-13", "2026-11-13")
    assert m[0].isoformat() == "2024-11-30" and m[-1].isoformat() == "2026-10-31" and len(m) == 24
