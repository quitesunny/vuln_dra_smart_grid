import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
import build_pairs as BP
import nvd_parse as P
from timeline import Timeline

RAW = os.path.join(ROOT, "data", "raw", "2026-11-13")
CASES = ["CVE-2017-6770", "CVE-2016-1261", "CVE-2014-6447", "CVE-2016-1285"]

pytestmark = pytest.mark.skipif(not os.path.isdir(os.path.join(RAW, "cves_pages")), reason="ham veri yok")


@pytest.fixture(scope="module")
def raw():
    cves = {}
    for fn in os.listdir(os.path.join(RAW, "cves_pages")):
        for v in json.loads(open(os.path.join(RAW, "cves_pages", fn), "rb").read())["vulnerabilities"]:
            cves.setdefault(v["cve"]["id"], v["cve"])
    hist = {}
    for cid in CASES:
        hist[cid] = [json.loads(open(os.path.join(RAW, "cvehistory", f"{cid}__start00000.json"), "rb").read())]
    lookup, _ = BP.build_lookup(cves)
    return cves, hist, lookup


def test_prefix_and_nvd_flag(raw):
    _, hist, _ = raw
    ev = P.cvss_events(hist["CVE-2016-1261"])
    jun = [e for e in ev if e["source"] == "sirt@juniper.net"]
    assert len(jun) == 1 and jun[0]["value_prefix"] == "Juniper Networks, Inc." and jun[0]["is_nvd"] is False
    assert jun[0]["new_vector"] == "AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H"
    nvd = [e for e in ev if e["is_nvd"]]
    assert [(e["version"], e["new_vector"]) for e in nvd] == [
        ("2.0", "AV:N/AC:M/Au:N/C:P/I:P/A:P"), ("3.0", "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H")]


def test_nist_parenthesis_format_and_metadata_ignored(raw):
    _, hist, _ = raw
    ev = P.cvss_events(hist["CVE-2014-6447"])
    assert [e["type"] for e in ev] == ["CVSS V2", "CVSS V3.1"]
    assert ev[0]["value_prefix"] == "NIST" and ev[0]["is_nvd"] is True
    assert ev[0]["new_vector"] == "AV:N/AC:M/Au:N/C:N/I:P/A:P"


def test_revised_v2_pair_uses_raw_lookup(raw):
    cves, hist, lookup = raw
    pairs, excl = BP.pairs_for_cve("CVE-2017-6770", cves["CVE-2017-6770"], hist["CVE-2017-6770"], lookup)
    p2 = [p for p in pairs if p["cvss_version"] == "2.0"][0]
    assert p2["first_vector"] == "AV:N/AC:M/Au:N/C:P/I:P/A:P"
    assert p2["first_score_date"] == "2017-08-15T16:14:44.990"
    assert p2["first_score"] == 6.8 and p2["first_score_source"] == "raw_lookup"
    assert p2["current_score"] == 4.0 and p2["score_diff"] == -2.8
    assert p2["revision_count"] == 2 and p2["last_revision_date"] == "2021-12-21T12:53:52.767"
    p31 = [p for p in pairs if p["cvss_version"] == "3.1"][0]
    assert (p31["first_score"], p31["current_score"], p31["revision_count"]) == (4.2, 4.2, 0)
    assert [(e["cvss_version"], e["reason"]) for e in excl] == [("3.0", "no_current_nvd_primary_for_version")]


def test_v30_removed_v31_added_not_mixed(raw):
    cves, hist, lookup = raw
    pairs, excl = BP.pairs_for_cve("CVE-2016-1285", cves["CVE-2016-1285"], hist["CVE-2016-1285"], lookup)
    assert [(e["cvss_version"], e["reason"]) for e in excl] == [("3.0", "no_current_nvd_primary_for_version")]
    p31 = [p for p in pairs if p["cvss_version"] == "3.1"][0]
    assert p31["first_score_date"] == "2023-11-30T17:08:17.480" and p31["current_score"] == 6.8
    assert p31["revision_count"] == 0


def test_cna_metric_not_used_as_nvd(raw):
    cves, hist, lookup = raw
    pairs, _ = BP.pairs_for_cve("CVE-2016-1261", cves["CVE-2016-1261"], hist["CVE-2016-1261"], lookup)
    p30 = [p for p in pairs if p["cvss_version"] == "3.0"][0]
    assert (p30["first_score"], p30["current_score"], p30["revision_count"]) == (8.8, 8.8, 0)


def test_score_at_reconstructs_changes_and_same_event_remove_add(raw):
    cves, hist, lookup = raw
    tl = Timeline(cves, hist, lookup)
    cid = "CVE-2017-6770"
    assert tl.score_at(cid, "2017-08-20T00:00:00", "2.0")["vector"] == "AV:N/AC:M/Au:N/C:P/I:P/A:P"
    assert tl.score_at(cid, "2019-01-31T23:59:59", "2.0")["vector"] == "AV:A/AC:M/Au:N/C:N/I:P/A:P"
    r = tl.score_at(cid, "2022-01-31T23:59:59", "2.0")
    assert (r["state"], r["vector"], r["score"]) == ("scored", "AV:N/AC:H/Au:N/C:P/I:P/A:N", 4.0)
    assert tl.score_at(cid, "2022-01-31T23:59:59", "3.0")["state"] == "removed"
    assert tl.score_at(cid, "2021-12-01T00:00:00", "3.1")["state"] == "not_yet_scored"
