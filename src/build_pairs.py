import csv
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(__file__))
import nvd_parse as P
import rawdata

ROOT = rawdata.ROOT
PROC = os.path.join(ROOT, "data", "processed")
FETCH_DATE = os.environ.get("FETCH_DATE", "2026-11-13")
VERSIONS = ["2.0", "3.0", "3.1", "4.0"]


def build_lookup(cves):
    lk, conflicts = {}, defaultdict(set)
    for cve in cves.values():
        for m in P.current_metrics(cve):
            if m["vector"] is None or m["baseScore"] is None:
                continue
            k = (m["version"], m["vector"])
            if k in lk and lk[k] != m["baseScore"]:
                conflicts[k] |= {lk[k], m["baseScore"]}
            lk.setdefault(k, m["baseScore"])
    for k in conflicts:
        lk.pop(k, None)
    return lk, conflicts


def pairs_for_cve(cid, cve, hist_pages, lookup):
    pairs, excl = [], []
    events = P.cvss_events(hist_pages) if hist_pages else []
    unk = [e for e in events if e["version"] is None]
    for e in unk:
        excl.append({"cve_id": cid, "cvss_version": "", "reason": "unknown_cvss_type_in_history",
                     "detail": e["type"]})
    any_nvd = False
    for v in VERSIONS:
        ev = [e for e in events if e["version"] == v and e["is_nvd"]]
        cur = P.nvd_primary(cve, v)
        if not ev and not cur:
            continue
        any_nvd = True
        if cur is None:
            sec = [m for m in P.current_metrics(cve) if m["version"] == v and m["source"] == P.NVD_SOURCE]
            if sec:
                excl.append({"cve_id": cid, "cvss_version": v, "reason": "current_nvd_metric_type_is_" + str(sec[0]["type"]),
                             "detail": f"güncel kayıtta nvd@nist.gov {v} metriği type={sec[0]['type']} (Primary değil); "
                                       f"history NVD olay sayısı={len(ev)}"})
                continue
            excl.append({"cve_id": cid, "cvss_version": v, "reason": "no_current_nvd_primary_for_version",
                         "detail": f"history NVD olay sayısı={len(ev)}; son eylem={ev[-1]['action']}"})
            continue
        if not ev:
            other = sorted({e["type"] for e in events if e["is_nvd"] and e["version"] != v and e["version"][0] == v[0]})
            if other:
                excl.append({"cve_id": cid, "cvss_version": v, "reason": "history_nvd_events_only_under_other_label",
                             "detail": f"güncel NVD Primary {v}; history'de NVD olayları yalnızca {other} tipinde (sürümler karıştırılmadı)"})
                continue
            excl.append({"cve_id": cid, "cvss_version": v, "reason": "history_has_no_nvd_score_event",
                         "detail": "güncel NVD Primary metriği var ama change history'de bu sürüm için NVD CVSS olayı yok; ilk skor belirlenemiyor"})
            continue
        e0 = ev[0]
        if e0["action"] == "Added":
            first_vec, first_date, basis = e0["new_vector"], e0["created"], "added_event"
            rest = [e for e in ev if e["cveChangeId"] != e0["cveChangeId"]]
        else:
            first_vec, first_date, basis = e0["old_vector"], "", "old_value_of_first_event"
            rest = ev
        revs = []
        for e in rest:
            if not revs or revs[-1]["cveChangeId"] != e["cveChangeId"]:
                revs.append(e)
        if first_vec is None:
            excl.append({"cve_id": cid, "cvss_version": v, "reason": "first_vector_unparseable",
                         "detail": repr(e0["new_raw"] if e0["action"] == "Added" else e0["old_raw"])[:200]})
            continue
        if first_vec == cur["vector"]:
            first_score, score_src = cur["baseScore"], "current_record_same_vector"
        elif (v, first_vec) in lookup:
            first_score, score_src = lookup[(v, first_vec)], "raw_lookup"
        else:
            excl.append({"cve_id": cid, "cvss_version": v, "reason": "first_vector_score_not_in_raw_lookup",
                         "detail": first_vec})
            continue
        pairs.append({
            "cve_id": cid, "cvss_version": v, "source": P.NVD_SOURCE, "source_type": "Primary",
            "first_vector": first_vec, "first_score": first_score, "first_score_source": score_src,
            "first_basis": basis, "first_score_date": first_date or "",
            "current_vector": cur["vector"], "current_score": cur["baseScore"],
            "score_diff": round(cur["baseScore"] - first_score, 1),
            "revision_count": len(revs), "last_revision_date": revs[-1]["created"] if revs else "",
            "published": cve.get("published", ""), "vuln_status": cve.get("vulnStatus", ""),
        })
    if not any_nvd:
        excl.append({"cve_id": cid, "cvss_version": "", "reason": "no_nvd_primary_metric_and_no_nvd_cvss_event",
                     "detail": "metrik kaynakları: " + ";".join(sorted({f"{m['source']}/{m['type']}/{m['version']}"
                                                                         for m in P.current_metrics(cve)})) or "yok"})
    return pairs, excl


def main():
    D = rawdata.load(FETCH_DATE)
    os.makedirs(PROC, exist_ok=True)
    all_ids = sorted({c for v in D["dev_cves"].values() for c in v})
    lookup, conflicts = build_lookup(D["cves"])
    pairs, excl = [], []
    for cid in all_ids:
        if cid not in D["cves"]:
            excl.append({"cve_id": cid, "cvss_version": "", "reason": "missing_cve_record", "detail": ""})
            continue
        if cid in D["hist_404"] or cid not in D["hist"]:
            excl.append({"cve_id": cid, "cvss_version": "", "reason": "history_not_available", "detail": "cvehistory 404 ya da dosya yok"})
            continue
        p, e = pairs_for_cve(cid, D["cves"][cid], D["hist"][cid], lookup)
        pairs += p
        excl += e

    def wcsv(name, rows, fields):
        with open(os.path.join(PROC, name), "w", newline="", encoding="utf8") as f:
            w = csv.DictWriter(f, fieldnames=fields)
            w.writeheader()
            w.writerows(rows)

    wcsv("cve_pairs.csv", pairs, ["cve_id", "cvss_version", "source", "source_type", "first_vector", "first_score",
                                  "first_score_source", "first_basis", "first_score_date", "current_vector",
                                  "current_score", "score_diff", "revision_count", "last_revision_date",
                                  "published", "vuln_status"])
    wcsv("excluded.csv", excl, ["cve_id", "cvss_version", "reason", "detail"])
    rows = []
    for dev, m in D["dev_match"].items():
        for cid in D["dev_cves"][dev]:
            for crit, vul in sorted(set(m[cid])):
                rows.append({"cve_id": cid, "device_id": dev, "vulnerable": str(vul).lower(), "matched_criteria": crit})
    wcsv("cve_device_map.csv", rows, ["cve_id", "device_id", "vulnerable", "matched_criteria"])
    wcsv("vector_score_lookup_conflicts.csv",
         [{"cvss_version": k[0], "vector": k[1], "scores": ";".join(map(str, sorted(v)))} for k, v in conflicts.items()],
         ["cvss_version", "vector", "scores"])
    print(f"CVE {len(all_ids)}, çift {len(pairs)}, excluded satır {len(excl)}, lookup {len(lookup)}, çelişki {len(conflicts)}")


if __name__ == "__main__":
    main()
