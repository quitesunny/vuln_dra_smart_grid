import calendar
import csv
import datetime as dt
import os
import sys

import yaml

sys.path.insert(0, os.path.dirname(__file__))
import build_pairs as BP
import nvd_parse as P
import rawdata

ROOT = rawdata.ROOT
PROC = os.path.join(ROOT, "data", "processed")


def month_ends(start, end):
    s = dt.date.fromisoformat(start)
    e = dt.date.fromisoformat(end)
    y, m = s.year, s.month
    out = []
    while True:
        last = dt.date(y, m, calendar.monthrange(y, m)[1])
        if last > e:
            break
        if last >= s:
            out.append(last)
        y, m = (y + 1, 1) if m == 12 else (y, m + 1)
    return out


class Timeline:
    def __init__(self, cves, hist, lookup):
        self.cves, self.hist, self.lookup = cves, hist, lookup
        self._ev = {}

    def nvd_events(self, cid, version):
        k = (cid, version)
        if k not in self._ev:
            ev = P.cvss_events(self.hist.get(cid, []))
            self._ev[k] = [e for e in ev if e["version"] == version and e["is_nvd"]]
        return self._ev[k]

    def _score(self, cid, version, vector):
        if vector is None:
            return None, ""
        cur = P.nvd_primary(self.cves.get(cid, {}), version)
        if cur and cur["vector"] == vector:
            return cur["baseScore"], "current_record_same_vector"
        if (version, vector) in self.lookup:
            return self.lookup[(version, vector)], "raw_lookup"
        return None, "score_not_in_raw_lookup"

    def score_at(self, cid, when, version):
        ev = self.nvd_events(cid, version)
        if not ev:
            return {"state": "no_nvd_events", "vector": None, "score": None, "score_source": "", "source": ""}
        if ev[0]["action"] != "Added" and when < ev[0]["created"]:
            return {"state": "unknown_pre_history", "vector": None, "score": None, "score_source": "", "source": ""}
        vec, seen = None, False
        for e in ev:
            if e["created"] > when:
                break
            seen = True
            vec = None if e["action"] == "Removed" else e["new_vector"]
        if not seen:
            return {"state": "not_yet_scored", "vector": None, "score": None, "score_source": "", "source": ""}
        if vec is None:
            return {"state": "removed", "vector": None, "score": None, "score_source": "", "source": P.NVD_SOURCE}
        sc, ss = self._score(cid, version, vec)
        return {"state": "scored", "vector": vec, "score": sc, "score_source": ss, "source": P.NVD_SOURCE}


def snapshot_row(tl, cid, me, v):
    r = tl.score_at(cid, me.isoformat() + "T23:59:59.999", v)
    return {"cve_id": cid, "month": me.isoformat()[:7], "snapshot_date": me.isoformat(),
            "score": "" if r["score"] is None else r["score"], "cvss_version": v,
            "source": r["source"], "state": r["state"], "vector": r["vector"] or "",
            "score_source": r["score_source"]}


def snapshot_keys(tl, D):
    ids = sorted({c for v in D["dev_cves"].values() for c in v})
    for cid in ids:
        if cid not in D["hist"]:
            continue
        for v in BP.VERSIONS:
            if tl.nvd_events(cid, v) or P.nvd_primary(D["cves"].get(cid, {}), v):
                yield cid, v


def main():
    fetch_date = os.environ.get("FETCH_DATE", "2026-11-13")
    cfg = yaml.safe_load(open(os.path.join(ROOT, "config", "model.yaml"), encoding="utf8"))
    w = {"start": cfg["t_x"], "end": cfg["t_y"]}
    D = rawdata.load(fetch_date)
    lookup, _ = BP.build_lookup(D["cves"])
    tl = Timeline(D["cves"], D["hist"], lookup)
    ids = sorted({c for v in D["dev_cves"].values() for c in v})
    months = month_ends(w["start"], w["end"])
    snaps, val = [], []
    for cid in ids:
        if cid not in D["hist"]:
            continue
        for v in BP.VERSIONS:
            ev = tl.nvd_events(cid, v)
            cur = P.nvd_primary(D["cves"].get(cid, {}), v)
            if not ev and not cur:
                continue
            for me in months:
                snaps.append(snapshot_row(tl, cid, me, v))
            r = tl.score_at(cid, "9999-12-31T23:59:59", v)
            ok = (cur is not None and r["state"] == "scored" and r["vector"] == cur["vector"]) or \
                 (cur is None and r["state"] in ("removed", "no_nvd_events"))
            note = ""
            if not ok:
                if r["state"] == "no_nvd_events" and cur is not None:
                    note = "history_has_no_nvd_score_event"
                elif cur is None and any(m["version"] == v and m["source"] == P.NVD_SOURCE
                                         for m in P.current_metrics(D["cves"].get(cid, {}))):
                    note = "current_nvd_metric_not_primary"
                elif r["state"] == "unknown_pre_history":
                    note = "unknown_pre_history"
                else:
                    note = "vector_mismatch_or_other"
            val.append({"cve_id": cid, "cvss_version": v, "note": note, "rebuilt_state": r["state"],
                        "rebuilt_vector": r["vector"] or "", "rebuilt_score": "" if r["score"] is None else r["score"],
                        "current_vector": cur["vector"] if cur else "", "current_score": cur["baseScore"] if cur else "",
                        "consistent": str(ok).lower()})
    os.makedirs(PROC, exist_ok=True)
    for name, rows in (("monthly_snapshots.csv", snaps), ("timeline_validation.csv", val)):
        with open(os.path.join(PROC, name), "w", newline="", encoding="utf8") as f:
            wr = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            wr.writeheader()
            wr.writerows(rows)
    print(f"snapshot satırı {len(snaps)}, ay {len(months)} ({months[0]}..{months[-1]}), doğrulama {len(val)}, "
          f"tutarsız {sum(1 for x in val if x['consistent'] == 'false')}")


if __name__ == "__main__":
    main()
