import csv
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
import model as M
import timeline as TL
from run_main import MAIN_T_X
from run_model import f4

ROOT = M.ROOT
END = "T23:59:59.999"


def device_monthly(D, tl, cfg):
    dates = [m.isoformat() for m in TL.month_ends(cfg["t_x"], cfg["t_y"])]
    by_month = {d[:7]: d for d in dates}
    idx = {(r["device_id"], by_month[r["ay"]]): r for r in M.monthly_device_severity(D, tl, cfg)}
    devs = [x["device_id"] for x in D["devices"]]
    return [{"tarih": t, "cihaz_id": d, "N_d": idx[(d, t)]["N_d"], "n_skorlu": idx[(d, t)]["skorlu_cve_sayisi"]}
            for t in dates for d in devs]


def scored_since(tl, c, t_x, t_y, version):
    times = sorted({e["created"] for e in tl.nvd_events(c, version) if t_x + END < e["created"] <= t_y + END})
    for t in times:
        r = tl.score_at(c, t, version)
        if r["state"] == "scored" and r["score"] is not None:
            return t
    raise ValueError(f"{c}: no scoring time found in ({t_x}, {t_y}]")


def new_scored(D, tl, cfg):
    v, rows, revised = cfg["cvss_version"], [], []
    for d in [x["device_id"] for x in D["devices"]]:
        s_x, _ = M.scores_at(D, tl, D["dev_cves"][d], cfg["t_x"], v)
        s_y, _ = M.scores_at(D, tl, D["dev_cves"][d], cfg["t_y"], v)
        items = sorted((scored_since(tl, c, cfg["t_x"], cfg["t_y"], v), c) for c in set(s_y) - set(s_x))
        rows += [{"cihaz_id": d, "cve_id": c, "cvss31_skor": f"{s_y[c]:.1f}", "skorlanma_tarihi": t} for t, c in items]
        revised += [(d, c) for c in set(s_x) & set(s_y) if s_x[c] != s_y[c]]
    return rows, revised


def main():
    cfg = dict(M.load_config(), t_x=MAIN_T_X)
    res = os.path.join(ROOT, cfg.get("output_dir", "results"))
    D, tl = M.load_data(cfg["fetch_date"])
    monthly = device_monthly(D, tl, cfg)
    with open(os.path.join(res, "device_monthly.csv"), "w", newline="", encoding="utf8") as f:
        w = csv.writer(f)
        w.writerow(["tarih", "cihaz_id", "N_d", "n_skorlu"])
        for r in monthly:
            w.writerow([r["tarih"], r["cihaz_id"], f4(r["N_d"]), r["n_skorlu"]])
    rows, revised = new_scored(D, tl, cfg)
    with open(os.path.join(res, "new_scored_cves.csv"), "w", newline="", encoding="utf8") as f:
        w = csv.DictWriter(f, fieldnames=["cihaz_id", "cve_id", "cvss31_skor", "skorlanma_tarihi"])
        w.writeheader()
        w.writerows(rows)
    print(f"device_monthly: {len(monthly)} rows; new_scored_cves: {len(rows)} rows; revised: {len(revised)}")


if __name__ == "__main__":
    main()
