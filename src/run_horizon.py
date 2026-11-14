import argparse
import collections
import csv
import math
import os
import sys

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

sys.path.insert(0, os.path.dirname(__file__))
import graph
import model as M
import timeline as TL
from run_model import GRID, INK, PALETTE, write_csv

ROOT = M.ROOT
PROC = os.path.join(ROOT, "data", "processed")
DEV_COLS = ["device_id", "N_x", "N_y", "fark", "n_cve_x", "n_cve_y", "katki_yeni", "katki_revize",
            "katki_kaldirilan", "etiket", "baskin_neden"]
SUM_COLS = ["t_x", "tanimli_cihaz", "esigi_asan_cihaz", "tanimli_yol", "tanimsiz_yol", "artan_yol", "azalan_yol",
            "degismedi_yol", "toplam_abs_katki_revize", "toplam_abs_katki_yeni"]
NON_PRIMARY = "current_nvd_metric_type_is_Secondary"


def horizon(D, tl, cfg, path_rows):
    out = []
    for tx in cfg["horizon_t_x"]:
        if not tx < cfg["t_y"]:
            raise ValueError(f"ufuk t_x ({tx}) t_y'den ({cfg['t_y']}) önce olmalı")
        c = dict(cfg, t_x=tx)
        dev_rows, _ = M.device_changes(D, tl, c)
        path_out = M.path_changes(path_rows, dev_rows, c["değişim_etiketi_eşiği"])
        out.append((tx, dev_rows, path_out))
    return out


def summary_row(tx, dev_rows, path_out):
    dd = [r for r in dev_rows if r["fark"] is not None]
    pd = [r for r in path_out if r["fark"] is not None]
    lab = collections.Counter(r["etiket"] for r in pd)
    return {"t_x": tx, "tanimli_cihaz": len(dd),
            "esigi_asan_cihaz": sum(1 for r in dd if r["etiket"] in ("artan", "azalan")),
            "tanimli_yol": len(pd), "tanimsiz_yol": len(path_out) - len(pd),
            "artan_yol": lab["artan"], "azalan_yol": lab["azalan"], "degismedi_yol": lab["değişmedi"],
            "toplam_abs_katki_revize": sum(abs(r["katki_revize"]) for r in dd if r["katki_revize"] is not None),
            "toplam_abs_katki_yeni": sum(abs(r["katki_yeni"]) for r in dd if r["katki_yeni"] is not None)}


def read_csv(name):
    with open(os.path.join(PROC, name), encoding="utf8") as f:
        return list(csv.DictReader(f))


def first_scores(version):
    out = {}
    for r in read_csv("cve_pairs.csv"):
        if r["cvss_version"] == version:
            out[r["cve_id"]] = (r["first_score_date"], float(r["first_score"]) if r["first_score"] else None, "")
    excl = {(r["cve_id"], r["cvss_version"]) for r in read_csv("excluded.csv") if r["reason"] == NON_PRIMARY}
    snaps = collections.defaultdict(list)
    for r in read_csv("monthly_snapshots.csv"):
        if r["cvss_version"] == version:
            snaps[r["cve_id"]].append(r)
    for c, rs in snaps.items():
        if c in out or (c, version) in excl:
            continue
        rs.sort(key=lambda r: r["month"])
        first = next((r for r in rs if r["state"] == "scored"), None)
        if first is None:
            continue
        if first is rs[0]:
            out[c] = ("", None, f"ilk skor tarihi belirlenemedi ({c}: cve_pairs.csv'de yok, monthly_snapshots.csv "
                                f"ilk ayında {rs[0]['month']} zaten skorlu)")
        elif first["score"] == "":
            out[c] = (first["month"], None, f"ilk skoru bilinmiyor, ortalamaya girmedi ({c}: monthly_snapshots.csv "
                                            f"{first['month']} skorlu ama skor boş, {first['score_source']})")
        else:
            out[c] = (first["month"], float(first["score"]), "")
    return out


def check_pairs_vs_snapshots(version):
    pairs = {r["cve_id"]: r for r in read_csv("cve_pairs.csv") if r["cvss_version"] == version}
    snaps = collections.defaultdict(list)
    for r in read_csv("monthly_snapshots.csv"):
        if r["cvss_version"] == version:
            snaps[r["cve_id"]].append(r)
    n, bad = 0, []
    for c, p in pairs.items():
        rs = sorted(snaps.get(c, []), key=lambda r: r["month"])
        if not rs or p["first_score_date"][:7] <= rs[0]["month"]:
            continue
        n += 1
        first = next((r for r in rs if r["state"] == "scored"), None)
        same_month_rev = p["last_revision_date"][:7] == p["first_score_date"][:7]
        if first is None or first["month"] != p["first_score_date"][:7] or \
                (not same_month_rev and first["score"] != "" and float(first["score"]) != float(p["first_score"])):
            bad.append(c)
    return n, bad


def arrival_per_year(version, devices):
    dev_map = collections.defaultdict(set)
    for r in read_csv("cve_device_map.csv"):
        if r["vulnerable"] == "true":
            dev_map[r["device_id"]].add(r["cve_id"])
    fs = first_scores(version)
    rows = []
    for d in devices:
        by_year = collections.defaultdict(list)
        for c in sorted(dev_map.get(d, ())):
            if c in fs:
                by_year[fs[c][0][:4]].append(fs[c])
        for y in sorted(by_year, key=lambda y: (y == "", y)):
            items = by_year[y]
            known = [s for _, s, _ in items if s is not None]
            notes = "; ".join(n for _, _, n in items if n)
            rows.append({"device_id": d, "yil": y, "ilk_skor_alan_cve_sayisi": len(items),
                         "ortalama_ilk_skor": M.mean(known), "not": notes})
    return rows


def first_scored_month(D, tl, cfg):
    v = cfg["cvss_version"]
    pairs = {r["cve_id"]: r for r in read_csv("cve_pairs.csv") if r["cvss_version"] == v}
    start = min(r["first_score_date"] for r in pairs.values() if r["first_score_date"])[:8] + "01"
    months = [m.isoformat() for m in TL.month_ends(start, cfg["t_y"])]
    devices = [x["device_id"] for x in D["devices"]]
    scored = {m: {d: len(M.scores_at(D, tl, D["dev_cves"][d], m, v)[0]) for d in devices} for m in months}
    rows = []
    for d in devices:
        m1 = next((m for m in months if scored[m][d] > 0), None)
        cand = sorted((pairs[c]["first_score_date"], c) for c in D["dev_cves"][d]
                      if c in pairs and pairs[c]["first_score_date"])
        rows.append({"device_id": d, "ilk_skorlu_ay": m1[:7] if m1 else "",
                     "ilk_skor_tarihi": cand[0][0] if cand else "", "ilk_skor_cve": cand[0][1] if cand else "",
                     "ilk_skor": float(pairs[cand[0][1]]["first_score"]) if cand else None,
                     "t_y_ye_kadar_kesintisiz": ""})
    all_m = next((m for m in months if all(scored[m][d] > 0 for d in devices)), None)
    cont = all_m is not None and all(all(scored[m][d] > 0 for d in devices) for m in months if m >= all_m)
    rows.append({"device_id": f"tüm {len(devices)} cihaz", "ilk_skorlu_ay": all_m[:7] if all_m else "",
                 "ilk_skor_tarihi": "", "ilk_skor_cve": "", "ilk_skor": None,
                 "t_y_ye_kadar_kesintisiz": ("evet" if cont else "hayır") if all_m else ""})
    return rows, all_m


def nice_step(raw):
    k = 10 ** math.floor(math.log10(raw))
    return next(m * k for m in (1, 2, 2.5, 3, 4, 5, 6, 8, 10) if m * k >= raw - 1e-12)


def figure3(summary, cfg, out):
    x = list(range(len(summary)))
    changed = [r["artan_yol"] + r["azalan_yol"] for r in summary]
    rev = [r["toplam_abs_katki_revize"] for r in summary]
    new = [r["toplam_abs_katki_yeni"] for r in summary]
    fig, ax = plt.subplots(figsize=(max(8, 1.15 * len(summary)), 4.4))
    ax2 = ax.twinx()
    w = 0.32
    b1 = ax2.bar([i - w / 2 - 0.01 for i in x], rev, width=w, color=PALETTE[0], edgecolor="white", linewidth=1,
                 label="Σ |katki_revize| (cihaz bazında, sağ eksen)", zorder=2)
    b2 = ax2.bar([i + w / 2 + 0.01 for i in x], new, width=w, color=PALETTE[1], edgecolor="white", linewidth=1,
                 label="Σ |katki_yeni| (cihaz bazında, sağ eksen)", zorder=2)
    for bars, vals in ((b1, rev), (b2, new)):
        for b, v in zip(bars, vals):
            ax.annotate(f"{v:.2f}", (b.get_x() + b.get_width() / 2, v), xycoords=ax2.transData, xytext=(0, 2),
                        textcoords="offset points", ha="center", va="bottom", fontsize=6.5, color=INK,
                        bbox=dict(boxstyle="square,pad=0.1", fc="white", ec="none", alpha=0.85))
    ax.set_zorder(ax2.get_zorder() + 1)
    ax.patch.set_visible(False)
    ln, = ax.plot(x, changed, color=INK, lw=2, marker="o", markersize=6, markerfacecolor=INK,
                  markeredgecolor="white", markeredgewidth=1.5, label="değişen yol sayısı (artan+azalan, sol eksen)")
    n_int = 6
    s1, s2 = nice_step(max(max(changed), 1) * 1.2 / n_int), nice_step(max(max(rev + new), 0.01) * 1.2 / n_int)
    ax.set_ylim(0, s1 * n_int)
    ax.set_yticks([s1 * k for k in range(n_int + 1)])
    ax2.set_ylim(0, s2 * n_int)
    ax2.set_yticks([s2 * k for k in range(n_int + 1)])
    ax.grid(False)
    ax2.grid(axis="y", color=GRID, linewidth=0.6)
    ax2.set_axisbelow(True)
    for i, r in enumerate(summary):
        ax.annotate(f"{changed[i]} / {r['tanimli_yol']}", (i, 1.0), xycoords=("data", "axes fraction"),
                    xytext=(0, 4), textcoords="offset points", ha="center", va="bottom", fontsize=7, color=INK)
    ax.set_xticks(x)
    ax.set_xticklabels([r["t_x"] for r in summary])
    ax.set_xlim(-0.6, len(x) - 0.4)
    ax.set_xlabel(f"t_x (ufuk); t_y = {cfg['t_y']} sabit")
    ax.set_ylabel("değişen yol sayısı (|fark| > eşik)")
    ax2.set_ylabel("cihaz bazında |katkı| toplamı (CVSS puanı)")
    ax2.spines["right"].set_visible(True)
    ax2.spines["top"].set_visible(False)
    ax.legend([ln, b1, b2], [ln.get_label(), b1.get_label(), b2.get_label()], loc="upper center",
              bbox_to_anchor=(0.5, -0.16), ncol=2, fontsize=6.5)
    ax.set_title(f"Şekil 3. Ufuk taraması: t_x geriye çekilerek model tekrarı (CVSS v{cfg['cvss_version']} NVD "
                 f"Primary, eşik ±{cfg['değişim_etiketi_eşiği']})\n"
                 "çizim üstündeki satır: değişen yol / t_x'te tanımlı yol; çubuk etiketi: |katkı| toplamı",
                 loc="left", fontsize=8.5, pad=16)
    fig.tight_layout()
    fig.savefig(out, dpi=300, metadata={"Software": None})
    plt.close(fig)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Ufuk taraması (t_x geriye çekilerek model tekrarı)")
    ap.add_argument("--cvss-version", choices=["2.0", "3.0", "3.1"], help="varsayılan: config/model.yaml")
    ap.add_argument("--output-dir", help="varsayılan: <output_dir> ya da sürüm farklıysa <output_dir>/v<sürüm>")
    a = ap.parse_args(argv)
    cfg = M.load_config()
    out = os.path.join(ROOT, cfg.get("output_dir", "results"))
    if a.cvss_version and a.cvss_version != cfg["cvss_version"]:
        cfg["cvss_version"] = a.cvss_version
        out = os.path.join(out, f"v{a.cvss_version}")
    if a.output_dir:
        out = a.output_dir if os.path.isabs(a.output_dir) else os.path.join(ROOT, a.output_dir)
    os.makedirs(out, exist_ok=True)
    cfg["horizon_t_x"] = [str(t) for t in cfg["horizon_t_x"]]
    D, tl = M.load_data(cfg["fetch_date"])
    _, _, path_rows = graph.load_paths()

    res = horizon(D, tl, cfg, path_rows)
    write_csv(os.path.join(out, "horizon_devices.csv"),
              [dict(r, t_x=tx) for tx, dev_rows, _ in res for r in dev_rows], ["t_x"] + DEV_COLS)
    write_csv(os.path.join(out, "horizon_paths.csv"),
              [dict(r, t_x=tx) for tx, _, po in res for r in po if r["fark"] is not None],
              ["t_x", "path_id", "P_x", "P_y", "fark", "etiket"])
    summary = [summary_row(tx, dev_rows, po) for tx, dev_rows, po in res]
    write_csv(os.path.join(out, "horizon_summary.csv"), summary, SUM_COLS)

    write_csv(os.path.join(out, "arrival_per_year.csv"), arrival_per_year(cfg["cvss_version"], [x["device_id"] for x in D["devices"]]),
              ["device_id", "yil", "ilk_skor_alan_cve_sayisi", "ortalama_ilk_skor", "not"])
    n_chk, bad = check_pairs_vs_snapshots(cfg["cvss_version"])

    fsm, all_m = first_scored_month(D, tl, cfg)
    write_csv(os.path.join(out, "first_scored_month.csv"), fsm,
              ["device_id", "ilk_skorlu_ay", "ilk_skor_tarihi", "ilk_skor_cve", "ilk_skor", "t_y_ye_kadar_kesintisiz"])
    figure3(summary, cfg, os.path.join(out, "sekil3_ufuk.png"))

    fm = next((r for r in fsm if r["device_id"] == "FIELD-METER-01"), None)
    print(f"v{cfg['cvss_version']}: {len(res)} ufuk -> {out}")
    print(f"cve_pairs ilk skor vs monthly_snapshots kontrolü: {n_chk} CVE (pencere içi ilk skor), uyumsuz {len(bad)}"
          + (f": {', '.join(bad)}" if bad else ""))
    print(f"tüm cihazlarda skorlu ilk ay: {all_m[:7] if all_m else 'yok'}"
          + (f" (FIELD-METER-01 ilk skor tarihi: {fm['ilk_skor_tarihi']}, {fm['ilk_skor_cve']}, "
             f"skor {fm['ilk_skor']})" if fm and fm["ilk_skor_tarihi"] else " (FIELD-METER-01: bu sürümde skor yok)"))


if __name__ == "__main__":
    main()
