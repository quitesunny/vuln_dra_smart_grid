import argparse
import collections
import csv
import os
import sys

import matplotlib

matplotlib.use("Agg")
import matplotlib.lines as mlines
import matplotlib.pyplot as plt

sys.path.insert(0, os.path.dirname(__file__))
import graph
import model as M
from run_model import GRAY, INK, PALETTE

ROOT = M.ROOT
MAIN_T_X = M.load_config()["t_x"]


def copy_rows(src, t_x):
    with open(src, encoding="utf8", newline="") as f:
        rd = csv.DictReader(f)
        rows = [r for r in rd if r["t_x"] == t_x]
        cols = rd.fieldnames
    if not rows:
        raise ValueError(f"{os.path.basename(src)} içinde t_x = {t_x} satırı yok (run_horizon çalıştırıldı mı?)")
    return cols, rows


def write(path, cols, rows):
    with open(path, "w", encoding="utf8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)


def num(s):
    return None if s == "" else float(s)


LABEL_EN = {"artan": "increased", "azalan": "decreased", "değişmedi": "unchanged"}


def label_en(etiket):
    if etiket in LABEL_EN:
        return LABEL_EN[etiket]
    if etiket.startswith("t_x'te tanımsız"):
        return "undefined at t_x"
    if etiket.startswith("t_y'de tanımsız"):
        return "undefined at t_y"
    raise ValueError(f"bilinmeyen etiket: {etiket}")


def figure(dev_rows, cfg, outs):
    n = len(dev_rows)
    with plt.rc_context({"pdf.fonttype": 42}):
        fig, ax = plt.subplots(figsize=(8, 0.42 * n + 1.0))
        for i, r in enumerate(dev_rows):
            y = n - 1 - i
            nx_, ny_ = num(r["N_x"]), num(r["N_y"])
            if nx_ is not None and ny_ is not None:
                ax.plot([nx_, ny_], [y, y], color=GRAY, lw=2.5, zorder=1, solid_capstyle="round")
            if nx_ is not None:
                ax.plot(nx_, y, "o", ms=10, color=PALETTE[0], mec="white", mew=1.2, zorder=3)
            if ny_ is not None:
                ax.plot(ny_, y, "D", ms=5.5, color=PALETTE[1], mec="white", mew=0.8, zorder=4)
            right = max(v for v in (nx_, ny_) if v is not None)
            lab = label_en(r["etiket"])
            if r["fark"] != "":
                lab += f" ({float(r['fark']):+.2f})"
            ax.text(right + 0.08, y, f"{lab}, n={r['n_cve_x']}→{r['n_cve_y']}", va="center", fontsize=7,
                    color=INK)
        ax.set_yticks(range(n))
        ax.set_yticklabels([r["device_id"] for r in reversed(dev_rows)], fontsize=7)
        vals = [num(r[k]) for r in dev_rows for k in ("N_x", "N_y") if num(r[k]) is not None]
        lo = int(min(vals) * 2) / 2 - 0.25
        ax.set_xlim(lo, max(vals) + 1.75)
        ax.set_xticks([lo + 0.25 + 0.5 * k for k in range(int((max(vals) - lo) / 0.5) + 2)])
        ax.grid(axis="y", visible=False)
        ax.set_axisbelow(True)
        ax.set_xlabel(f"Mean CVSS v{cfg['cvss_version']} base score (N_d)")
        h1 = mlines.Line2D([], [], ls="", marker="o", ms=10, color=PALETTE[0], mec="white", label="t_x")
        h2 = mlines.Line2D([], [], ls="", marker="D", ms=5.5, color=PALETTE[1], mec="white", label="t_y")
        ax.legend(handles=[h1, h2], loc="upper center", bbox_to_anchor=(0.5, -0.09), ncol=2, fontsize=7)
        fig.tight_layout()
        for out in outs:
            meta = {"Software": None} if out.endswith(".png") else {"Creator": None, "Producer": None,
                                                                    "CreationDate": None}
            fig.savefig(out, dpi=300, metadata=meta)
        plt.close(fig)


THRESHOLDS = (0.05, 0.10, 0.15)


def threshold_sensitivity(dev_rows, path_rows, thresholds=THRESHOLDS):
    out = []
    for level, rows in (("paths", path_rows), ("devices", dev_rows)):
        diffs = [float(r["fark"]) for r in rows if r["fark"] != ""]
        for t in thresholds:
            amb = [d for d in diffs if abs(abs(d) - t) < 5e-9]
            if amb:
                raise ValueError(f"{level}: yuvarlanmış fark eşiğe ({t}) eşit, ham değer gerekir: {amb}")
            c = collections.Counter(M.label(d, t) for d in diffs)
            out.append({"level": level, "threshold": f"{t:.2f}", "n_defined": len(diffs),
                        "n_undefined": len(rows) - len(diffs), "increased": c["artan"],
                        "decreased": c["azalan"], "unchanged": c["değişmedi"]})
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description="Ana çift: horizon çıktılarından seçili t_x satırlarını kopyala")
    ap.add_argument("--t-x", default=MAIN_T_X)
    a = ap.parse_args(argv)
    cfg = M.load_config()
    res = os.path.join(ROOT, cfg.get("output_dir", "results"))
    dcols, drows = copy_rows(os.path.join(res, "horizon_devices.csv"), a.t_x)
    pcols, prows = copy_rows(os.path.join(res, "horizon_paths.csv"), a.t_x)
    _, _, paths = graph.load_paths()
    n_nodes = {p["path_id"]: len(p["nodes"].split(graph.NODE_SEP)) for p in paths}
    for r in prows:
        r["dugum_sayisi"] = n_nodes[r["path_id"]]
    write(os.path.join(res, "main_devices.csv"), dcols, drows)
    write(os.path.join(res, "main_paths.csv"), pcols + ["dugum_sayisi"], prows)
    figure(drows, cfg, [os.path.join(res, "main_devices.png"), os.path.join(res, "main_devices.pdf")])
    ts = threshold_sensitivity(drows, prows)
    write(os.path.join(res, "threshold_sensitivity.csv"), list(ts[0]), ts)
    print(f"ana çift {a.t_x} -> {cfg['t_y']}: {len(drows)} cihaz, {len(prows)} yol -> {res}")
    print("main_devices.png/pdf yazıldı")


if __name__ == "__main__":
    main()
