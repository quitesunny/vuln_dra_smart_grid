import csv
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
import graph
import model as M
import propagation as PR
from run_main import MAIN_T_X

ROOT = M.ROOT
PCOLS = ["hedef", "n_yol", "n_yol_tanimsiz", "R_x", "R_y", "ln_fark", "en_olasi_yol_x", "en_olasi_yol_y",
         "ayni_yol", "dugum_katkilari", "yol_degisimi_katkisi", "katki_toplami"]


def fmt(v, nd=6):
    if v is None:
        return ""
    if isinstance(v, float):
        return f"{0.0 if round(v, nd) == 0 else v:.{nd}f}"
    return v


def write(path, rows, cols, nd=6):
    with open(path, "w", newline="", encoding="utf8") as f:
        w = csv.writer(f)
        w.writerow(cols)
        for r in rows:
            w.writerow([fmt(r[c], nd) for c in cols])


def propagation_for(D, tl, cfg, topo, path_rows, t_x):
    dev, _ = M.device_changes(D, tl, dict(cfg, t_x=t_x))
    return PR.target_risk(path_rows, dev, topo["targets"])


def main():
    cfg = M.load_config()
    res = os.path.join(ROOT, cfg.get("output_dir", "results"))
    D, tl = M.load_data(cfg["fetch_date"])
    topo, _, path_rows = graph.load_paths()
    hz = [str(t) for t in cfg["horizon_t_x"]]

    main_rows = propagation_for(D, tl, cfg, topo, path_rows, MAIN_T_X)
    write(os.path.join(res, "propagation_main.csv"), [dict(r, t_x=MAIN_T_X, t_y=cfg["t_y"]) for r in main_rows],
          ["t_x", "t_y"] + PCOLS)
    hrows = [dict(r, t_x=tx, t_y=cfg["t_y"]) for tx in hz for r in propagation_for(D, tl, cfg, topo, path_rows, tx)]
    write(os.path.join(res, "propagation_horizon.csv"), hrows, ["t_x", "t_y"] + PCOLS)

    print(f"propagation: {len(main_rows)} hedef (ana çift {MAIN_T_X} -> {cfg['t_y']}), {len(hz)} ufuk")


if __name__ == "__main__":
    main()
