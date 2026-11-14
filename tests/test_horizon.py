import collections
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import graph
import model as M
import run_horizon as H


@pytest.fixture(scope="module")
def data():
    cfg = M.load_config()
    D, tl = M.load_data(cfg["fetch_date"])
    _, _, paths = graph.load_paths()
    return cfg, D, tl, paths


def test_horizon_equals_single_model_run(data):
    cfg, D, tl, paths = data
    c = dict(cfg, horizon_t_x=[cfg["t_x"]])
    (tx, dev_rows, path_out), = H.horizon(D, tl, c, paths)
    ref_dev, _ = M.device_changes(D, tl, cfg)
    assert tx == cfg["t_x"] and dev_rows == ref_dev
    assert path_out == M.path_changes(paths, ref_dev, cfg["değişim_etiketi_eşiği"])


def test_horizon_rejects_t_x_after_t_y(data):
    cfg, D, tl, paths = data
    with pytest.raises(ValueError):
        H.horizon(D, tl, dict(cfg, horizon_t_x=[cfg["t_y"]]), paths)


def test_summary_row_counts():
    dev = [{"fark": 0.5, "etiket": "artan", "katki_revize": -0.2, "katki_yeni": 0.7},
           {"fark": 0.0, "etiket": "değişmedi", "katki_revize": 0.0, "katki_yeni": 0.0},
           {"fark": None, "etiket": "t_x'te tanımsız", "katki_revize": None, "katki_yeni": None}]
    paths = [{"fark": 0.2, "etiket": "artan"}, {"fark": -0.3, "etiket": "azalan"},
             {"fark": 0.01, "etiket": "değişmedi"}, {"fark": None, "etiket": "t_x'te tanımsız"}]
    r = H.summary_row("2020-12-31", dev, paths)
    assert (r["tanimli_cihaz"], r["esigi_asan_cihaz"], r["tanimli_yol"], r["tanimsiz_yol"]) == (2, 1, 3, 1)
    assert (r["artan_yol"], r["azalan_yol"], r["degismedi_yol"]) == (1, 1, 1)
    assert r["toplam_abs_katki_revize"] == pytest.approx(0.2) and r["toplam_abs_katki_yeni"] == pytest.approx(0.7)


def test_nice_step():
    assert [H.nice_step(v) for v in (5.4, 1.946, 0.009, 1.0)] == [6, 2, 0.01, 1]


def test_main_files_are_exact_copies_of_horizon_rows():
    import csv
    import run_main as R
    res = os.path.join(M.ROOT, "results")
    if not os.path.exists(os.path.join(res, "main_devices.csv")):
        pytest.skip("main_*.csv yok (python -m src.run_main çalıştırılmadı)")

    def rows(name):
        with open(os.path.join(res, name), encoding="utf8", newline="") as f:
            return list(csv.DictReader(f))
    hd = [r for r in rows("horizon_devices.csv") if r["t_x"] == R.MAIN_T_X]
    hp = [r for r in rows("horizon_paths.csv") if r["t_x"] == R.MAIN_T_X]
    assert rows("main_devices.csv") == hd
    mp = rows("main_paths.csv")
    assert [{k: v for k, v in r.items() if k != "dugum_sayisi"} for r in mp] == hp
    _, _, paths = graph.load_paths()
    n = {p["path_id"]: str(len(p["nodes"].split(graph.NODE_SEP))) for p in paths}
    assert all(r["dugum_sayisi"] == n[r["path_id"]] for r in mp)


def test_threshold_sensitivity_at_model_threshold_matches_labels():
    import csv
    import run_main as R
    res = os.path.join(M.ROOT, "results")
    if not os.path.exists(os.path.join(res, "main_devices.csv")):
        pytest.skip("main_*.csv yok")

    def rows(name):
        with open(os.path.join(res, name), encoding="utf8", newline="") as f:
            return list(csv.DictReader(f))
    dev, paths = rows("main_devices.csv"), rows("main_paths.csv")
    ts = R.threshold_sensitivity(dev, paths, thresholds=(0.05, 0.10, 0.15))
    for level, src in (("paths", paths), ("devices", dev)):
        r10 = next(r for r in ts if r["level"] == level and r["threshold"] == "0.10")
        lab = collections.Counter(r["etiket"] for r in src)
        assert (r10["increased"], r10["decreased"], r10["unchanged"]) == (lab["artan"], lab["azalan"], lab["değişmedi"])
        unchanged = [r["unchanged"] for r in ts if r["level"] == level]
        assert unchanged == sorted(unchanged)
