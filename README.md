# Vulnerability-Aware Dynamic Risk Assessment for Threat Modeling in Smart Grids

This repository contains the code and data for a study that follows how the NVD CVSS v3.1 scores of 13 smart grid devices, and of the 84 attack paths between them, change between two dates. Device severity is the mean NVD Primary base score of the device's scored CVEs at a given date, rebuilt from the NVD change history, and path risk is derived from these device values over a fixed reference topology.

The raw NVD responses were fetched on 2026-11-13 and are included under data/raw/2026-11-13/, so every result can be reproduced without network access. The main comparison is t_x = 2025-12-31 against t_y = 2026-10-31.

```
config/          devices.yaml (the 13 devices and their CPE match strings), topology.yaml (directed attack graph,
                 entry points, targets, path rule), model.yaml (t_x, t_y, CVSS version, label threshold, horizon dates)
data/raw/        2026-11-13/ unmodified NVD cves/2.0 and cvehistory/2.0 responses, _probe/ sample responses used by tests
data/processed/  cve_pairs.csv, excluded.csv, cve_device_map.csv, monthly_snapshots.csv
src/             collection, parsing, score timeline, model and result scripts
tests/           unit and data tests
results/         outputs listed below
```

Python 3.9 was used. Install the dependencies with

```
pip install -r requirements.txt
```

Run the scripts from the repository root in this order. The first step needs internet access and an NVD API key and can be skipped, because the fetched data is already in data/raw/.

```
python src/collect.py
python src/build_pairs.py
python src/timeline.py
python -m src.run_horizon
python -m src.run_main
python -m src.run_propagation
python -m src.run_monthly
python -m pytest
```

collect.py reads the API key from the NVD_API_KEY environment variable and never writes it to disk. FETCH_DATE selects the folder under data/raw/ (default: the current UTC date). For example:

```
export NVD_API_KEY=your-key FETCH_DATE=2026-11-13      (bash)
set NVD_API_KEY=your-key & set FETCH_DATE=2026-11-13   (Windows cmd)
$env:NVD_API_KEY="your-key"; $env:FETCH_DATE="2026-11-13"   (PowerShell)
```

Results:

```
main_devices.csv           per device N_d at t_x and t_y, difference, label and its decomposition into new, revised and removed CVEs
main_paths.csv             per path P at t_x and t_y, difference, label and number of nodes
main_devices.png/.pdf      device N_d at t_x and t_y for the main comparison
threshold_sensitivity.csv  counts of increased, decreased and unchanged paths and devices for thresholds 0.05, 0.10 and 0.15
horizon_devices.csv        the device table for every t_x in horizon_t_x, with t_y fixed
horizon_paths.csv          the path table for every t_x in horizon_t_x, defined paths only
horizon_summary.csv        per t_x counts of defined devices and paths, path labels and summed absolute contributions
arrival_per_year.csv       per device and year, the number of CVEs that received their first NVD score and their mean first score
propagation_main.csv       per target the highest path risk R (product of N_d/10 over the path) at t_x and t_y, log difference and node contributions
propagation_horizon.csv    the same as propagation_main.csv for every t_x in horizon_t_x
device_monthly.csv         N_d and the number of scored CVEs per device at each month end from t_x to t_y
new_scored_cves.csv        CVEs that were not scored at t_x and are scored at t_y, with their score and scoring time
```

run_horizon.py also writes first_scored_month.csv and sekil3_ufuk.png, timeline.py writes timeline_validation.csv, and build_pairs.py writes vector_score_lookup_conflicts.csv. These files are not part of the paper results and are not tracked.
