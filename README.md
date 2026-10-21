# From Attack Patterns to Key Leakage

Simulation-driven machine learning for **detecting and quantifying cache
side channels in cryptographic implementations**, built on the
[gem5](https://www.gem5.org/) cycle-accurate simulator.

This repository accompanies the paper *"From Attack Patterns to Key Leakage:
Simulation-Driven Machine Learning for Detecting and Quantifying Cache Side
Channels in Cryptographic Implementations"* (extended version of our PROOFS
2025 workshop paper, submitted to the *Journal of Cryptographic
Engineering*).

The framework co-simulates cryptographic victims (leaky and constant-time
AES, square-and-multiply RSA, ChaCha20) with cache attackers
(Flush+Reload, Prime+Probe, Spectre-v1) in gem5 system-call-emulation mode,
samples microarchitectural statistics at a fixed tick interval, extracts
aggregate and temporal features, and runs two heads in parallel:

* **Detection** — supervised (Random Forest, XGBoost, SVM, logistic
  regression) and unsupervised (Isolation Forest, autoencoder, HDBSCAN)
  classifiers that flag attack activity.
* **Leakage quantification** — mutual information, key-recovery success
  rate, and guessing entropy per victim implementation, distinguishing
  implementations that are *merely attacked* from those that *actually leak*.

## Repository layout

```
workloads/        C workload generators (victims + attackers)
  src/common.h      timing/flush primitives, per-run randomisation
  src/victims.h     AES T-table, constant-time AES, RSA, ChaCha20, benign
  src/attackers.h   Flush+Reload, Prime+Probe, Spectre-v1 patterns
  src/driver.c      victim+attacker driver (ground-truth logging)
  Makefile          builds the 8 workload binaries
configs/
  config.yaml       sweep, sampling, workload, and cache definitions
  se_run.py         gem5 SE-mode config with interval stats dumping
pipeline/
  run_gem5.py       orchestrates the (workload x cache x seed) sweep
  parse_traces.py   stats.txt -> aggregate + temporal feature table (CSV)
analysis/
  detect.py         detection: supervised CV + unsupervised ensemble
  leakage.py        leakage quantification (MI / SR / guessing entropy)
  generalise.py     zero-day, leave-one-family-out, stealthiness
results/            precomputed outputs for the paper (400-run dataset)
figures/            paper figures (PDF)
```

## Requirements

* gem5 v23.x built for X86 (`build/X86/gem5.opt`)
* a C compiler (gcc) with x86-64 SSE2 support
* Python 3.10+ with the packages in `requirements.txt`:
  `pip install -r requirements.txt`

## Reproducing the results

```bash
# 1. build the workload binaries
cd workloads && make && cd ..

# 2. point configs/config.yaml at your gem5.opt, then run the sweep
#    (50 seeds x 8 classes on the 'small' cache config = 400 runs)
python pipeline/run_gem5.py   --config configs/config.yaml --per-class 50 --mem small

# 3. extract features from the simulator output
python pipeline/parse_traces.py --config configs/config.yaml   # -> features.csv

# 4. run the analyses
python analysis/detect.py     --features features.csv   # detection + CV
python analysis/leakage.py    --features features.csv   # leakage per victim
python analysis/generalise.py --features features.csv   # generalisation
```

A quick smoke test (3 seeds per class) is available via
`run_gem5.py --per-class 3 --mem small`.

## Notes

* The workloads are self-contained *pattern* kernels run inside a single
  simulated process; they generate the characteristic microarchitectural
  trace of each attack class for detector training and never recover a key.
* Run-to-run variation is injected deliberately through randomised attacker
  parameters and victim inputs (there is no measurement noise in a
  deterministic simulator); the per-run attacker *probe rate* doubles as the
  stealthiness axis of the generalisation study.
* `results/` contains the feature table and analysis outputs for the
  400-run dataset reported in the paper.

## Citation

If you use this code, please cite the paper (BibTeX to be added on
acceptance).

## License

Released under the MIT License (see `LICENSE`).
