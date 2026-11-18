# Artifacts for the Paper: What the Proofs Ruled Out: A Symbolic Analysis of SRP Under Compromise

This artifacts folder contains the necessary files to reproduce the results presented in the paper. It is organized into two main directories: `Offline_Guessing` and `Trace_Properties`.

## Prerequisites

To run the models and automation scripts in this repository, you need the following tools installed:

* **Python** (3.8 or later) and [**uv**](https://docs.astral.sh/uv/): Required to execute the verification wrapper script (`scripy.py`). The script only uses the Python standard library, so there is nothing else to install.
* **ProVerif**: Required to verify the `.pv` protocol models. It is not installed by `uv`. We recommend building ProVerif from the `master` branch of the official GitLab repository:
  * **Repository:** <https://gitlab.inria.fr/bblanche/proverif/-/tree/master/proverif>
  * **Branch:** `master` (e.g., `git clone -b master https://gitlab.inria.fr/bblanche/proverif.git`)

*(Note: Ensure the `proverif` executable is on your system `PATH` before running the Python script. The script calls it by that name.)*

## Directory Structure

```
.
├── Offline_Guessing/
│   ├── Offline_Guessing SRP6a/
│   │   ├── Corin/
│   │   └── Lowe/
│   └── Offline_Guessing SRP6a_fix/
│       ├── Corin/
│       └── Lowe/
└── Trace_Properties/
    ├── srp/
    │   ├── base.pv
    │   ├── reuse.pv
    │   └── fix.pv
    ├── pyproject.toml
    ├── uv.lock
    └── scripy.py
```

## 1. Offline Guessing (`Offline_Guessing/`)

The `Offline_Guessing` directory contains two subfolders: one for standard SRP (`Offline_Guessing SRP6a`), and one for the fix proposed in the paper (`Offline_Guessing SRP6a_fix`).

For both notions of offline guessing attacks—**à la Lowe** (`Lowe/`) and **à la Corin** (`Corin/`)—we provide the necessary ProVerif models using the following naming convention:

* `no_R.pv`: Implies no leakage was considered in this file.
* `R{x}.pv` (for example `Ra.pv`, `Rb.pv`, `Rv.pv`, `RKc.pv`, `RKs.pv`): Implies the analysis is for when value `x` is leaked during protocol execution.
* `R{x}_aft.pv` (for example `Rv_aft.pv`): Implies the analysis is for when value `x` is leaked after the protocol execution was completed.

Each file is run on its own with ProVerif, for example:

```bash
proverif "Offline_Guessing/Offline_Guessing SRP6a/Lowe/Rb.pv"
```

The verdict is on the `RESULT` lines at the end of the output.

## 2. Trace Properties (`Trace_Properties/`)

The `Trace_Properties` directory contains a subfolder `srp/`, which holds the SRP models used for our analysis (`base.pv`, `reuse.pv`, `fix.pv`).

It also contains a Python script, `scripy.py`, which takes one of the files in the `srp/` subfolder (`base.pv` by default) as input and starts the analysis to find all possible compromise scenarios for the input model.

### Property Notations

Each property is referred to by a short notation. The table below lists the short notations used along with the corresponding properties analyzed in `Trace_Properties`:

| Notation | Property Analyzed | 
| :--- | :--- | 
| `ks_server` | Secrecy of $K$ from $S$'s point of view | 
| `ks_client` | Secrecy of $K$ from $C$'s point of view | 
| `ks_mutual` | Mutual secrecy of $K$ | 
| `auth_s2c` | Authentication of $S$ to $C$ and agreement on $K$ | 
| `auth_c2s` | Authentication of $C$ to $S$ and agreement on $K$ | 
| `buks` | BUKS attacks resistance | 
| `uuks_c` | UUKS attacks resistance w.r.t. $C$ | 
| `uuks_s` | UUKS attacks resistance w.r.t. $S$ | 
| `deriv_v` | Long-lived key non-derivability of $v$ | 
| `deriv_pwd` | Long-lived key non-derivability of $pwd$ | 

### Execution Commands

To execute the files from within the `Trace_Properties/` directory, we recommend using the following commands. `uv run` uses the `pyproject.toml` of this directory.

```bash
cd Trace_Properties

# Run every property on the default model (srp/base.pv)
uv run scripy.py

# Run just those two specific properties
uv run scripy.py auth_c2s uuks_s

# Run reuse.pv and output results in the runs_reuse folder
uv run scripy.py --base srp/reuse.pv --out runs_reuse

# Run fix.pv and output results in the runs_fix folder
uv run scripy.py --base srp/fix.pv --out runs_fix
```

The script runs up to 8 ProVerif processes in parallel and stops a run after 30 minutes (the `JOBS` and `TIMEOUT` constants at the top of `scripy.py`).
Results are written in the output folder: `summary.txt` lists the minimal compromise scenarios for each property, and the sub-folders `R/` and `M/` contain one generated `.pv` file and one `.out` file for each configuration that was run.