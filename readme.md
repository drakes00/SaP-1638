# Artifacts for the Paper: What the Proofs Ruled Out: A Symbolic Analysis of SRP Under Compromise

This artifacts folder contains the necessary files to reproduce the results presented in the paper. It is organized into two main directories: `Offline_Guessing` and `Trace_Properties`.

## Prerequisites

To run the models and automation scripts in this repository, you need the following tools installed:

* **Python**: Required to execute the verification wrapper script (`scripy.py`).
* **ProVerif**: Required to verify the `.pv` protocol models. 

*(Note: Ensure the compiled `proverif` executable is added to your system `PATH` before running the Python scripts.)*

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
    │    ├── base.pv
    │    ├── reuse.pv
    │    └── fix.pv
    └──scripy.py
``` 
## 1. Offline Guessing (`Offline_Guessing/`)

The `Offline_Guessing` directory contains two subfolders: one for standard SRP (`Offline_Guessing SRP6a`), and one for the fix proposed in the paper (`Offline_Guessing SRP6a_fix`).

For both notions of offline guessing attacks—**à la Lowe** (`Lowe/`) and **à la Corin** (`Corin/`)—we provide the necessary ProVerif models using the following naming convention:

* `no_R.pv`: Implies no leakage was considered in this file.
* `R_{x}.pv`: Implies the analysis is for when value `x` is leaked during protocol execution.
* `R_{x}_aft.pv`: Implies the analysis is for when value `x` is leaked after the protocol execution was completed.

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

To execute the files from within the `Trace_Properties/` directory, we recommend using the following commands:

```bash
# Run every property on the default model (srp/base.pv)
python3 scripy.py

# Run just those two specific properties
python3 scripy.py auth_c2s uuks_s

# Run reuse.pv and output results in the runs_reuse folder
python3 scripy.py --base srp/reuse.pv --out runs_reuse

# Run fix.pv and output results in the runs_fix folder
python3 scripy.py --base srp/fix.pv --out runs_fix
```