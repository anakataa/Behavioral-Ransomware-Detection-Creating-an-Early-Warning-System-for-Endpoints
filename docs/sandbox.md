# Testing Sentinel in a VirtualBox virtual machine

Use this to reproduce the evaluation on an isolated Windows machine you
control. The same steps work for an Ubuntu VM.

Everything here uses Sentinel's own simulator, which only ever touches a
sandbox folder it created itself. Real ransomware samples are **not**
part of this procedure; use them only with your supervisor's approval,
inside a VM with networking switched off.

## 1. Create the VM (once)

1. Install [VirtualBox](https://www.virtualbox.org/wiki/Downloads).
2. Get a Windows 10 or 11 ISO from Microsoft. Activation is not needed for testing.
3. New VM: 2 CPUs, 4 GB RAM, 60 GB disk. Install Windows with a local account.
4. Isolation, in the VM settings:
   - **General → Advanced**: Shared Clipboard and Drag'n'Drop **Disabled**.
   - **Shared Folders**: none.
   - **Network**: NAT while installing; for runs with anything other than
     the built-in simulator, set it to **Not attached**.
5. Inside the VM install [Python 3.12](https://www.python.org/downloads/)
   (tick "Add python.exe to PATH") and [Git](https://git-scm.com/download/win).

## 2. Install Sentinel in the VM

```powershell
git clone https://github.com/anakataa/sentinel-ransomware.git sentinel
cd sentinel
python -m pip install -e ".[dev]"
python -m pytest -q
```

Or copy `sentinel-windows-x64.zip` from a release and use `sentinel.exe`.

## 3. Take a clean snapshot

Machine → **Take Snapshot** → name it `clean`. Restore it after every
evaluation session so each one starts from the same state.

## 4. Run the evaluation matrix

```powershell
python scripts/vm/run_matrix.py --runs 3 --rates 20,50,100,200,400,0 --out results/win10-vm
```

It takes about 10 minutes and writes:

- `results/win10-vm/results.csv` — one row per run
- `results/win10-vm/summary.md` — tables ready for the thesis

Long session? Split it and append:

```powershell
python scripts/vm/run_matrix.py --scenarios attack --rates 20,50 --out results/win10-vm
python scripts/vm/run_matrix.py --scenarios attack,evasive --rates 100,0 --append --out results/win10-vm
python scripts/vm/run_matrix.py --scenarios benign,idle --append --out results/win10-vm
```

## 5. Extra false-positive checks by hand

With the agent in watch-only mode on a test folder:

```powershell
python -m sentinel run --watch C:\test --monitor-only
```

then, in another window, archive the folder with 7-Zip, create a
VeraCrypt container in it, copy a few GB into it, and let Windows Update
run. Afterwards `python -m sentinel audit -n 50` lists any verdicts.
Record each workload and whether it produced a verdict.

## 6. What to report

| Metric | Where |
|---|---|
| Detection rate | `Detected` column of `summary.md` |
| Files lost before the stop | `Files encrypted` column |
| Time to first signal and to decision | `First signal`, `Decision` columns |
| False positives | "Legitimate workloads" table + section 5 |
| CPU and memory | "Idle overhead" |

Copy `summary.md` into `docs/results.md` with the date and the VM's
specifications.
