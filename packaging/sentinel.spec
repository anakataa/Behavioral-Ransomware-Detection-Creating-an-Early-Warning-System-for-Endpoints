# PyInstaller spec: one portable executable (sentinel.exe on Windows).
# Build from the repository root:  pyinstaller packaging/sentinel.spec
# The dashboard HTML and the mock-ransomware simulator are bundled so that
# `sentinel demo` works without a Python installation.

from PyInstaller.utils.hooks import collect_submodules

root = SPECPATH + "/.."

a = Analysis(
    [root + "/packaging/entry.py"],
    pathex=[root + "/src"],
    datas=[
        (root + "/dashboard/sentinel_dashboard.html", "dashboard"),
        (root + "/scripts/mock_ransomware.py", "scripts"),
        (root + "/config.example.yaml", "."),
    ],
    hiddenimports=collect_submodules("watchdog.observers") + collect_submodules("sentinel"),
    excludes=["tkinter", "pytest"],
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    name="sentinel",
    console=True,
    upx=False,
)
