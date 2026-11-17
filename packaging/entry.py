"""PyInstaller entry point for the standalone `sentinel` executable.

Build (see .github/workflows/release.yml):
    pyinstaller packaging/sentinel.spec
"""

import sys

from sentinel.__main__ import main

if __name__ == "__main__":
    sys.exit(main())
