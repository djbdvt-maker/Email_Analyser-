import sys
import os

# Automatically ensure repo root and sibling forensics/registry packages are on sys.path
_repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)
for _subpkg in ["01_REGISTRY", "02_FORENSICS", "03_BACKEND"]:
    _subpath = os.path.join(_repo_root, _subpkg)
    if os.path.isdir(_subpath) and _subpath not in sys.path:
        sys.path.insert(0, _subpath)
