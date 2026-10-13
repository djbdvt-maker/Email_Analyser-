#!/usr/bin/env python3
"""
scripts/package_extension.py
Packages the 07_EXTENSION folder into a clean, distributable zip file
for employees to install in Chrome.
Supports embedding a custom Hub URL for zero-friction employee setup.
"""
import os
import sys
import shutil
import zipfile
import argparse
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
EXT_SRC = REPO_ROOT / "07_EXTENSION"
DIST_DIR = REPO_ROOT / "dist"


def package_extension(hub_url: str = None, output_zip: Path = None) -> Path:
    DIST_DIR.mkdir(parents=True, exist_ok=True)
    out_file = output_zip or (DIST_DIR / "hopzero-employee-extension.zip")

    # Files to include
    include_patterns = [
        "manifest.json",
        "README.md",
        "assets/*",
        "src/**/*",
    ]

    import tempfile

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_stage = Path(temp_dir) / "hopzero_extension"
        temp_stage.mkdir(parents=True)

        # Copy extension assets and source
        shutil.copy(EXT_SRC / "manifest.json", temp_stage / "manifest.json")
        if (EXT_SRC / "README.md").exists():
            shutil.copy(EXT_SRC / "README.md", temp_stage / "README.md")
        if (EXT_SRC / "assets").exists():
            shutil.copytree(EXT_SRC / "assets", temp_stage / "assets")
        if (EXT_SRC / "src").exists():
            shutil.copytree(EXT_SRC / "src", temp_stage / "src")

        # If custom Hub URL is specified, patch the default in popup.html and hopzero_client.js
        if hub_url:
            clean_url = hub_url.rstrip("/")
            # Patch popup.html default input value
            popup_html = temp_stage / "src" / "popup" / "popup.html"
            if popup_html.exists():
                content = popup_html.read_text(encoding="utf-8")
                content = content.replace('value="http://localhost:8000"', f'value="{clean_url}"')
                popup_html.write_text(content, encoding="utf-8")

            # Patch hopzero_client.js constructor default
            client_js = temp_stage / "src" / "api" / "hopzero_client.js"
            if client_js.exists():
                content = client_js.read_text(encoding="utf-8")
                content = content.replace('this.baseUrl = "http://localhost:8000";', f'this.baseUrl = "{clean_url}";')
                client_js.write_text(content, encoding="utf-8")

        # Create zip archive
        if out_file.exists():
            out_file.unlink()

        with zipfile.ZipFile(out_file, "w", zipfile.ZIP_DEFLATED) as zipf:
            for root, _, files in os.walk(temp_stage):
                for file in files:
                    file_path = Path(root) / file
                    rel_path = file_path.relative_to(temp_stage)
                    zipf.write(file_path, arcname=str(rel_path))

        print(f"[*] Packaged employee extension -> {out_file.resolve()}")
        if hub_url:
            print(f"    Pre-configured Hub URL: {hub_url}")
        return out_file


def main():
    parser = argparse.ArgumentParser(description="Package HopZero Employee Browser Extension")
    parser.add_argument("--hub-url", type=str, default=None, help="Pre-configure the default Hub URL in the package")
    parser.add_argument("--output", type=str, default=None, help="Custom output zip file path")
    args = parser.parse_args()

    out_path = Path(args.output) if args.output else None
    package_extension(hub_url=args.hub_url, output_zip=out_path)


if __name__ == "__main__":
    main()
