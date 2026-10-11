"""
hopzero.core.hardware
Hardware auto-detection (CPU, RAM, GPU, VRAM) and edition recommender.
Supports first-run hardware profiling and edition selection (Lite / Standard / Pro / Server)
while enforcing one shared local model (hermes3:3b) across HopZero and BotChain tools.
"""
import os
import sys
import json
import shutil
import subprocess
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any

from hopzero.core.paths import get_app_data_root


@dataclass
class HardwareProfile:
    cpu_cores: int
    ram_gb: float
    gpu_name: Optional[str]
    vram_gb: float
    has_cuda: bool
    platform: str
    recommended_edition: str
    recommendation_reason: str
    recommended_settings: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def get_cpu_count() -> int:
    return os.cpu_count() or 4


def get_ram_gb() -> float:
    """Returns total system RAM in GB using native platform interfaces."""
    if sys.platform == "win32":
        try:
            import ctypes
            from ctypes import wintypes
            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ('dwLength', wintypes.DWORD),
                    ('dwMemoryLoad', wintypes.DWORD),
                    ('ullTotalPhys', ctypes.c_uint64),
                    ('ullAvailPhys', ctypes.c_uint64),
                    ('ullTotalPageFile', ctypes.c_uint64),
                    ('ullAvailPageFile', ctypes.c_uint64),
                    ('ullTotalVirtual', ctypes.c_uint64),
                    ('ullAvailVirtual', ctypes.c_uint64),
                    ('ullAvailExtendedVirtual', ctypes.c_uint64),
                ]
            stat = MEMORYSTATUSEX()
            stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
                return round(stat.ullTotalPhys / (1024 ** 3), 2)
        except Exception:
            pass
    elif sys.platform == "linux":
        try:
            with open("/proc/meminfo", "r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        kb = int(line.split()[1])
                        return round(kb / (1024 ** 2), 2)
        except Exception:
            pass
    elif sys.platform == "darwin":
        try:
            res = subprocess.run(["sysctl", "-n", "hw.memsize"], capture_output=True, text=True)
            if res.returncode == 0:
                bytes_mem = int(res.stdout.strip())
                return round(bytes_mem / (1024 ** 3), 2)
        except Exception:
            pass
    return 8.0  # Safe fallback assumption


def get_gpu_info() -> tuple[Optional[str], float, bool]:
    """Detects primary dedicated GPU and VRAM in GB."""
    # 1. Try nvidia-smi
    nvidia_smi = shutil.which("nvidia-smi")
    if nvidia_smi:
        try:
            res = subprocess.run(
                [nvidia_smi, "--query-gpu=name,memory.total", "--format=csv,noheader,nounits"],
                capture_output=True,
                text=True,
                timeout=3.0
            )
            if res.returncode == 0 and res.stdout.strip():
                lines = res.stdout.strip().split("\n")
                if lines:
                    parts = [p.strip() for p in lines[0].split(",")]
                    name = parts[0]
                    vram_mb = float(parts[1]) if len(parts) > 1 else 0.0
                    return name, round(vram_mb / 1024, 2), True
        except Exception:
            pass
    return None, 0.0, False


def detect_hardware() -> HardwareProfile:
    cpu = get_cpu_count()
    ram = get_ram_gb()
    gpu_name, vram, has_cuda = get_gpu_info()

    # Determine recommended edition
    # Force override if explicitly configured
    forced = os.environ.get("HOPZERO_EDITION")
    if forced and forced.lower() in ("lite", "standard", "pro", "server"):
        rec = forced.capitalize()
        reason = f"Explicitly configured via HOPZERO_EDITION={forced}"
    elif ram >= 32.0:
        rec = "Server"
        reason = f"High-capacity host ({ram} GB RAM, {cpu} cores); suited for multi-user enterprise deployment."
    elif ram >= 15.0 and vram >= 4.0:
        rec = "Pro"
        reason = f"High-performance workstation ({ram} GB RAM, {gpu_name} with {vram} GB VRAM); optimal for high-throughput batch analysis."
    elif ram >= 7.0 and (vram >= 3.0 or cpu >= 6):
        rec = "Standard"
        reason = f"Balanced system ({ram} GB RAM, {cpu} cores, {gpu_name or 'integrated graphics'}); perfect for local Ollama hermes3:3b inference."
    else:
        rec = "Lite"
        reason = f"Resource-constrained environment ({ram} GB RAM, {cpu} cores); optimized for lightweight SQLite and rule-based screening."

    # Settings tailored for recommendation while maintaining the single shared model
    settings = {
        "edition": rec,
        "shared_model": "hermes3:3b",
        "shared_model_digest": "a8851c5041d400c8eece484771e0a9f438e6500de9f22150ef2863bf7209fbd9",
        "shared_model_quantization": "Q4_K_M",
        "shared_context_window": 4096,
        "database": "postgresql" if rec == "Server" else "sqlite",
        "laya_prescreen_enabled": True if rec in ("Lite", "Standard") else False,
        "parser_isolation_mode": "subprocess",
        "vram_offload": True if (has_cuda and vram >= 3.5) else False
    }

    return HardwareProfile(
        cpu_cores=cpu,
        ram_gb=ram,
        gpu_name=gpu_name,
        vram_gb=vram,
        has_cuda=has_cuda,
        platform=sys.platform,
        recommended_edition=rec,
        recommendation_reason=reason,
        recommended_settings=settings
    )


def get_or_create_hardware_profile() -> HardwareProfile:
    """Reads cached hardware profile or generates and persists on first run."""
    cache_path = get_app_data_root() / "hardware_profile.json"
    if cache_path.exists():
        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return HardwareProfile(**data)
        except Exception:
            pass

    profile = detect_hardware()
    try:
        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(profile.to_dict(), f, indent=2)
    except Exception:
        pass
    return profile
