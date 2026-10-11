"""
HopZero Core Package.
=====================
Shared domain primitives, single local LLM adapter, and tool suite standards.
"""
from . import core
from . import llm

__version__ = "2.0.0"

__all__ = ["core", "llm", "__version__"]
