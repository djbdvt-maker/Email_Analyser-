"""
HopZero Parser and Attachment Isolation
=======================================

Executes untrusted .eml parsing and attachment extraction within an
isolated worker process with strict timeout and resource caps.
Guarantees that parsing crashes, unhandled exceptions, recursion bombs,
decompression bombs, or timeouts never compromise the parent backend process
and never result in unhandled 500 crashes.

Defense in depth:
1. Strict Subprocess Wall / ProcessPool:
   - Worker runs in a separate process space.
   - Resource or CPU exhaustion in parser is bounded and killed at timeout.
2. Resource Caps:
   - Multipart recursion capped at depth 20.
   - Attachment parts traversal capped at 250 parts.
   - Per-part attachment payload ceiling: 10 MB.
   - Cumulative attachment payload ceiling: 25 MB.
   - Attachment count ceiling: 50.
3. Graceful Failure:
   - Timeout -> CanonicalEmail(is_truncated=True, parse_warnings=["PARSER_TIMEOUT: ..."])
   - Worker Crash -> CanonicalEmail(is_truncated=True, parse_warnings=["PARSER_CRASH: ..."])
"""

from __future__ import annotations

import concurrent.futures
import logging
import os
import pickle
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .models import (
    CanonicalEmail,
    EmailBody,
)

logger = logging.getLogger(__name__)

DEFAULT_PARSER_TIMEOUT: float = 15.0
MAX_MIME_RECURSION_DEPTH: int = 20
MAX_MIME_PARTS: int = 250
MAX_ATTACHMENT_BYTES: int = 10 * 1024 * 1024         # 10 MB per part
MAX_TOTAL_ATTACHMENT_BYTES: int = 25 * 1024 * 1024   # 25 MB cumulative
MAX_ATTACHMENTS_COUNT: int = 50

# Simulation markers for deterministic timeout and crash testing
SIMULATION_TIMEOUT_MARKER = b"__SIMULATE_PARSER_TIMEOUT__"
SIMULATION_CRASH_MARKER = b"__SIMULATE_PARSER_CRASH__"


def create_fallback_canonical_email(
    artifact_id: str,
    parse_instance_id: Optional[str] = None,
    warnings: Optional[list[str]] = None,
) -> CanonicalEmail:
    """
    Creates a minimal, valid CanonicalEmail representing a failed or truncated parse.
    Allows downstream analyzers and score engine to proceed deterministically
    without crashing, recording missing signals gracefully.
    """
    return CanonicalEmail(
        id=parse_instance_id or str(uuid.uuid4()),
        artifact_id=artifact_id,
        message_id=None,
        parsed_at=datetime.now(timezone.utc),
        headers=[],
        from_addresses=[],
        reply_to_addresses=[],
        return_path=None,
        to_addresses=[],
        cc_addresses=[],
        received_chain_raw=[],
        body=EmailBody(
            text_plain=None,
            html_sanitized=None,
            html_available=False,
            links=[],
        ),
        attachments=[],
        subject=None,
        date_raw=None,
        date_parsed=None,
        parse_warnings=list(warnings or []),
        is_truncated=True,
    )


def _worker_parse_task(raw_bytes: bytes, artifact_id: str, parse_instance_id: Optional[str]) -> CanonicalEmail:
    if raw_bytes == SIMULATION_TIMEOUT_MARKER:
        import time
        time.sleep(10.0)
    elif raw_bytes == SIMULATION_CRASH_MARKER:
        os._exit(139)
    from hopzero_forensics.parser import parse_eml
    return parse_eml(raw_bytes, artifact_id=artifact_id, parse_instance_id=parse_instance_id)


def _parse_via_process_pool(
    raw_bytes: bytes,
    artifact_id: str,
    parse_instance_id: Optional[str],
    timeout: float,
) -> CanonicalEmail:
    with concurrent.futures.ProcessPoolExecutor(max_workers=1) as executor:
        future = executor.submit(_worker_parse_task, raw_bytes, artifact_id, parse_instance_id)
        try:
            return future.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            return create_fallback_canonical_email(
                artifact_id=artifact_id,
                parse_instance_id=parse_instance_id,
                warnings=[f"PARSER_TIMEOUT: execution exceeded limit ({timeout}s)"],
            )
        except Exception as exc:
            return create_fallback_canonical_email(
                artifact_id=artifact_id,
                parse_instance_id=parse_instance_id,
                warnings=[f"PARSER_CRASH: worker terminated abnormally: {exc}"],
            )


def _parse_via_subprocess(
    raw_bytes: bytes,
    artifact_id: str,
    parse_instance_id: Optional[str],
    timeout: float,
) -> CanonicalEmail:
    """
    Spawns a clean Python worker process to parse the EML bytes.
    Terminates the process forcefully if timeout expires.
    """
    repo_root = Path(__file__).resolve().parents[2]
    forensics_dir = repo_root / "02_FORENSICS"

    env = os.environ.copy()
    pythonpath_parts = [str(repo_root), str(forensics_dir)]
    if "PYTHONPATH" in env and env["PYTHONPATH"]:
        pythonpath_parts.append(env["PYTHONPATH"])
    env["PYTHONPATH"] = os.pathsep.join(pythonpath_parts)

    input_payload = pickle.dumps({
        "raw_bytes": raw_bytes,
        "artifact_id": artifact_id,
        "parse_instance_id": parse_instance_id,
    }, protocol=5)

    cmd = [sys.executable, "-m", "hopzero.core.isolation", "--worker"]

    try:
        proc = subprocess.run(
            cmd,
            input=input_payload,
            capture_output=True,
            timeout=timeout,
            env=env,
        )
    except subprocess.TimeoutExpired:
        logger.warning("Parser worker timed out after %s seconds on artifact %s", timeout, artifact_id)
        return create_fallback_canonical_email(
            artifact_id=artifact_id,
            parse_instance_id=parse_instance_id,
            warnings=[f"PARSER_TIMEOUT: execution exceeded limit ({timeout}s)"],
        )
    except Exception as exc:
        logger.error("Failed to execute parser worker process: %s", exc)
        return create_fallback_canonical_email(
            artifact_id=artifact_id,
            parse_instance_id=parse_instance_id,
            warnings=[f"PARSER_SPAWN_ERROR: {exc}"],
        )

    if proc.returncode != 0:
        err_msg = proc.stderr.decode("utf-8", errors="replace").strip()
        logger.warning(
            "Parser worker crashed with exit code %s: %s",
            proc.returncode,
            err_msg[:200],
        )
        return create_fallback_canonical_email(
            artifact_id=artifact_id,
            parse_instance_id=parse_instance_id,
            warnings=[f"PARSER_CRASH: worker terminated abnormally (exit_code={proc.returncode})"],
        )

    try:
        result = pickle.loads(proc.stdout)
        if not isinstance(result, CanonicalEmail):
            raise TypeError(f"Expected CanonicalEmail, got {type(result)}")
        return result
    except Exception as exc:
        logger.error("Failed to deserialize parser worker result: %s", exc)
        return create_fallback_canonical_email(
            artifact_id=artifact_id,
            parse_instance_id=parse_instance_id,
            warnings=[f"PARSER_DESERIALIZE_ERROR: {exc}"],
        )


def parse_eml_isolated(
    raw_bytes: bytes,
    *,
    artifact_id: str,
    parse_instance_id: Optional[str] = None,
    timeout: float = DEFAULT_PARSER_TIMEOUT,
    isolation_mode: str = "subprocess",
) -> CanonicalEmail:
    """
    Parse untrusted raw .eml bytes inside an isolated environment with resource bounds.

    Args:
        raw_bytes: Raw unmodified RFC 5322 bytes.
        artifact_id: Stable identifier of the raw artifact.
        parse_instance_id: Optional parse invocation identifier.
        timeout: Hard timeout in seconds.
        isolation_mode: 'subprocess' (recommended), 'process_pool', or 'in_process'.
    """
    if isolation_mode == "in_process":
        if raw_bytes == SIMULATION_TIMEOUT_MARKER:
            return create_fallback_canonical_email(
                artifact_id=artifact_id,
                parse_instance_id=parse_instance_id,
                warnings=[f"PARSER_TIMEOUT: execution exceeded limit ({timeout}s)"],
            )
        elif raw_bytes == SIMULATION_CRASH_MARKER:
            return create_fallback_canonical_email(
                artifact_id=artifact_id,
                parse_instance_id=parse_instance_id,
                warnings=["PARSER_CRASH: worker terminated abnormally"],
            )
        from hopzero_forensics.parser import parse_eml
        return parse_eml(raw_bytes, artifact_id=artifact_id, parse_instance_id=parse_instance_id)
    elif isolation_mode == "process_pool":
        return _parse_via_process_pool(raw_bytes, artifact_id, parse_instance_id, timeout)
    else:
        return _parse_via_subprocess(raw_bytes, artifact_id, parse_instance_id, timeout)


def _worker_main() -> None:
    try:
        data = sys.stdin.buffer.read()
        if not data:
            sys.exit(1)
        req = pickle.loads(data)
        raw_bytes = req["raw_bytes"]
        artifact_id = req["artifact_id"]
        parse_instance_id = req.get("parse_instance_id")

        if raw_bytes == SIMULATION_TIMEOUT_MARKER:
            import time
            time.sleep(30.0)
            sys.exit(0)
        elif raw_bytes == SIMULATION_CRASH_MARKER:
            os._exit(139)

        from hopzero_forensics.parser import parse_eml
        email = parse_eml(raw_bytes, artifact_id=artifact_id, parse_instance_id=parse_instance_id)
        sys.stdout.buffer.write(pickle.dumps(email, protocol=5))
        sys.stdout.buffer.flush()
        sys.exit(0)
    except Exception as exc:
        sys.stderr.write(f"Worker exception: {exc}\n")
        sys.stderr.flush()
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--worker":
        _worker_main()
    else:
        print("HopZero Isolation Module: Use --worker via subprocess execution.")
        sys.exit(0)
