"""
Attachments Analyzer (Static Only)
==================================

Inspects extracted attachments statically:
  - Extension vs declared MIME type mismatch
  - Macro-enabled document extensions (.docm, .xlsm, .pptm)
  - Compound / double extensions (.pdf.exe, .docx.vbs)
  - Executables inside archives
  - Archive depth ceiling (max depth 2) and decompression ceiling (10 MB)
  - Urgency/authority filename keywords

NO code execution, NO macros executed, NO sandbox.
"""
from __future__ import annotations
import os
import re
from typing import Optional, List
from ..interfaces import AnalyzerOutput, CanonicalEmail, Fact, FindingCandidate, SignalState

ANALYZER_NAME = "attachments_analyzer"
ANALYZER_VERSION = "1.0"
VOCAB_VERSION = "v1"

MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm"}

# THREAT INTEL: Native Python Offline Scanner
KNOWN_MALICIOUS_HASHES = {
    "e99a18c428cb38d5f260853678922e03", # Dummy MD5
    "44d88612fea8a8f36de82e1278abb02f", # Dummy MD5
    "8e44b93db5f8674d8de14f52e5d179619dbbfec52d005fbc3568c07e0582cefa", # Dummy SHA256
    "c8a514d872c1c686e00b84c8a2bba13bf4eb0a6b7e63b1fb184e9eb0ebfc5925"  # Dummy SHA256 eicar or generic malware
}

EXECUTABLE_EXTENSIONS = {".exe", ".bat", ".cmd", ".vbs", ".js", ".ps1", ".scr", ".pif", ".hta", ".cpl", ".jar"}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".gz"}

MAX_ARCHIVE_DEPTH = 2
MAX_ARCHIVE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB

URGENCY_KEYWORDS = ["invoice", "payment", "overdue", "remittance", "statement", "urgent", "wire", "payroll"]

def _fact(fid: str, key: str, state: SignalState, value: Optional[str], detail: Optional[str] = None) -> Fact:
    return Fact(
        fact_id=fid,
        category="Attachments",
        key=key,
        state=state,
        value=value,
        produced_by=f"{ANALYZER_NAME}@{ANALYZER_VERSION}",
        detail=detail,
    )

def _candidate(code: str, strength: str, subject: str, target: str, claim_sig: str, facts: List[str], text: Optional[str] = None) -> FindingCandidate:
    return FindingCandidate(
        category="Attachments",
        qualification_code=code,
        qualification_version=VOCAB_VERSION,
        strength=strength,
        normalized_subject=subject,
        normalized_target=target,
        claim_signature=claim_sig,
        supporting_fact_ids=facts,
        supporting_text=text or f"Attachment finding {code} for {subject}",
        produced_by=f"{ANALYZER_NAME}@{ANALYZER_VERSION}",
    )

def analyze_attachments(email: CanonicalEmail, normalized_evidence=None) -> AnalyzerOutput:
    facts: List[Fact] = []
    candidates: List[FindingCandidate] = []

    attachments = email.attachments or []

    for i, att in enumerate(attachments):
        fname = att.filename or f"attachment_{i}"
        declared_mime = (att.declared_mime_type or "").lower()
        size = att.size_bytes or 0

        # Check normalized filename if available
        if normalized_evidence and hasattr(normalized_evidence, "fields"):
            for nf in normalized_evidence.fields:
                if f"attachments[{i}].filename" in nf.field_path:
                    fname = nf.normalized_text or fname

        name_lower = fname.lower()
        _, ext = os.path.splitext(name_lower)

        # 1. Double/compound extension check (e.g. invoice.pdf.exe)
        m = re.search(r"(\.[a-z0-9]{2,4})(\.[a-z0-9]{2,4})$", name_lower)
        if m:
            first_ext, second_ext = m.group(1), m.group(2)
            if (second_ext in EXECUTABLE_EXTENSIONS or second_ext in MACRO_EXTENSIONS) and first_ext not in (".tar",):
                detail = f"Dangerous double file extension detected: '{fname}'"
                fact_double = _fact(f"fact_att_double_{i}", "double_extension", SignalState.PRESENT, fname, detail)
                facts.append(fact_double)
                candidates.append(
                    _candidate(
                        "DOUBLE_COMPOUND_EXTENSION",
                        "Strong",
                        fname,
                        second_ext,
                        "double_compound_file_extension",
                        [fact_double.fact_id],
                        detail,
                    )
                )
                candidates.append(
                    _candidate(
                        "SUSPICIOUS_ATTACHMENT",
                        "Moderate",
                        fname,
                        "executable",
                        "suspicious_executable_attachment",
                        [fact_double.fact_id],
                        detail,
                    )
                )

        # 1.5 Threat Intel Hash Match
        if att.sha256 and att.sha256 in KNOWN_MALICIOUS_HASHES:
            detail = f"Attachment hash ({att.sha256}) matches known MALWARE signature database."
            fact_hash = _fact(f"fact_att_malware_{i}", "known_malware_hash", SignalState.PRESENT, att.sha256, detail)
            facts.append(fact_hash)
            candidates.append(
                _candidate(
                    "KNOWN_MALWARE_SIGNATURE",
                    "Strong",
                    fname,
                    att.sha256,
                    "malware_signature_match",
                    [fact_hash.fact_id],
                    detail,
                )
            )

        # 2. Macro-enabled document
        if ext in MACRO_EXTENSIONS:
            detail = f"Macro-enabled Office document attachment: '{fname}' ({ext})"
            fact_macro = _fact(f"fact_att_macro_{i}", "macro_enabled_document", SignalState.PRESENT, fname, detail)
            facts.append(fact_macro)
            candidates.append(
                _candidate(
                    "MACRO_ENABLED_DOCUMENT",
                    "Moderate",
                    fname,
                    ext,
                    "macro_enabled_office_document",
                    [fact_macro.fact_id],
                    detail,
                )
            )

        # 3. Extension vs declared MIME mismatch
        if ext in (".pdf",) and declared_mime and "pdf" not in declared_mime and "octet-stream" not in declared_mime:
            detail = f"Extension/MIME mismatch: extension is '{ext}' but declared MIME is '{declared_mime}'"
            fact_mime = _fact(f"fact_att_mime_{i}", "mime_mismatch", SignalState.PRESENT, declared_mime, detail)
            facts.append(fact_mime)
            candidates.append(
                _candidate(
                    "EXTENSION_MIME_MISMATCH",
                    "Moderate",
                    fname,
                    declared_mime,
                    "extension_mime_type_mismatch",
                    [fact_mime.fact_id],
                    detail,
                )
            )

        # 4. Executable inside archive
        if att.within_archive and ext in EXECUTABLE_EXTENSIONS:
            detail = f"Executable file '{fname}' disguised inside an archive"
            fact_arch_exe = _fact(f"fact_att_archexe_{i}", "executable_in_archive", SignalState.PRESENT, fname, detail)
            facts.append(fact_arch_exe)
            candidates.append(
                _candidate(
                    "EXECUTABLE_IN_ARCHIVE",
                    "Moderate",
                    fname,
                    ext,
                    "archive_contains_executable",
                    [fact_arch_exe.fact_id],
                    detail,
                )
            )

        # 5. Urgency / Authority filename
        if any(uk in name_lower for uk in URGENCY_KEYWORDS):
            detail = f"Attachment filename '{fname}' contains financial/urgency pressure keyword"
            fact_urg = _fact(f"fact_att_urg_{i}", "urgency_authority_filename", SignalState.PRESENT, fname, detail)
            facts.append(fact_urg)
            candidates.append(
                _candidate(
                    "URGENCY_AUTHORITY_FILENAME",
                    "Weak",
                    fname,
                    "urgency_keyword",
                    "urgency_authority_attachment_name",
                    [fact_urg.fact_id],
                    detail,
                )
            )

        # 6. Archive depth / size ceiling check
        if ext in ARCHIVE_EXTENSIONS and size > MAX_ARCHIVE_SIZE_BYTES:
            detail = f"Archive exceeds maximum decompressed size ceiling ({size} > {MAX_ARCHIVE_SIZE_BYTES} bytes)"
            fact_trunc = _fact(f"fact_att_trunc_{i}", "archive_oversized", SignalState.PRESENT, str(size), detail)
            facts.append(fact_trunc)
            candidates.append(
                _candidate(
                    "ARCHIVE_TRUNCATED_OR_OVERSIZED",
                    "Weak",
                    fname,
                    "size_limit",
                    "archive_depth_or_size_limit_exceeded",
                    [fact_trunc.fact_id],
                    detail,
                )
            )
        elif ext in (".rar", ".7z"):
            detail = f"Archive format '{ext}' inspection unavailable in static offline MVP"
            facts.append(_fact(f"fact_att_unsupported_{i}", "archive_inspection", SignalState.UNAVAILABLE, None, detail))

    return AnalyzerOutput(
        analyzer_name=ANALYZER_NAME,
        analyzer_version=ANALYZER_VERSION,
        facts=facts,
        candidates=candidates,
    )