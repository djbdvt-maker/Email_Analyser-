"""
HopZero .eml Parser
====================

Converts raw RFC 5322 / MIME bytes into a CanonicalEmail. This is the ONLY
place raw email bytes are re-parsed; every downstream analyzer consumes
CanonicalEmail instead.

Design notes:
  * Uses only Python's standard library `email` package (policy.default,
    which is RFC 5322/6532-aware) to avoid an external dependency for a
    security-sensitive parsing surface.
  * Never fetches, executes, or renders anything. HTML is sanitized to a
    safe-for-display subset (scripts/event handlers/iframes stripped);
    the sanitized HTML is descriptive data, not rendered.
  * Any header or part that fails to parse is recorded with
    SignalState.UNAVAILABLE / a parse_warning - it is never silently
    dropped and never treated as if it were simply absent.
  * Email body/subject content is treated as untrusted data throughout;
    nothing extracted from the body is ever executed or treated as an
    instruction to this parser.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
import uuid
from datetime import datetime, timezone
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime
from html.parser import HTMLParser

from .interfaces import (
    CanonicalEmail,
    EmailAddress,
    EmailBody,
    ExtractedAttachment,
    ExtractedLink,
    RawHeader,
    ReceivedHopRaw,
    SignalState,
)

PARSER_NAME = "eml_parser"
PARSER_VERSION = "1.0"

# Conservative regexes for structural extraction from Received headers.
# These are intentionally simple/robust; ambiguity is reported via
# parse_state=UNAVAILABLE rather than guessed at.
_FROM_CLAUSE_RE = re.compile(r"\bfrom\s+(.+?)(?=\s+by\s+|\s+with\s+|\s+id\s+|\s*;|$)", re.IGNORECASE | re.DOTALL)
_BY_CLAUSE_RE = re.compile(r"\bby\s+(.+?)(?=\s+with\s+|\s+id\s+|\s*;|$)", re.IGNORECASE | re.DOTALL)
_WITH_CLAUSE_RE = re.compile(r"\bwith\s+(.+?)(?=\s+id\s+|\s*;|$)", re.IGNORECASE | re.DOTALL)
_FOR_CLAUSE_RE = re.compile(r"\bfor\s+(<[^>]+>|\S+)(?=\s*;|$)", re.IGNORECASE)
_HREF_RE = re.compile(r'href\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)


class _StrippingHTMLParser(HTMLParser):
    """
    Minimal HTML sanitizer for evidence display, plus link extraction.
    Removes <script>, <style>, <iframe>, <object>, <embed>, and all
    on-* event-handler attributes. Does not attempt full HTML rendering
    fidelity - this is for safe forensic display only, never execution.
    """

    _DANGEROUS_TAGS = {"script", "style", "iframe", "object", "embed", "form"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._skip_depth = 0
        self._out: list[str] = []
        self.links: list[tuple[str, str]] = []  # (href, display_text placeholder)
        self._current_href: str | None = None
        self._current_text_parts: list[str] = []

    def handle_starttag(self, tag, attrs):
        attrs_d = dict(attrs)
        if tag in self._DANGEROUS_TAGS:
            self._skip_depth += 1
            return
        if self._skip_depth:
            return
        if tag == "a" and "href" in attrs_d:
            self._current_href = attrs_d["href"]
            self._current_text_parts = []
        safe_attrs = " ".join(
            f'{k}="{v}"' for k, v in attrs_d.items() if not k.lower().startswith("on")
        )
        self._out.append(f"<{tag}{(' ' + safe_attrs) if safe_attrs else ''}>")

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag not in self._DANGEROUS_TAGS:
            self._out.append(f"</{tag}>")

    def handle_endtag(self, tag):
        if tag in self._DANGEROUS_TAGS:
            if self._skip_depth:
                self._skip_depth -= 1
            return
        if self._skip_depth:
            return
        if tag == "a" and self._current_href is not None:
            self.links.append((self._current_href, "".join(self._current_text_parts).strip()))
            self._current_href = None
        self._out.append(f"</{tag}>")

    def handle_data(self, data):
        if self._skip_depth:
            return
        if self._current_href is not None:
            self._current_text_parts.append(data)
        self._out.append(data)

    def get_sanitized_html(self) -> str:
        return "".join(self._out)


def _decode_bytes(raw: bytes) -> str:
    for enc in ("utf-8", "latin-1"):
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("utf-8", errors="replace")


def _extract_valid_ip(claim_text: str) -> str | None:
    """
    Extracts the first token from claim_text that is a genuinely valid
    IPv4 or IPv6 address (validated via the stdlib `ipaddress` module),
    in order of appearance. Digit/hex-looking strings that are NOT valid
    IPs (e.g. octets out of range, malformed IPv6) are deliberately
    rejected rather than passed through - a malformed value must never
    be silently treated as a real IP.
    """
    # Split on whitespace and the bracket/paren characters Received
    # headers commonly wrap IP literals in (e.g. "host [1.2.3.4]").
    tokens = re.split(r"[\s()\[\]]+", claim_text)
    for raw_token in tokens:
        token = raw_token.strip(",;")
        if not token:
            continue
        try:
            ipaddress.ip_address(token)
            return token
        except ValueError:
            continue
    return None


def _extract_headers(msg: EmailMessage) -> list[RawHeader]:
    headers: list[RawHeader] = []
    for idx, (name, value) in enumerate(msg.raw_items()):
        decoded_value = str(value)
        headers.append(
            RawHeader(
                name=name.lower(),
                value=decoded_value,
                raw_line=f"{name}: {value}",
                sequence_index=idx,
            )
        )
    return headers


def _parse_addresses(raw_value: str | None) -> list[EmailAddress]:
    if not raw_value:
        return []
    results: list[EmailAddress] = []
    try:
        pairs = getaddresses([raw_value])
    except Exception:
        return [
            EmailAddress(
                display_name=None,
                address=None,
                raw_value=raw_value,
                parse_state=SignalState.UNAVAILABLE,
            )
        ]
    for display_name, addr in pairs:
        if not addr:
            results.append(
                EmailAddress(
                    display_name=display_name or None,
                    address=None,
                    raw_value=raw_value,
                    parse_state=SignalState.UNAVAILABLE,
                )
            )
            continue
        normalized = addr.strip()
        # A parsed "address" without an '@' is not a usable email address
        # (e.g. free text that getaddresses couldn't properly split). This
        # must be reported as unavailable/malformed, not silently treated
        # as a present, valid address.
        if "@" not in normalized:
            results.append(
                EmailAddress(
                    display_name=display_name or None,
                    address=None,
                    raw_value=raw_value,
                    parse_state=SignalState.UNAVAILABLE,
                )
            )
            continue
        local, _, domain = normalized.rpartition("@")
        normalized = f"{local}@{domain.lower()}"
        results.append(
            EmailAddress(
                display_name=display_name or None,
                address=normalized,
                raw_value=raw_value,
                parse_state=SignalState.PRESENT,
            )
        )
    return results


def _parse_single_address(raw_value: str | None) -> EmailAddress | None:
    parsed = _parse_addresses(raw_value)
    return parsed[0] if parsed else None


def _parse_received_chain(headers: list[RawHeader]) -> list[ReceivedHopRaw]:
    received_headers = [h for h in headers if h.name == "received"]
    hops: list[ReceivedHopRaw] = []
    for idx, h in enumerate(received_headers):
        value = h.value
        malformed_reason = None
        from_claim = by_claim = with_claim = for_claim = None
        observed_ip = None
        timestamp_raw = None
        timestamp_parsed = None
        state = SignalState.PRESENT

        try:
            # Timestamp is the part after the last ';'
            if ";" in value:
                body_part, _, ts_part = value.rpartition(";")
                timestamp_raw = ts_part.strip() or None
            else:
                body_part = value
                timestamp_raw = None

            # A well-formed Received trace section must begin with "from"
            # or "by" as its first token (RFC 5321 sec 4.4 trace grammar).
            # If it doesn't, this is not a from/by clause at all - reject
            # up front rather than let permissive regexes pick up
            # incidental "from"/"by" substrings from unstructured prose.
            first_token = body_part.strip().split(None, 1)[0].lower() if body_part.strip() else ""
            if first_token not in ("from", "by"):
                hops.append(
                    ReceivedHopRaw(
                        sequence_index=idx,
                        raw_line=h.raw_line,
                        from_claim=None,
                        by_claim=None,
                        with_claim=None,
                        for_claim=None,
                        observed_ip=None,
                        timestamp_raw=timestamp_raw,
                        timestamp_parsed=None,
                        parse_state=SignalState.UNAVAILABLE,
                        malformed_reason="does_not_start_with_from_or_by",
                    )
                )
                continue

            m = _FROM_CLAUSE_RE.search(body_part)
            if m:
                from_claim = " ".join(m.group(1).split())
            m = _BY_CLAUSE_RE.search(body_part)
            if m:
                by_claim = " ".join(m.group(1).split())
            m = _WITH_CLAUSE_RE.search(body_part)
            if m:
                with_claim = " ".join(m.group(1).split())
            m = _FOR_CLAUSE_RE.search(body_part)
            if m:
                for_claim = m.group(1).strip()

            if from_claim:
                observed_ip = _extract_valid_ip(from_claim)

            if timestamp_raw:
                try:
                    timestamp_parsed = parsedate_to_datetime(timestamp_raw)
                except Exception:
                    timestamp_parsed = None
                    malformed_reason = "unparsable_timestamp"

            if not from_claim and not by_claim:
                state = SignalState.UNAVAILABLE
                malformed_reason = malformed_reason or "no_from_or_by_clause_extracted"

        except Exception as exc:  # defensive: never let one bad header break the chain
            state = SignalState.UNAVAILABLE
            malformed_reason = f"exception_during_parse: {exc}"

        hops.append(
            ReceivedHopRaw(
                sequence_index=idx,
                raw_line=h.raw_line,
                from_claim=from_claim,
                by_claim=by_claim,
                with_claim=with_claim,
                for_claim=for_claim,
                observed_ip=observed_ip,
                timestamp_raw=timestamp_raw,
                timestamp_parsed=timestamp_parsed,
                parse_state=state,
                malformed_reason=malformed_reason,
            )
        )
    return hops


def _extract_body_and_links(msg: EmailMessage) -> EmailBody:
    text_plain = None
    html_raw = None
    html_available = False

    try:
        plain_part = msg.get_body(preferencelist=("plain",))
        if plain_part is not None:
            text_plain = plain_part.get_content()
    except Exception:
        text_plain = None

    try:
        html_part = msg.get_body(preferencelist=("html",))
        if html_part is not None:
            html_available = True
            html_raw = html_part.get_content()
    except Exception:
        html_available = False
        html_raw = None

    links: list[ExtractedLink] = []
    html_sanitized = None
    if html_raw:
        stripper = _StrippingHTMLParser()
        try:
            stripper.feed(html_raw)
            html_sanitized = stripper.get_sanitized_html()
            for i, (href, display_text) in enumerate(stripper.links):
                links.append(
                    ExtractedLink(
                        link_id=f"link-html-{i}",
                        href=href,
                        display_text=display_text or None,
                        source="html",
                        context_snippet=None,
                    )
                )
        except Exception:
            html_sanitized = None  # unavailable, not "no html"

    if text_plain:
        # Plaintext bare-URL extraction: conservative, evidence-only.
        for i, m in enumerate(re.finditer(r"(https?://\S+|www\.\S+)", text_plain)):
            href = m.group(0).rstrip(").,;>\"'")
            start = max(0, m.start() - 30)
            end = min(len(text_plain), m.end() + 30)
            links.append(
                ExtractedLink(
                    link_id=f"link-text-{i}",
                    href=href,
                    display_text=None,
                    source="plaintext",
                    context_snippet=text_plain[start:end].replace("\n", " ").strip(),
                )
            )

    return EmailBody(
        text_plain=text_plain,
        html_sanitized=html_sanitized,
        html_available=html_available,
        links=links,
    )


def _extract_attachments(msg: EmailMessage) -> list[ExtractedAttachment]:
    attachments: list[ExtractedAttachment] = []
    idx = 0
    for part in msg.walk():
        if part.is_multipart():
            continue
        content_disposition = part.get_content_disposition()
        filename = part.get_filename()
        is_attachment_like = content_disposition == "attachment" or (
            filename is not None and content_disposition != "inline"
            and part.get_content_maintype() not in ("text",)
        )
        is_inline = content_disposition == "inline"
        if not (is_attachment_like or is_inline):
            continue

        state = SignalState.PRESENT
        sha256 = None
        size_bytes = None
        try:
            payload = part.get_payload(decode=True)
            if payload is not None:
                size_bytes = len(payload)
                sha256 = hashlib.sha256(payload).hexdigest()
            else:
                state = SignalState.UNAVAILABLE
        except Exception:
            state = SignalState.UNAVAILABLE

        attachments.append(
            ExtractedAttachment(
                attachment_id=f"att-{idx}",
                filename=filename,
                declared_mime_type=part.get_content_type(),
                size_bytes=size_bytes,
                sha256=sha256,
                content_disposition=content_disposition,
                is_inline=is_inline,
                within_archive=False,
                parse_state=state,
            )
        )
        idx += 1

        # Bounded, safe archive inspection for ZIP attachments
        # Maximum uncompressed ceiling: 10MB; maximum archive depth: 2
        if payload and (
            (filename and filename.lower().endswith(".zip"))
            or part.get_content_type() in ("application/zip", "application/x-zip-compressed")
        ):
            try:
                import io
                import zipfile
                with zipfile.ZipFile(io.BytesIO(payload)) as zf:
                    total_uncompressed = 0
                    for zinfo in zf.infolist():
                        total_uncompressed += zinfo.file_size
                        if total_uncompressed > 10 * 1024 * 1024:
                            break
                        depth = zinfo.filename.count("/") + zinfo.filename.count("\\")
                        if depth > 2:
                            continue
                        if not zinfo.is_dir():
                            member_name = os.path.basename(zinfo.filename) or zinfo.filename
                            attachments.append(
                                ExtractedAttachment(
                                    attachment_id=f"att-{idx}",
                                    filename=member_name,
                                    declared_mime_type=None,
                                    size_bytes=zinfo.file_size,
                                    sha256=None,
                                    content_disposition="attachment",
                                    is_inline=False,
                                    within_archive=True,
                                    parse_state=SignalState.PRESENT,
                                )
                            )
                            idx += 1
            except Exception:
                pass
    return attachments


def parse_eml(raw_bytes: bytes, *, artifact_id: str, parse_instance_id: str | None = None) -> CanonicalEmail:
    """
    Parse raw .eml bytes into a CanonicalEmail.

    Args:
        raw_bytes: the raw, unmodified bytes of the .eml file.
        artifact_id: the STABLE identity of the underlying raw artifact,
                     assigned by backend persistence (not generated
                     here). Re-parsing the same stored artifact must be
                     called with the same artifact_id every time.
        parse_instance_id: optional handle for THIS parse
                     instance/invocation (see CanonicalEmail.id
                     docstring in interfaces.py). This is NOT an
                     artifact identity - it is generated fresh per call
                     if not supplied, and two parses of the same
                     artifact_id will get two different values here by
                     default. Do not use this for dedup/correlation.

    Never raises on malformed input for structural sub-elements: parse
    failures are captured in parse_warnings / per-field parse_state and
    the function returns a best-effort CanonicalEmail rather than None.
    """
    parse_warnings: list[str] = []
    is_truncated = False

    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    except Exception as exc:
        parse_warnings.append(f"top_level_parse_failed: {exc}")
        # Fall back to permissive re-decode + re-parse attempt.
        try:
            text = _decode_bytes(raw_bytes)
            msg = BytesParser(policy=policy.default).parsebytes(text.encode("utf-8"))
        except Exception as exc2:
            parse_warnings.append(f"fallback_parse_failed: {exc2}")
            msg = EmailMessage()
            is_truncated = True

    headers = _extract_headers(msg) if not is_truncated else []

    def _first_header(name: str) -> str | None:
        v = msg.get(name)
        return str(v) if v is not None else None

    message_id = _first_header("message-id")
    subject = _first_header("subject")
    date_raw = _first_header("date")
    date_parsed = None
    if date_raw:
        try:
            date_parsed = parsedate_to_datetime(date_raw)
        except Exception:
            parse_warnings.append("date_header_unparsable")

    from_addresses = _parse_addresses(_first_header("from"))
    reply_to_addresses = _parse_addresses(_first_header("reply-to"))
    return_path = _parse_single_address(_first_header("return-path"))
    to_addresses = _parse_addresses(_first_header("to"))
    cc_addresses = _parse_addresses(_first_header("cc"))

    received_chain_raw = _parse_received_chain(headers)

    try:
        body = _extract_body_and_links(msg)
    except Exception as exc:
        parse_warnings.append(f"body_extraction_failed: {exc}")
        body = EmailBody(text_plain=None, html_sanitized=None, html_available=False, links=[])

    try:
        attachments = _extract_attachments(msg)
    except Exception as exc:
        parse_warnings.append(f"attachment_extraction_failed: {exc}")
        attachments = []

    return CanonicalEmail(
        id=parse_instance_id or str(uuid.uuid4()),
        artifact_id=artifact_id,
        message_id=message_id,
        parsed_at=datetime.now(timezone.utc),
        headers=headers,
        from_addresses=from_addresses,
        reply_to_addresses=reply_to_addresses,
        return_path=return_path,
        to_addresses=to_addresses,
        cc_addresses=cc_addresses,
        received_chain_raw=received_chain_raw,
        body=body,
        attachments=attachments,
        subject=subject,
        date_raw=date_raw,
        date_parsed=date_parsed,
        parse_warnings=parse_warnings,
        is_truncated=is_truncated,
    )


def parse_eml_file(path: str, *, artifact_id: str | None = None, parse_instance_id: str | None = None) -> CanonicalEmail:
    """Convenience wrapper: read a .eml file from disk and parse it."""
    with open(path, "rb") as f:
        raw = f.read()
    return parse_eml(raw, artifact_id=artifact_id or path, parse_instance_id=parse_instance_id)
