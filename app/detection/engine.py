from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Iterable

from app.models.security import DetectionFinding, ThreatLevel
from app.utils.normalization import normalize_input


@dataclass(frozen=True)
class Rule:
    name: str
    pattern: re.Pattern[str]
    score: int
    severity: ThreatLevel
    location: str
    match_on_raw: bool = False


class DetectionEngine:
    """Regex-based detection engine that scores common web attack patterns."""

    def __init__(self) -> None:
        flags = re.IGNORECASE | re.DOTALL
        self.rules: tuple[Rule, ...] = (
            Rule("sqli_union_select", re.compile(r"\bunion\b\s+\bselect\b", flags), 70, ThreatLevel.high, "input"),
            Rule("sqli_or_true", re.compile(r"(?:'|\")?\s*or\s+1\s*=\s*1", flags), 70, ThreatLevel.high, "input"),
            Rule("sqli_information_schema", re.compile(r"information_schema", flags), 70, ThreatLevel.high, "input"),
            Rule("sqli_sleep", re.compile(r"\bsleep\s*\(", flags), 70, ThreatLevel.high, "input"),
            Rule("xss_script_tag", re.compile(r"<\s*script\b", flags), 70, ThreatLevel.high, "input"),
            Rule("xss_event_handler", re.compile(r"on\w+\s*=\s*", flags), 30, ThreatLevel.medium, "input"),
            Rule("xss_js_uri", re.compile(r"javascript\s*:", flags), 70, ThreatLevel.high, "input"),
            Rule("xss_encoded_payload", re.compile(r"(?:%3c|%3e|&#x3c;|&#x3e;|&lt;|&gt;)", flags), 30, ThreatLevel.medium, "input", True),
            Rule("cmd_injection_sep", re.compile(r"(?:;|&&|\|\|)", flags), 30, ThreatLevel.medium, "input"),
            Rule("cmd_injection_shell", re.compile(r"\b(?:sh|bash|zsh|cmd|powershell|nc|netcat)\b", flags), 70, ThreatLevel.high, "input"),
            Rule("cmd_injection_pipe", re.compile(r"\|\s*(?:sh|bash|python|perl|php)\b", flags), 70, ThreatLevel.high, "input"),
            Rule("dir_traversal_plain", re.compile(r"\.\./|\.\\\\", flags), 70, ThreatLevel.high, "input"),
            Rule("dir_traversal_encoded", re.compile(r"(?:%2e%2e%2f|%2e%2e/|%252e%252e%252f|%2e%2e%5c)", flags), 70, ThreatLevel.high, "input", True),
            Rule("malicious_user_agent", re.compile(r"(?:sqlmap|nikto|acunetix|netsparker|burp|crawler|scanner)", flags), 70, ThreatLevel.high, "user-agent"),
            Rule("bot_traffic", re.compile(r"(?:bot|spider|crawler|scrapy|python-requests|curl|wget)", flags), 10, ThreatLevel.low, "user-agent"),
        )

    def inspect(self, value: str, *, location: str, allow_bot_flagging: bool = True) -> list[DetectionFinding]:
        normalized = normalize_input(value)
        raw_value = value.lower()
        findings: list[DetectionFinding] = []
        for rule in self.rules:
            if rule.location != location and rule.location != "input":
                continue
            if rule.name == "bot_traffic" and not allow_bot_flagging:
                continue
            haystack = raw_value if rule.match_on_raw else normalized
            match = rule.pattern.search(haystack)
            if match:
                findings.append(
                    DetectionFinding(
                        finding_type=rule.name,
                        pattern=match.group(0),
                        score=rule.score,
                        severity=rule.severity,
                        location=location,
                    )
                )
        return findings

    def inspect_many(self, payloads: Iterable[tuple[str, str]]) -> list[DetectionFinding]:
        findings: list[DetectionFinding] = []
        for location, value in payloads:
            findings.extend(self.inspect(value, location=location))
        return findings
