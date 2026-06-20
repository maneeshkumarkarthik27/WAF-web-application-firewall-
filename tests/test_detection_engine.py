from __future__ import annotations

from app.detection.engine import DetectionEngine


def test_detection_engine_detects_common_attack_patterns() -> None:
    engine = DetectionEngine()

    sqli_findings = engine.inspect("' OR 1=1 UNION SELECT password FROM users", location="query:q")
    xss_findings = engine.inspect("<script>alert(1)</script>", location="body")
    encoded_xss_findings = engine.inspect("%3Cscript%3Ealert(1)%3C/script%3E", location="body")
    cmd_findings = engine.inspect("id; cat /etc/passwd && whoami", location="body")
    traversal_findings = engine.inspect("..%2f..%2fetc%2fpasswd", location="body")
    user_agent_findings = engine.inspect("sqlmap/1.8.0", location="user-agent")

    assert any(finding.finding_type.startswith("sqli") for finding in sqli_findings)
    assert any(finding.finding_type.startswith("xss") for finding in xss_findings)
    assert any(finding.finding_type == "xss_encoded_payload" for finding in encoded_xss_findings)
    assert any(finding.finding_type.startswith("cmd_injection") for finding in cmd_findings)
    assert any(finding.finding_type.startswith("dir_traversal") for finding in traversal_findings)
    assert any(finding.finding_type == "malicious_user_agent" for finding in user_agent_findings)
