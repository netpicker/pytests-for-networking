from comfy import high


@high(
    name="rule_cve202562439",
    platform=["fortinet"],
    commands=dict(
        show_version="get system status",
        show_fsso="show user fsso",
    ),
)
def rule_cve202562439(configuration, commands, device, devices):
    """
    CVE-2025-62439 (Fortinet FortiOS) - Firewall policy bypass in FSSO Terminal Services Agent
    (Improper Verification of Source of a Communication Channel, CWE-940).

    Affected FortiOS versions (per advisory FG-IR-25-384):
      - FortiOS 7.6.0 through 7.6.4
      - FortiOS 7.4.0 through 7.4.9
      - FortiOS 7.2 all versions
      - FortiOS 7.0 all versions
      - FortiOS 8.0: not affected
      - FortiOS 6.4: not affected

    Vulnerable scenario (heuristic):
      - Device runs an affected FortiOS version, AND
      - FSSO is configured and includes a Terminal Services Agent (TS Agent) / collector agent entry
        (heuristic: 'config user fsso' present and either 'set type collector' or 'collector-agent' appears).

    Non-vulnerable scenarios:
      - FortiOS version is not in an affected branch/range, OR
      - FSSO / TS Agent is not configured (no 'config user fsso' / no collector agent indications).

    Advisory: https://fortiguard.com/psirt/FG-IR-25-384
    """
    version_output = (commands.show_version or "").lower()
    fsso_output = (commands.show_fsso or "").lower()

    def _extract_version(text: str):
        # Common FortiOS outputs include:
        #   "FortiOS v7.4.6,build...."
        #   "Version: 7.4.6"
        import re

        m = re.search(r"\bversion:\s*([0-9]+\.[0-9]+\.[0-9]+)\b", text, re.IGNORECASE)
        if m:
            return m.group(1)
        m = re.search(r"\bv([0-9]+\.[0-9]+\.[0-9]+)\b", text, re.IGNORECASE)
        if m:
            return m.group(1)
        return None

    def _parse_semver(v: str):
        try:
            a, b, c = v.split(".")
            return int(a), int(b), int(c)
        except Exception:
            return None

    def _in_range(v: str, lo: str, hi: str):
        pv = _parse_semver(v)
        plo = _parse_semver(lo)
        phi = _parse_semver(hi)
        if not (pv and plo and phi):
            return False
        return plo <= pv <= phi

    detected_version = _extract_version(commands.show_version or "")

    # Version vulnerable if:
    # - 7.6.0..7.6.4
    # - 7.4.0..7.4.9
    # - 7.2.* (all)
    # - 7.0.* (all)
    version_vulnerable = False
    if detected_version:
        if _in_range(detected_version, "7.6.0", "7.6.4"):
            version_vulnerable = True
        elif _in_range(detected_version, "7.4.0", "7.4.9"):
            version_vulnerable = True
        else:
            pv = _parse_semver(detected_version)
            if pv:
                major, minor, _patch = pv
                if major == 7 and minor in (0, 2):
                    version_vulnerable = True
    else:
        # Fallback heuristic if we cannot parse version cleanly.
        # Treat explicit 7.0/7.2 as vulnerable; 7.4/7.6 require patch parsing.
        if "fortios v7.0" in version_output or "version: 7.0" in version_output:
            version_vulnerable = True
        if "fortios v7.2" in version_output or "version: 7.2" in version_output:
            version_vulnerable = True

    # Strip comment lines before checking for indicators to avoid false positives
    # (e.g. a comment "# no collector agent present" should not trigger detection).
    import re as _re
    fsso_no_comments = "\n".join(
        line for line in fsso_output.splitlines() if not _re.match(r"\s*#", line)
    )

    # Configuration vulnerable heuristic: FSSO configured with collector/TS agent.
    fsso_config_present = "config user fsso" in fsso_no_comments
    ts_agent_indicators = any(
        s in fsso_no_comments
        for s in [
            "set type collector",
            "collector-agent",
            "collector agent",
            "ts agent",
            "terminal server",
            "terminal services",
        ]
    )
    config_vulnerable = fsso_config_present and ts_agent_indicators

    # Safe configuration heuristic: no FSSO config or no collector/TS agent indications.
    config_safe = (not fsso_config_present) or (fsso_config_present and not ts_agent_indicators)

    is_vulnerable = version_vulnerable and config_vulnerable and not config_safe

    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-62439 (Fortinet FortiOS): "
        "an authenticated user with knowledge of FSSO policy configurations may gain unauthorized access "
        "to protected network resources via crafted requests due to improper verification of the source of a "
        "communication channel in the FSSO Terminal Services Agent. "
        f"Detected affected FortiOS version ({detected_version or 'unknown'}) and FSSO/TS Agent (collector) configuration "
        "('config user fsso' with collector/TS agent indicators found in 'show user fsso'). "
        "Remediation: upgrade FortiOS to a fixed release (7.6.5+ with FSSO TS Agent 5.0 build 0324+, "
        "7.4.10+ with FSSO TS Agent 5.0 build 0324+, or migrate from 7.2/7.0 to a fixed release) and ensure "
        "FSSO TS Agent is updated to 5.0 build 0324 or later. "
        "Advisory: https://fortiguard.com/psirt/FG-IR-25-384"
    )