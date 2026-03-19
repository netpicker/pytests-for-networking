from comfy import high


@high(
    name="rule_cve202525253",
    platform=["fortinet_fortinet"],
    commands=dict(
        show_version="get system status",
        show_ztna="show firewall ztna",
        show_ztna_server="show firewall ztna-server",
    ),
)
def rule_cve202525253(configuration, commands, device, devices):
    """
    CVE-2025-25253 (Fortinet FortiOS / FortiProxy) - ZTNA proxy improper certificate validation (host mismatch) (CWE-297).

    Summary (Fortinet PSIRT, 2025-10-14):
      - FortiOS and FortiProxy ZTNA proxy improperly validates certificates with host mismatch.
      - An unauthenticated attacker in a man-in-the-middle position may intercept and tamper with connections to the ZTNA proxy.

    Affected versions / fixed versions (per advisory):
      FortiOS:
        - 7.6.0 through 7.6.2  -> fixed in 7.6.3+
        - 7.4.0 through 7.4.8  -> fixed in 7.4.9+
        - 7.2 all versions     -> migrate to a fixed release (treat all 7.2.x as affected)
        - 7.0 all versions     -> migrate to a fixed release (treat all 7.0.x as affected)
      FortiProxy:
        - 7.6.0 through 7.6.1  -> fixed in 7.6.2+
        - 7.4.0 through 7.4.8  -> fixed in 7.4.9+
        - 7.2 all versions     -> migrate to a fixed release (treat all 7.2.x as affected)
        - 7.0 all versions     -> migrate to a fixed release (treat all 7.0.x as affected)

    Vulnerable configuration (exposure heuristic):
      - Device is running an affected FortiOS/FortiProxy version, AND
      - ZTNA proxy feature appears configured/enabled (presence of ZTNA config blocks / ztna-server entries).

    Non-vulnerable scenarios:
      - Version is not in an affected train or is at/above the fixed version for that train, OR
      - ZTNA is not configured (no ZTNA proxy usage detected), OR
      - Version cannot be parsed (rule returns safe to avoid false positives).

    Advisory:
      - https://www.fortiguard.com/psirt/FG-IR-24-457
    """
    version_text = commands.show_version or ""
    ztna_text = (commands.show_ztna or "").lower()
    ztna_server_text = (commands.show_ztna_server or "").lower()

    def _parse_version(text: str):
        """
        Extract Fortinet version as (major, minor, patch).
        Accepts patterns like:
          - "FortiOS v7.6.2,build..."
          - "FortiProxy v7.4.8,build..."
          - "Version: 7.6.2"
        """
        import re

        m = re.search(r"\b(?:fortios|fortiproxy)\s+v(\d+)\.(\d+)\.(\d+)\b", text, re.IGNORECASE)
        if m:
            return (int(m.group(1)), int(m.group(2)), int(m.group(3)))

        m = re.search(r"\bversion:\s*(\d+)\.(\d+)\.(\d+)\b", text, re.IGNORECASE)
        if m:
            return (int(m.group(1)), int(m.group(2)), int(m.group(3)))

        return None

    def _detect_product(text: str):
        import re

        if re.search(r"\bfortiproxy\b", text, re.IGNORECASE):
            return "fortiproxy"
        if re.search(r"\bfortios\b", text, re.IGNORECASE):
            return "fortios"
        # Fallback: FortiGate typically reports FortiOS; treat unknown as FortiOS for train logic,
        # but version parsing failure will return safe anyway.
        return "fortios"

    def _is_version_vulnerable(text: str):
        """
        Release-train-based matching only.
        Returns (is_vuln: bool, parsed_version: tuple|None, product: str|None, rationale: str)
        """
        v = _parse_version(text)
        if not v:
            return (False, None, None, "version_unparsed")

        product = _detect_product(text)

        # Per-train first fixed versions (exclusive upper bound: v < fix => vulnerable).
        # For "all versions" trains, use a sentinel fix of next major train boundary.
        if product == "fortiproxy":
            fixed_by_train = {
                (7, 6): (7, 6, 2),
                (7, 4): (7, 4, 9),
                (7, 2): (7, 3, 0),  # all 7.2.x affected
                (7, 0): (7, 1, 0),  # all 7.0.x affected
            }
        else:  # fortios
            fixed_by_train = {
                (7, 6): (7, 6, 3),
                (7, 4): (7, 4, 9),
                (7, 2): (7, 3, 0),  # all 7.2.x affected
                (7, 0): (7, 1, 0),  # all 7.0.x affected
            }

        train = (v[0], v[1])
        fix = fixed_by_train.get(train)
        if not fix:
            return (False, v, product, "train_not_affected")

        return (v < fix, v, product, f"affected_train_fix_{fix[0]}.{fix[1]}.{fix[2]}")

    def _is_ztna_configured(ztna_cfg: str, ztna_server_cfg: str) -> bool:
        """
        Heuristic: mark as configured if ZTNA is explicitly enabled or a ztna-server entry exists.
        Presence of the config block alone (e.g. set status disable) is not sufficient.
        """
        ztna_enabled = "set status enable" in ztna_cfg
        ztna_server_has_entries = "edit " in ztna_server_cfg
        return ztna_enabled or ztna_server_has_entries

    version_vuln, v, product, rationale = _is_version_vulnerable(version_text)
    ztna_configured = _is_ztna_configured(ztna_text, ztna_server_text)

    is_vulnerable = bool(version_vuln and ztna_configured)

    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-25253 (Fortinet {product or 'FortiOS/FortiProxy'}): "
        "ZTNA proxy improperly validates certificates with host mismatch (CWE-297), allowing an unauthenticated "
        "man-in-the-middle attacker to intercept and tamper with connections to the ZTNA proxy. "
        f"Detected affected version ({'.'.join(map(str, v)) if v else 'unparsed'}; {rationale}) and ZTNA appears "
        "configured/enabled on this device. Remediation: upgrade to a fixed release per Fortinet advisory "
        "(FortiOS 7.6.3+/7.4.9+; FortiProxy 7.6.2+/7.4.9+; migrate off 7.2/7.0 trains) and review ZTNA deployment "
        "for exposure to MITM. Advisory: https://www.fortiguard.com/psirt/FG-IR-24-457"
    )