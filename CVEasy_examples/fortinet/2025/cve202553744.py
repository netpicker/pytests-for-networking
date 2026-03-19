from comfy import high


@high(
    name="rule_cve202553744",
    platform=["fortinet_fortinet"],
    commands=dict(
        show_version="get system status",
        show_fabric="show system csf",
        show_admins="show system admin",
    ),
)
def rule_cve202553744(configuration, commands, device, devices):
    """
    CVE-2025-53744 (Fortinet FortiOS) - Incorrect privilege assignment in Security Fabric (CWE-266).

    Summary (Fortinet PSIRT, 2025-08-12):
      - An incorrect privilege assignment vulnerability in FortiOS Security Fabric may allow a remote authenticated
        attacker with high privileges to escalate to super-admin by registering the device to a malicious FortiManager.

    Affected versions / fixed versions (per advisory):
      - FortiOS 7.6.0 through 7.6.2  -> fixed in 7.6.3+
      - FortiOS 7.4.0 through 7.4.7  -> fixed in 7.4.8+
      - FortiOS 7.2 all versions     -> migrate to a fixed release (no fixed version specified in-train)
      - FortiOS 7.0 all versions     -> migrate to a fixed release (no fixed version specified in-train)
      - FortiOS 6.4 all versions     -> migrate to a fixed release (no fixed version specified in-train)

    Vulnerable configuration (exposure heuristic):
      - Device runs an affected FortiOS version, AND
      - Security Fabric is enabled/used such that the device can be (or is) registered to FortiManager
        (i.e., FortiManager/Fabric management is enabled or configured).

    Non-vulnerable scenarios:
      - FortiOS is at/above the fixed version for the train (7.6.3+, 7.4.8+), OR
      - FortiOS is not in an affected train, OR
      - Security Fabric / FortiManager registration is not enabled/configured (reduces exposure to the described path).

    Advisory:
      - https://www.fortiguard.com/psirt/FG-IR-25-173
    """
    import re

    version_text = commands.show_version or ""
    fabric_text = (commands.show_fabric or "")
    admins_text = (commands.show_admins or "")

    def _parse_version(text: str):
        """
        Extract FortiOS version as (major, minor, patch).
        Accepts common outputs like:
          - "FortiOS v7.4.7,build...."
          - "Version: 7.4.7"
        """
        m = re.search(r"\bFortiOS\s+v(\d+)\.(\d+)\.(\d+)\b", text, re.IGNORECASE)
        if not m:
            m = re.search(r"\bVersion:\s*(\d+)\.(\d+)\.(\d+)\b", text, re.IGNORECASE)
        if not m:
            m = re.search(r"\bv(\d+)\.(\d+)\.(\d+)\b", text, re.IGNORECASE)
        if not m:
            return None
        return (int(m.group(1)), int(m.group(2)), int(m.group(3)))

    def _is_version_vulnerable(text: str):
        """
        Release-train-based matching only for trains explicitly listed as affected.
        Returns (is_vuln: bool, parsed_version: tuple|None, reason: str).
        If version cannot be parsed, return safe (False).
        """
        v = _parse_version(text)
        if not v:
            return (False, None, "version_unparsed")

        train = (v[0], v[1])

        # For trains with a stated fixed version, treat as vulnerable if v < fixed.
        fixed_by_train = {
            (7, 6): (7, 6, 3),  # 7.6.0-7.6.2 affected; fixed in 7.6.3+
            (7, 4): (7, 4, 8),  # 7.4.0-7.4.7 affected; fixed in 7.4.8+
        }
        if train in fixed_by_train:
            return (v < fixed_by_train[train], v, f"fixed_in_{fixed_by_train[train]}")

        # For trains marked "all versions" affected, any parsed version in that train is vulnerable.
        all_versions_affected_trains = {(7, 2), (7, 0), (6, 4)}
        if train in all_versions_affected_trains:
            return (True, v, "all_versions_affected_in_train")

        # Not an affected train per advisory.
        return (False, v, "train_not_affected")

    def _is_fabric_fortimanager_configured(fabric_cfg: str):
        """
        Heuristic: consider device exposed if Security Fabric / FortiManager registration is enabled/configured.
        We look for common FortiOS CSF/Fabric/FortiManager management indicators.
        """
        t = (fabric_cfg or "").lower()

        # Common patterns seen in "show system csf" / fabric-related config:
        #   set status enable
        #   set fabric-object-unification enable
        #   set group-name ...
        #   set upstream "..."
        #   set upstream-port ...
        #   set accept-auth-cert enable
        # FortiManager-related patterns may appear as:
        #   set fortimanager ...
        #   set fmg ...
        #   set manager-ip ...
        #   set central-management ...
        # Only flag when fabric/fortimanager is actually enabled/configured.
        # "config system csf" alone (with set status disable) is not sufficient.
        # Require explicit status enable, upstream, or fortimanager-specific config.
        indicators = (
            "set upstream",
            "set group-name",
            "set accept-auth-cert enable",
            "fortimanager",
            "fmg",
            "central-management",
            "manager-ip",
            "set type fortimanager",
        )
        if any(ind in t for ind in indicators):
            return True
        # Only treat "set status enable" as a hit when it appears alongside the CSF block.
        if "config system csf" in t and "set status enable" in t:
            return True
        return False

    version_vuln, parsed_v, version_reason = _is_version_vulnerable(version_text)

    # Configuration exposure heuristic: fabric/fortimanager registration enabled/configured.
    fabric_configured = _is_fabric_fortimanager_configured(fabric_text)

    # Optional additional signal: presence of at least one high-privilege admin account.
    # (CVE requires authenticated attacker with high privileges; we don't attempt to prove exploitability,
    # but we can note if such roles exist.)
    admins_lower = admins_text.lower()
    has_high_priv_admin = ("set accprofile" in admins_lower) or ("super_admin" in admins_lower) or ("super-admin" in admins_lower)

    is_vulnerable = version_vuln and fabric_configured

    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-53744 (Fortinet FortiOS Security Fabric): "
        "incorrect privilege assignment (CWE-266) may allow a remote authenticated attacker with high privileges "
        "to escalate to super-admin by registering the device to a malicious FortiManager. "
        f"Detected affected FortiOS version ({'.'.join(map(str, parsed_v)) if parsed_v else 'unparsed'}; {version_reason}) "
        "and Security Fabric/FortiManager registration appears enabled/configured. "
        f"High-privilege admin presence signal: {'present' if has_high_priv_admin else 'unknown/not-detected'}. "
        "Remediation: upgrade to FortiOS 7.6.3+ (for 7.6) or 7.4.8+ (for 7.4), or migrate off affected 7.2/7.0/6.4 trains; "
        "and restrict/monitor FortiManager registration and Security Fabric settings. "
        "Advisory: https://www.fortiguard.com/psirt/FG-IR-25-173"
    )