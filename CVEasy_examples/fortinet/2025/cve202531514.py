from comfy import high


@high(
    name="rule_cve202531514",
    platform=["fortinet_fortinet"],
    commands=dict(
        show_version="get system status",
        show_log_settings="show log setting",
        show_admins="show system admin",
    ),
)
def rule_cve202531514(configuration, commands, device, devices):
    """
    CVE-2025-31514 (Fortinet FortiOS) - Insertion of Sensitive 2FA Information into logs/diagnose output (CWE-532).

    Advisory summary:
      - FortiOS affected: 7.6.0 through 7.6.3; 7.4 all versions; 7.2 all versions; 7.0 all versions; 6.4 all versions.
      - Impact: An attacker with at least read-only privileges may retrieve sensitive 2FA-related information
        by observing logs or via diagnose command output.
      - Fixed: FortiOS 7.6.4+ (for 7.6 train). Other trains: "migrate to a fixed release" (no fixed version specified).

    Detection approach (configuration exposure heuristic):
      - Device is running an affected FortiOS release train/version, AND
      - There exists at least one admin account with read-only privileges (or profile) that could access logs/diagnose.

    Notes:
      - This is an information disclosure issue; the vulnerable "configuration" is effectively the presence of
        read-only administrative access combined with affected software.
      - If version cannot be parsed, treat as safe (do not flag) to avoid false positives.
      - If admin configuration cannot be retrieved, treat as safe (do not flag) to avoid false positives.
    """
    version_text = commands.show_version or ""
    admins_text = commands.show_admins or ""
    log_settings_text = commands.show_log_settings or ""

    def _parse_version(text: str):
        """
        FortiOS version formats commonly seen:
          - 'FortiOS v7.6.3,buildxxxx,...'
          - 'Version: 7.6.3'
        Return (major, minor, patch) as ints, or None if not found.
        """
        import re

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
        Release-train-based matching per advisory.

        Trains explicitly listed as affected:
          - 7.6: vulnerable < 7.6.4 (since 7.6.0 through 7.6.3)
          - 7.4: all versions affected (no fixed version specified in advisory)
          - 7.2: all versions affected
          - 7.0: all versions affected
          - 6.4: all versions affected

        If a train is "all versions", we treat any parsed version in that train as vulnerable.
        If version cannot be parsed, return False (safe).
        """
        v = _parse_version(text)
        if not v:
            return False

        train = (v[0], v[1])
        fixed_by_train = {
            (7, 6): (7, 6, 4),  # fixed in 7.6.4 and above
            (7, 4): None,  # all versions affected (per advisory)
            (7, 2): None,  # all versions affected
            (7, 0): None,  # all versions affected
            (6, 4): None,  # all versions affected
        }

        if train not in fixed_by_train:
            return False

        fix = fixed_by_train[train]
        if fix is None:
            return True
        return v < fix

    def _has_readonly_admin(text: str):
        """
        Heuristic: detect at least one admin configured with read-only privileges/profile.

        Common FortiOS admin config patterns:
          config system admin
              edit "auditor"
                  set accprofile "read_only"
              next
          end

        Also seen:
          set accprofile "super_admin"
          set accprofile "prof_readonly"
          set accprofile "Read-Only"

        We flag if we see an accprofile containing 'read' and 'only' (case-insensitive),
        or explicit 'readonly' token.
        """
        import re

        if not text.strip():
            return False

        # Look for any accprofile assignment that indicates read-only.
        # Keep it conservative: require "read" and ("only" or "readonly") in the profile name.
        for m in re.finditer(r'\bset\s+accprofile\s+"([^"]+)"', text, re.IGNORECASE):
            prof = (m.group(1) or "").strip().lower()
            if "readonly" in prof or ("read" in prof and "only" in prof):
                return True

        # Some configs may omit quotes.
        for m in re.finditer(r"\bset\s+accprofile\s+([^\s]+)", text, re.IGNORECASE):
            prof = (m.group(1) or "").strip().strip('"').lower()
            if "readonly" in prof or ("read" in prof and "only" in prof):
                return True

        return False

    version_vulnerable = _is_version_vulnerable(version_text)
    readonly_admin_present = _has_readonly_admin(admins_text)

    # Optional additional context: if logging is enabled, exposure is more plausible.
    # Do not require it for detection (advisory says logs OR diagnose).
    logging_enabled = "set status enable" in (log_settings_text or "").lower()

    is_vulnerable = version_vulnerable and readonly_admin_present

    v = _parse_version(version_text)
    v_str = ".".join(str(x) for x in v) if v else "unparsed"

    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-31514 (Fortinet FortiOS): "
        "sensitive 2FA-related information may be inserted into log files and/or exposed via diagnose output (CWE-532), "
        "allowing an attacker with at least read-only privileges to retrieve it. "
        f"Detected affected FortiOS version ({v_str}) and at least one read-only admin profile configured. "
        f"{'Logging appears enabled, increasing likelihood of exposure via logs. ' if logging_enabled else ''}"
        "Remediation: upgrade to FortiOS 7.6.4+ if on 7.6.0-7.6.3; for 7.4/7.2/7.0/6.4 migrate to a fixed release per Fortinet guidance, "
        "and restrict/monitor read-only administrative access to logs/diagnose. "
        "Advisory: https://www.fortiguard.com/psirt/FG-IR-24-452"
    )