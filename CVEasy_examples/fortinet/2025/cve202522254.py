from comfy import high


@high(
    name="rule_cve202522254",
    platform=["fortinet_fortinet"],
    commands=dict(
        show_version="get system status",
        show_admins="show system admin",
        show_global="show system global",
    ),
)
def rule_cve202522254(configuration, commands, device, devices):
    """
    CVE-2025-22254 (Fortinet FortiOS / FortiProxy / FortiWeb) - Privilege escalation in GUI websocket module (CWE-269).

    Advisory summary (Fortinet PSIRT, FG-IR-25-006, 2025-06-10):
      - An authenticated attacker with at least read-only admin permissions may gain super-admin privileges
        via crafted requests to the Node.js websocket module (GUI component).

    Affected / fixed versions (per advisory):
      FortiOS:
        - 7.6.0 - 7.6.1  -> fixed in 7.6.2+
        - 7.4.0 - 7.4.6  -> fixed in 7.4.7+
        - 7.2.0 - 7.2.10 -> fixed in 7.2.11+
        - 7.0.0 - 7.0.16 -> fixed in 7.0.17+
        - 6.4.0 - 6.4.15 -> fixed in 6.4.16+
      FortiProxy:
        - 7.6.0 - 7.6.1  -> fixed in 7.6.2+
        - 7.4.0 - 7.4.7  -> fixed in 7.4.8+
      FortiWeb:
        - 7.6.0 - 7.6.1  -> fixed in 7.6.2+
        - 7.4.0 - 7.4.6  -> fixed in 7.4.7+

    Vulnerable configuration (exposure heuristic):
      - Device is running an affected version train below the fixed version, AND
      - GUI is enabled (HTTPS admin access), AND
      - At least one admin account exists with read-only permissions (or equivalent limited profile),
        meaning a low-privileged authenticated admin could attempt the escalation.

    Non-vulnerable scenarios:
      - Version is at/above the fixed version for its train, OR
      - Version cannot be parsed (rule returns safe), OR
      - GUI is not enabled (no HTTPS admin access), OR
      - No read-only (or similarly limited) admin accounts exist.

    Advisory:
      - https://www.fortiguard.com/psirt/FG-IR-25-006
    """
    version_text = commands.show_version or ""
    admins_text = (commands.show_admins or "").lower()
    global_text = (commands.show_global or "").lower()

    def _parse_version(text: str):
        """
        Fortinet version formats commonly seen:
          - 'FortiOS v7.4.6,build....'
          - 'Version: 7.4.6'
          - 'FortiProxy v7.4.7,...'
          - 'FortiWeb v7.6.1,...'
        Return (major, minor, patch) or None.
        """
        import re

        # Prefer explicit "Version: x.y.z"
        m = re.search(r"\bversion:\s*([0-9]+)\.([0-9]+)\.([0-9]+)\b", text, re.IGNORECASE)
        if m:
            return (int(m.group(1)), int(m.group(2)), int(m.group(3)))

        # Then "vX.Y.Z"
        m = re.search(r"\bv([0-9]+)\.([0-9]+)\.([0-9]+)\b", text, re.IGNORECASE)
        if m:
            return (int(m.group(1)), int(m.group(2)), int(m.group(3)))

        return None

    def _is_version_vulnerable(text: str):
        """
        Train-based matching. Only trains explicitly listed as affected in the advisory are included.
        Returns (is_vuln: bool, parsed_version: tuple|None, fixed_version: tuple|None)
        """
        v = _parse_version(text)
        if not v:
            return (False, None, None)

        # Per-train first fixed version (exclusive upper bound: v < fix => vulnerable)
        fixed_by_train = {
            (7, 6): (7, 6, 2),
            (7, 4): (7, 4, 7),
            (7, 2): (7, 2, 11),
            (7, 0): (7, 0, 17),
            (6, 4): (6, 4, 16),
        }

        train = (v[0], v[1])
        fix = fixed_by_train.get(train)
        if not fix:
            # Not an affected train per advisory.
            return (False, v, None)

        return (v < fix, v, fix)

    version_vulnerable, parsed_v, fixed_v = _is_version_vulnerable(version_text)

    # Configuration heuristics:
    # 1) GUI enabled: look for admin HTTPS access in global settings.
    # Typical snippets:
    #   set admin-sport 443
    #   set admin-https-redirect enable
    #   set admin-https-ssl-versions tlsv1-2 tlsv1-3
    #   set admin-https enable
    #   set admin-https-redirect enable
    #   set admin-https-ssl-versions ...
    #
    # FortiOS often uses "set admin-https enable" under "config system global" on some versions,
    # but not always shown. We'll treat presence of "admin-https" or "admin-sport" as GUI/HTTPS enabled.
    gui_https_enabled = ("admin-https" in global_text) or ("admin-sport" in global_text)

    # 2) Presence of at least one read-only (or similarly limited) admin.
    # Typical "show system admin" output includes:
    #   edit "roadmin"
    #       set accprofile "read_only"
    #   next
    # or
    #       set accprofile "ReadOnly"
    #
    # We'll match common read-only profile names and also accept explicit "read-only" token.
    import re

    has_readonly_admin = False
    # Find accprofile lines and check for read-only-ish names.
    for m in re.finditer(r"\bset\s+accprofile\s+\"?([a-z0-9_\- ]+)\"?\b", admins_text, re.IGNORECASE):
        prof = (m.group(1) or "").strip().lower()
        if prof in ("read_only", "readonly", "read-only", "read only", "ro", "monitor", "super_read_only"):
            has_readonly_admin = True
            break
        # Heuristic: profile name contains "read" and "only"
        if ("read" in prof) and ("only" in prof):
            has_readonly_admin = True
            break

    config_vulnerable = gui_https_enabled and has_readonly_admin
    is_vulnerable = version_vulnerable and config_vulnerable

    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-22254 (Fortinet FortiOS/FortiProxy/FortiWeb): "
        "an authenticated attacker with at least read-only admin permissions may gain super-admin privileges "
        "via crafted requests to the Node.js websocket module (GUI) (CWE-269). "
        f"Detected affected version {'.'.join(map(str, parsed_v)) if parsed_v else 'unparsed'}"
        f"{' (fixed in ' + '.'.join(map(str, fixed_v)) + '+)' if fixed_v else ''}, "
        f"GUI/HTTPS appears enabled, and at least one read-only (or similarly limited) admin profile is present. "
        "Remediation: upgrade to the fixed release for your train (FortiOS: 7.6.2+/7.4.7+/7.2.11+/7.0.17+/6.4.16+; "
        "FortiProxy: 7.6.2+/7.4.8+; FortiWeb: 7.6.2+/7.4.7+) and restrict/monitor GUI admin access. "
        "Advisory: https://www.fortiguard.com/psirt/FG-IR-25-006"
    )