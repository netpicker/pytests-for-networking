from comfy import high


@high(
    name="rule_cve202558325",
    platform=["fortinet_fortinet"],
    commands=dict(
        show_version="get system status",
        show_admins="show system admin",
        show_global="show system global",
    ),
)
def rule_cve202558325(configuration, commands, device, devices):
    """
    CVE-2025-58325 (Fortinet FortiOS) - Restricted CLI command bypass leading to system command execution (CWE-684).

    Advisory summary (Fortinet PSIRT, FG-IR-24-361):
      - Incorrect Provision of Specified Functionality in FortiOS CLI may allow a local authenticated attacker
        to execute system commands via crafted CLI commands (restricted CLI command bypass).

    Affected versions / fixed versions (per advisory):
      - FortiOS 7.6: 7.6.0 vulnerable; fixed in 7.6.1+
      - FortiOS 7.4: 7.4.0 through 7.4.5 vulnerable; fixed in 7.4.6+
      - FortiOS 7.2: 7.2.0 through 7.2.10 vulnerable; fixed in 7.2.11+
      - FortiOS 7.0: 7.0.0 through 7.0.15 vulnerable; fixed in 7.0.16+
      - FortiOS 6.4: all versions vulnerable; fixed release not specified (migrate to a fixed release)

    Vulnerable configuration (exposure heuristic):
      - Device runs an affected FortiOS version, AND
      - There exists at least one local admin account that can access the CLI (e.g., ssh/telnet/console enabled),
        AND
      - That admin is not a super_admin (i.e., a restricted admin profile), because the issue is a restricted
        CLI command bypass (privilege escalation).

    Non-vulnerable scenarios:
      - FortiOS version is at/above the fixed version for its train, OR
      - FortiOS version cannot be parsed (rule returns safe), OR
      - No local CLI-capable admin accounts are present, OR
      - Only super_admin accounts exist (no restricted admin to exploit the bypass).

    Advisory:
      - https://www.fortiguard.com/psirt
        (PSIRT advisory: "Restricted CLI command bypass", CVE-2025-58325, FG-IR-24-361)
    """
    import re

    version_text = commands.show_version or ""
    admins_text = (commands.show_admins or "").lower()
    global_text = (commands.show_global or "").lower()

    def _parse_version(text: str):
        """
        Extract FortiOS version as (major, minor, patch).
        Accepts common outputs like:
          - "FortiOS v7.4.5,build...."
          - "Version: 7.4.5"
          - "v7.4.5"
        """
        patterns = [
            r"\bfortios\s+v(\d+)\.(\d+)\.(\d+)\b",
            r"\bversion:\s*(\d+)\.(\d+)\.(\d+)\b",
            r"\bv(\d+)\.(\d+)\.(\d+)\b",
        ]
        for pat in patterns:
            m = re.search(pat, text, re.IGNORECASE)
            if m:
                return (int(m.group(1)), int(m.group(2)), int(m.group(3)))
        return None

    def _is_version_vulnerable(text: str):
        v = _parse_version(text)
        if not v:
            # Per requirements: return early (treat as safe) if version cannot be parsed.
            return (False, None, None)

        # Per-train first fixed versions (exclusive upper bound: v < fix is vulnerable).
        fixed_by_train = {
            (7, 6): (7, 6, 1),
            (7, 4): (7, 4, 6),
            (7, 2): (7, 2, 11),
            (7, 0): (7, 0, 16),
            # 6.4: all versions affected; no fixed version specified in advisory (migrate).
            # Treat any 6.4.x as vulnerable.
            (6, 4): None,
        }

        train = (v[0], v[1])
        if train not in fixed_by_train:
            return (False, v, None)

        fix = fixed_by_train[train]
        if fix is None:
            return (True, v, None)

        return (v < fix, v, fix)

    def _has_cli_capable_admin(admins_cfg: str) -> bool:
        """
        Heuristic: look for at least one admin stanza with CLI access enabled.
        FortiOS admin config commonly includes:
          set ssh-enable enable
          set telnet-enable enable
        Console access is typically implicit for local admins; we treat ssh/telnet as CLI-capable signals.
        """
        return ("set ssh-enable enable" in admins_cfg) or ("set telnet-enable enable" in admins_cfg)

    def _has_restricted_admin(admins_cfg: str) -> bool:
        """
        Heuristic: detect presence of an admin that is not super_admin.
        Common patterns:
          set accprofile "read_only"
          set accprofile "prof_name"
        Super admin often:
          set accprofile "super_admin"
        """
        # If we see any accprofile that is not super_admin, treat as restricted admin present.
        for m in re.finditer(r'set\s+accprofile\s+"([^"]+)"', admins_cfg, re.IGNORECASE):
            prof = (m.group(1) or "").strip().lower()
            if prof and prof != "super_admin":
                return True
        return False

    version_vuln, parsed_v, fixed_v = _is_version_vulnerable(version_text)

    # Configuration exposure heuristic
    cli_capable_admin_present = _has_cli_capable_admin(admins_text)
    restricted_admin_present = _has_restricted_admin(admins_text)

    # Optional hardening signal: if "admin-restrict-local" or similar exists, we do not rely on it.
    # Keep the heuristic focused on presence of restricted CLI-capable admins.
    config_vulnerable = cli_capable_admin_present and restricted_admin_present

    is_vulnerable = bool(version_vuln and config_vulnerable)

    fix_str = (
        "migrate to a fixed release (Fortinet advisory does not specify a fixed 6.4.x)"
        if parsed_v and (parsed_v[0], parsed_v[1]) == (6, 4)
        else (f"upgrade to {fixed_v[0]}.{fixed_v[1]}.{fixed_v[2]} or above" if fixed_v else "upgrade to a fixed release")
    )

    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-58325 (Fortinet FortiOS): restricted CLI command bypass "
        f"may allow a local authenticated attacker to execute system commands via crafted CLI commands (CWE-684). "
        f"Detected affected FortiOS version ({'.'.join(map(str, parsed_v)) if parsed_v else 'unparsed'}), and local "
        f"restricted admin account(s) with CLI access appear present (ssh/telnet enabled and accprofile != super_admin). "
        f"Remediation: {fix_str}; additionally, restrict/disable CLI access for non-super_admin accounts where possible "
        f"and review admin profiles. Advisory: https://www.fortiguard.com/psirt"
    )