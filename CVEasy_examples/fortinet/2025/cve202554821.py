from comfy import high


@high(
    name="rule_cve202554821",
    platform=["fortinet_fortinet"],
    commands=dict(
        show_version="get system status",
        show_admins="show system admin",
        show_global="show system global",
    ),
)
def rule_cve202554821(configuration, commands, device, devices):
    """
    CVE-2025-54821 (Fortinet FortiOS / FortiProxy / FortiPAM) - Trusted hosts bypass via crafted CLI command (CWE-269).

    Summary (Fortinet PSIRT, FG-IR-25-545, 2025-11-18):
      - An authenticated administrator may bypass the trusted host policy via a crafted CLI command.
      - Component: CLI
      - Impact: privilege escalation / policy bypass (trusted hosts restriction)

    Affected / fixed versions (per advisory):
      - FortiOS 7.6.0 through 7.6.3  -> fixed in 7.6.4+
      - FortiProxy 7.6.0 through 7.6.3 -> fixed in 7.6.4+
      - FortiPAM 1.6.0 -> fixed in 1.6.1+
      - Other trains listed as "all versions" (FortiOS 7.4/7.2/7.0/6.4, FortiProxy 7.4/7.2/7.0, FortiPAM 1.5/1.4/1.3/1.2/1.1/1.0)
        are affected but do not have a single "first fixed" version in the advisory (they require migration).
        This rule only evaluates trains with an explicit fixed version boundary.

    Vulnerable configuration (exposure heuristic):
      - Device is running an affected train with a known fixed version boundary, AND
      - At least one administrator account has "trustedhost" configured (trusted host policy is in use).
        (If trusted hosts are not configured, there is no trusted-host policy to bypass.)

    Non-vulnerable scenarios:
      - Version is not in an affected train with a known fixed boundary, OR
      - Version is at/above the fixed version for that train, OR
      - No trustedhost entries are configured for any admin (trusted host policy not in use).
    """
    version_text = commands.show_version or ""
    admins_text = (commands.show_admins or "").lower()
    global_text = (commands.show_global or "").lower()

    def _parse_version(text: str):
        """
        Extract a version tuple (major, minor, patch) from Fortinet outputs.

        Accepts patterns commonly seen in:
          - FortiOS:  "FortiOS v7.6.3,build..." or "Version: 7.6.3"
          - FortiProxy: similar "v7.6.3" / "Version: 7.6.3"
          - FortiPAM: may show "Version: 1.6.0" (format varies)
        """
        import re

        # Prefer explicit "Version: X.Y.Z"
        m = re.search(r"\bversion:\s*([0-9]+)\.([0-9]+)\.([0-9]+)\b", text, re.IGNORECASE)
        if m:
            return (int(m.group(1)), int(m.group(2)), int(m.group(3)))

        # Common "vX.Y.Z" token
        m = re.search(r"\bv([0-9]+)\.([0-9]+)\.([0-9]+)\b", text, re.IGNORECASE)
        if m:
            return (int(m.group(1)), int(m.group(2)), int(m.group(3)))

        return None

    def _is_version_vulnerable(text: str):
        """
        Release-train-based matching with explicit fixed versions only.

        Returns: (is_vuln: bool, parsed_version: tuple|None, fix_version: tuple|None)
        """
        v = _parse_version(text)
        if not v:
            # Per requirements: return early (treat as safe) if version cannot be parsed.
            return (False, None, None)

        # Only include trains explicitly listed as affected AND with an explicit fixed version in the advisory.
        # FortiOS/FortiProxy: 7.6 fixed in 7.6.4
        # FortiPAM: 1.6 fixed in 1.6.1
        fixed_by_train = {
            (7, 6): (7, 6, 4),
            (1, 6): (1, 6, 1),
        }

        train = (v[0], v[1])
        fix = fixed_by_train.get(train)
        if not fix:
            return (False, v, None)

        # Advisory phrasing: "7.6.0 through 7.6.3" => vulnerable if v < 7.6.4
        return (v < fix, v, fix)

    version_vulnerable, parsed_v, fix_v = _is_version_vulnerable(version_text)

    # Configuration heuristic: trusted hosts are configured for at least one admin.
    # Typical snippet:
    #   config system admin
    #       edit "admin"
    #           set trusthost1 203.0.113.10 255.255.255.255
    #       next
    #   end
    import re as _re
    trusted_hosts_configured = bool(_re.search(r"\bset trusthost\d*\b", admins_text))

    # Optional additional signal: global admin restrictions exist (not required, but helps avoid edge cases)
    # Keep it non-blocking; trustedhost is the key.
    _ = global_text  # reserved for future heuristics

    config_vulnerable = trusted_hosts_configured
    is_vulnerable = version_vulnerable and config_vulnerable

    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-54821 (Fortinet): an authenticated administrator may bypass "
        "the trusted host policy via a crafted CLI command (CWE-269). "
        f"Detected affected version {'.'.join(map(str, parsed_v)) if parsed_v else 'unparsed'}"
        f"{' (fixed in ' + '.'.join(map(str, fix_v)) + '+)' if fix_v else ''} and trusted hosts appear configured "
        "for at least one admin account (trusted host policy in use). "
        "Remediation: upgrade to a fixed release (FortiOS/FortiProxy 7.6.4+ or FortiPAM 1.6.1+) or migrate to a "
        "fixed release for affected trains. Advisory: https://www.fortiguard.com/psirt/FG-IR-25-545"
    )