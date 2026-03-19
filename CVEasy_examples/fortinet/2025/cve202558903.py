from comfy import high


@high(
    name="rule_cve202558903",
    platform=["fortinet_fortinet"],
    commands=dict(
        show_version="get system status",
        show_admins="show system admin",
        show_global="show system global",
    ),
)
def rule_cve202558903(configuration, commands, device, devices):
    """
    CVE-2025-58903 (Fortinet FortiOS) - Unchecked Return Value leading to Null Pointer Dereference (httpd crash) via crafted API request.

    Advisory summary:
      - An Unchecked Return Value vulnerability [CWE-252] in FortiOS API may allow an authenticated user
        to cause a Null Pointer Dereference, crashing the http daemon via a specially crafted request.

    Affected versions / fixed versions (per Fortinet PSIRT advisory FG-IR-25-653):
      - FortiOS 7.6.0 through 7.6.3  -> fixed in 7.6.4 and above
      - FortiOS 7.4.0 through 7.4.8  -> fixed in 7.4.9 and above
      - FortiOS 7.2 all versions      -> migrate to a fixed release (no fixed version specified in advisory)
      - FortiOS 7.0 all versions      -> migrate to a fixed release (no fixed version specified in advisory)
      - FortiOS 6.4 all versions      -> migrate to a fixed release (no fixed version specified in advisory)

    Vulnerable configuration / exposure heuristic:
      - This is an authenticated API-triggered DoS against the GUI/httpd component.
      - Treat as "exposed" when the device has at least one admin account that can authenticate to the GUI/API.
        (Most deployments do; this is a conservative heuristic based on available CLI outputs.)

    Non-vulnerable scenarios:
      - FortiOS version is not in an affected train, OR
      - FortiOS version is at/above the fixed version for the affected train, OR
      - Version cannot be parsed (rule returns safe), OR
      - No admin accounts are configured (unlikely; treated as safe configuration).

    Advisory:
      - https://www.fortiguard.com/psirt/advisory/FG-IR-25-653
    """
    import re

    version_text = commands.show_version or ""
    admins_text = (commands.show_admins or "").lower()
    global_text = (commands.show_global or "").lower()

    def _parse_version(text: str):
        """
        FortiOS version formats commonly seen:
          - 'FortiOS v7.6.3,buildxxxx,...'
          - 'Version: 7.6.3'
        Return (major, minor, patch) as ints, or None if not found.
        """
        patterns = [
            r"\bFortiOS\s+v(\d+)\.(\d+)\.(\d+)\b",
            r"\bVersion:\s*(\d+)\.(\d+)\.(\d+)\b",
            r"\bv(\d+)\.(\d+)\.(\d+)\b",
        ]
        for pat in patterns:
            m = re.search(pat, text, re.IGNORECASE)
            if m:
                return (int(m.group(1)), int(m.group(2)), int(m.group(3)))
        return None

    def _is_version_vulnerable(text: str):
        """
        Train-based matching only for trains explicitly listed as affected in the advisory.
        Return True if vulnerable, False otherwise (including parse failure).
        """
        v = _parse_version(text)
        if not v:
            return False

        major, minor, patch = v
        train = (major, minor)

        # For trains with a specified fixed version: vulnerable if v < fixed.
        fixed_by_train = {
            (7, 6): (7, 6, 4),
            (7, 4): (7, 4, 9),
        }
        if train in fixed_by_train:
            return v < fixed_by_train[train]

        # For trains where advisory says "all versions" and does not specify a fixed version:
        # treat any version in that train as vulnerable.
        all_versions_affected_trains = {
            (7, 2),
            (7, 0),
            (6, 4),
        }
        if train in all_versions_affected_trains:
            return True

        return False

    version_tuple = _parse_version(version_text)
    version_vulnerable = _is_version_vulnerable(version_text)

    # Exposure heuristic: at least one admin exists (authenticated user possible).
    # 'show system admin' typically contains:
    #   config system admin
    #       edit "admin"
    #           set accprofile "super_admin"
    #       next
    #   end
    has_admin_config = ("config system admin" in admins_text) and ("edit " in admins_text)

    # Additional heuristic: GUI is not explicitly disabled (best-effort; may not appear in output).
    # If we see an explicit disable, treat as safer configuration.
    gui_explicitly_disabled = any(
        s in global_text
        for s in (
            "set admin-sport 0",
            "set admin-port 0",
            "set admin-https-port 0",
            "set admin-http-port 0",
        )
    )

    config_vulnerable = has_admin_config and (not gui_explicitly_disabled)
    is_vulnerable = version_vulnerable and config_vulnerable

    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-58903 (Fortinet FortiOS): "
        "an authenticated user can trigger an unchecked return value leading to a null pointer dereference, "
        "crashing the http daemon (GUI/API) via a specially crafted request (CWE-252). "
        f"Detected affected FortiOS version ({'.'.join(map(str, version_tuple)) if version_tuple else 'unparsed'}), "
        "and the device appears to have at least one admin account configured (authenticated access possible). "
        "Remediation: upgrade to FortiOS 7.6.4+ (for 7.6 train) or 7.4.9+ (for 7.4 train), or migrate off affected "
        "7.2/7.0/6.4 trains per Fortinet guidance. "
        "Advisory: https://www.fortiguard.com/psirt/advisory/FG-IR-25-653"
    )