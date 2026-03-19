from comfy import high


@high(
    name="rule_cve202522258",
    platform=["fortinet_fortinet"],
    commands=dict(
        show_version="get system status",
        show_admin="show system admin",
        show_global="show system global",
    ),
)
def rule_cve202522258(configuration, commands, device, devices):
    """
    CVE-2025-22258 (Fortinet FortiOS / FortiProxy / FortiPAM / FortiSRA / FortiSwitchManager) -
    Heap-based buffer overflow in nodejs daemon (websocket/GUI) allowing authenticated privilege escalation
    via specially crafted HTTP requests.

    This rule implements a FortiOS-focused check (platform: fortinet_fortinet):
      - Version vulnerable if FortiOS is in an affected train and below the first fixed version.
      - Configuration vulnerable if GUI administrative access is enabled (attack surface for crafted HTTP requests),
        and at least one local admin account exists (to satisfy "authenticated attacker" precondition).

    Advisory:
      - https://www.fortiguard.com/psirt/FG-IR-24-546
    """
    version_text = commands.show_version or ""
    admin_text = (commands.show_admin or "").lower()
    global_text = (commands.show_global or "").lower()

    def _parse_version(text: str):
        import re

        # Common FortiOS outputs:
        #   "FortiOS v7.4.6,buildxxxx,..."
        #   "Version: 7.4.6"
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

    def _is_version_vulnerable(text: str) -> bool:
        v = _parse_version(text)
        if not v:
            # Per requirements: if we cannot parse, return early and treat as safe.
            return False

        # Only trains explicitly listed as affected in the advisory.
        # Advisory says:
        #   FortiOS 7.6.0 through 7.6.2 -> fixed in 7.6.3+
        #   FortiOS 7.4.0 through 7.4.6 -> fixed in 7.4.7+
        #   FortiOS 7.2.0 through 7.2.10 -> fixed in 7.2.11+
        #   FortiOS 7.0.2 through 7.0.16 -> fixed in 7.0.17+
        fixed_by_train = {
            (7, 6): (7, 6, 3),
            (7, 4): (7, 4, 7),
            (7, 2): (7, 2, 11),
            (7, 0): (7, 0, 17),
        }

        train = (v[0], v[1])
        fix = fixed_by_train.get(train)
        if not fix:
            return False

        # Lower bounds from advisory (to avoid flagging earlier, non-listed versions).
        lower_bounds = {
            (7, 6): (7, 6, 0),
            (7, 4): (7, 4, 0),
            (7, 2): (7, 2, 0),
            (7, 0): (7, 0, 2),
        }
        lb = lower_bounds[train]

        return lb <= v < fix

    version_vulnerable = _is_version_vulnerable(version_text)

    # Configuration / exposure heuristic:
    # - Vulnerability is in GUI/nodejs handling crafted HTTP requests; reduce exposure if GUI is not enabled.
    # - "Authenticated attacker": assume at least one local admin exists (typical), but check anyway.
    #
    # FortiOS GUI access is controlled per admin account:
    #   config system admin
    #     edit "admin"
    #       set accprofile "super_admin"
    #       set vdom "root"
    #       set trusthost1 ...
    #     next
    #   end
    #
    # And global admin ports:
    #   config system global
    #     set admin-sport 443
    #     set admin-port 80
    #   end
    #
    # We treat "GUI enabled" if either admin-port/admin-sport is set (common indicator that HTTP/HTTPS admin GUI is in use).
    import re as _re
    gui_enabled = bool(
        _re.search(r"^\s*set admin-port\b", global_text, _re.MULTILINE)
        or _re.search(r"^\s*set admin-sport\b", global_text, _re.MULTILINE)
    )

    # Local admin presence heuristic: any "edit" stanza under config system admin.
    has_local_admin = ("config system admin" in admin_text) and ("edit " in admin_text)

    config_vulnerable = gui_enabled and has_local_admin
    is_vulnerable = version_vulnerable and config_vulnerable

    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-22258 (Fortinet FortiOS): "
        "a heap-based buffer overflow in the GUI/nodejs daemon may allow an authenticated attacker to escalate "
        "privileges via specially crafted HTTP requests. "
        "Detected an affected FortiOS release train/version below the first fixed version, and the administrative "
        "GUI appears enabled (admin-port/admin-sport set) with at least one local admin configured, increasing "
        "exposure to crafted HTTP requests. "
        "Remediation: upgrade FortiOS to a fixed release (7.6.3+/7.4.7+/7.2.11+/7.0.17+ as applicable) and reduce "
        "attack surface by restricting/disable GUI access where possible (trusted hosts, management interface "
        "segmentation). Advisory: https://www.fortiguard.com/psirt/FG-IR-24-546"
    )