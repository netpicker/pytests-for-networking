from comfy import high
import re


@high(
    name="rule_cve20250137",
    platform=["palo_alto_paloalto_panos"],
    commands=dict(
        show_system_info="show system info",
        show_management_interface="show interface management",
        show_running_config="show running-config",
    ),
)
def rule_cve20250137(configuration, commands, device, devices):
    """
    CVE-2025-0137: Improper input neutralization in PAN-OS management web interface
    allows an authenticated read-write administrator to impersonate another
    legitimate authenticated PAN-OS administrator.

    Exposure requires:
      1) Affected PAN-OS version (per advisory fixed versions), AND
      2) Management web interface is reachable from untrusted networks (greatest
         risk when internet-facing), typically via:
           - direct access to the management interface; OR
           - access through a dataplane interface with a Management Interface Profile
             that permits HTTPS/WEB (often port 4443).

    This rule uses configuration heuristics to detect likely exposure:
      - management interface has an IP configured (mgmt is in use), AND
      - running-config indicates management access is not restricted to trusted
        internal IPs (e.g., no permitted-ip / permitted-ipv6 configured).

    Note: This is a configuration-based risk test; it cannot prove internet exposure.
    """

    advisory_url = "https://security.paloaltonetworks.com/CVE-2025-0137"

    def _parse_version(text: str):
        """
        Parse PAN-OS version into comparable tuple: (major, minor, patch, hotfix)
        Examples:
          11.1.6-h14 -> (11, 1, 6, 14)
          10.2.13    -> (10, 2, 13, 0)
        Returns None if not parseable.
        """
        m = re.search(r"\b(\d+)\.(\d+)\.(\d+)(?:-h(\d+))?\b", (text or "").strip())
        if not m:
            return None
        return (int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4) or 0))

    def _is_version_vulnerable(version_text: str) -> bool:
        """
        Advisory affected trains and fixed versions:
          - 11.2: < 11.2.5
          - 11.1: < 11.1.8 OR 11.1.6 <= v < 11.1.6-h14 (special hotfix boundary)
          - 10.2: < 10.2.13
          - 10.1: 10.1.14 <= v < 10.1.14-h14 (advisory states <10.1.14-h14; applicability shows from 10.1.14)
        Only trains explicitly listed are evaluated; others are treated as not vulnerable.
        If parsing fails, treat as safe (return False).
        """
        v = _parse_version(version_text)
        if v is None:
            return False

        train = (v[0], v[1])

        # First fixed versions per train (exclusive upper bound: v < fix is vulnerable)
        fixed_by_train = {
            (11, 2): (11, 2, 5, 0),
            (11, 1): (11, 1, 8, 0),
            (10, 2): (10, 2, 13, 0),
        }

        if train in fixed_by_train:
            return v < fixed_by_train[train]

        # Special-case boundaries explicitly called out in advisory/applicability
        # 11.1.6 hotfix: vulnerable for 11.1.6 <= v < 11.1.6-h14
        if train == (11, 1):
            base = (11, 1, 6, 0)
            fix = (11, 1, 6, 14)
            return base <= v < fix

        # 10.1.14 hotfix: vulnerable for 10.1.14 <= v < 10.1.14-h14
        if train == (10, 1):
            base = (10, 1, 14, 0)
            fix = (10, 1, 14, 14)
            return base <= v < fix

        return False

    # --- Extract PAN-OS version ---
    sysinfo = commands.show_system_info or ""
    m_ver = re.search(r"sw-version:\s*([^\s]+)", sysinfo)
    if not m_ver:
        return
    version_str = m_ver.group(1).strip()

    if not _is_version_vulnerable(version_str):
        return

    # --- Heuristic: management interface is configured/active (has an IP) ---
    mgmt_if = commands.show_management_interface or ""
    mgmt_has_ip = bool(
        re.search(
            r"\b(ip|ipv4)\b\s*[:=]?\s*(\d{1,3}(?:\.\d{1,3}){3})\b",
            mgmt_if,
            re.IGNORECASE,
        )
    )

    if not mgmt_has_ip:
        # If mgmt isn't configured, management web interface is unlikely reachable.
        return

    # --- Heuristic: management access is restricted to trusted IPs ---
    # Look for permitted-ip / permitted-ipv6 in running-config (common PAN-OS setting).
    # Strip comment lines first to avoid false matches like "# no permitted-ip configured".
    running_raw = commands.show_running_config or ""
    running = "\n".join(
        ln for ln in running_raw.splitlines() if not ln.lstrip().startswith("#")
    )
    has_permitted_ip = bool(re.search(r"\bpermitted-ipv?6?\b", running, re.IGNORECASE))

    # If access is restricted, risk is greatly reduced; treat as safe configuration.
    if has_permitted_ip:
        return

    # --- If affected version + mgmt in use + no permitted-ip restriction, flag ---
    assert not True, (
        f"Device {device.name} is potentially vulnerable to CVE-2025-0137 (PAN-OS management web interface "
        "improper input neutralization enabling an authenticated read-write admin to impersonate another admin). "
        f"Detected affected PAN-OS version: {version_str}. "
        "Heuristics indicate the management interface is configured (has an IP) and management access does not appear "
        "restricted to trusted internal IP addresses (no 'permitted-ip' found in running configuration). "
        "Remediate by upgrading to a fixed PAN-OS release (11.2.5+, 11.1.6-h14/11.1.8+, 10.2.13+, 10.1.14-h14+) "
        "and restricting management web interface access to trusted internal IPs per Palo Alto Networks guidance. "
        f"Advisory: {advisory_url}"
    )