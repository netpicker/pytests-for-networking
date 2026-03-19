from comfy import high
import re


@high(
    name="rule_cve20250108",
    platform=["palo_alto_paloalto_panos"],
    commands=dict(
        show_system_info="show system info",
        show_management_interface="show system setting management",
        show_running_interface_mgmt_profiles="show running interface-management-profile",
    ),
)
def rule_cve20250108(configuration, commands, device, devices):
    """
    CVE-2025-0108: PAN-OS authentication bypass in the management web interface.

    Advisory summary:
      - An unauthenticated attacker with network access to the PAN-OS management web interface
        can bypass authentication and invoke certain PHP scripts.
      - Risk is greatest when the management web interface is reachable from untrusted networks
        (e.g., internet exposure), including via a dataplane interface with a Management Interface Profile.

    This rule flags devices as vulnerable when:
      1) PAN-OS version is in an affected release train and below the first fixed version for that train, AND
      2) Management web interface appears enabled AND exposed beyond a strictly trusted scope, heuristically:
         - Management service enabled on the dedicated management interface, OR
         - Any interface management profile appears to allow HTTPS/WEB management (dataplane exposure).

    Notes:
      - This is a configuration heuristic; definitive exposure depends on network reachability/ACLs.
      - Cloud NGFW and Prisma Access are not impacted (this rule targets PAN-OS firewalls).
    """

    advisory_url = "https://security.paloaltonetworks.com/CVE-2025-0108"

    def _parse_version(text: str):
        """
        Parse PAN-OS version into comparable tuple: (major, minor, patch, hotfix)
        Examples:
          10.2.13-h3 -> (10, 2, 13, 3)
          11.2.4     -> (11, 2, 4, 0)
        Return None if parsing fails.
        """
        m = re.search(r"\b(\d+)\.(\d+)\.(\d+)(?:-h(\d+))?\b", (text or "").strip())
        if not m:
            return None
        return (int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4) or 0))

    def _is_version_vulnerable(version_text: str) -> bool:
        """
        Per advisory, affected trains and first fixed versions:
          - 10.1: fixed in 10.1.14-h9
          - 10.2: fixed in 10.2.7-h24, 10.2.8-h21, 10.2.9-h21, 10.2.10-h14,
                  10.2.11-h12, 10.2.12-h6, 10.2.13-h3 (and later)
            (We implement as per (major, minor, patch) -> first fixed tuple for that patch line.)
          - 11.1: fixed in 11.1.2-h18, 11.1.4-h13, 11.1.6-h1
          - 11.2: fixed in 11.2.4-h4 and 11.2.5 (and later)
        Only trains explicitly listed above are evaluated; unparseable versions are treated as safe.
        """
        v = _parse_version(version_text)
        if v is None:
            return False

        major, minor, patch, hotfix = v

        # Train-level fixed baselines (apply to all patches in that train unless overridden below)
        train_fixed = {
            (10, 1): _parse_version("10.1.14-h9"),
        }

        # Patch-line specific fixed versions for trains with multiple fixed points
        # Keyed by (major, minor, patch) -> first fixed version tuple
        patch_fixed = {
            # 10.2 patch lines
            (10, 2, 7): _parse_version("10.2.7-h24"),
            (10, 2, 8): _parse_version("10.2.8-h21"),
            (10, 2, 9): _parse_version("10.2.9-h21"),
            (10, 2, 10): _parse_version("10.2.10-h14"),
            (10, 2, 11): _parse_version("10.2.11-h12"),
            (10, 2, 12): _parse_version("10.2.12-h6"),
            (10, 2, 13): _parse_version("10.2.13-h3"),
            # 11.1 patch lines
            (11, 1, 2): _parse_version("11.1.2-h18"),
            (11, 1, 4): _parse_version("11.1.4-h13"),
            (11, 1, 6): _parse_version("11.1.6-h1"),
            # 11.2 patch lines
            (11, 2, 4): _parse_version("11.2.4-h4"),
            (11, 2, 5): _parse_version("11.2.5"),  # base 11.2.5 is fixed
        }

        # Only evaluate trains explicitly listed as affected in the advisory
        affected_trains = {(10, 1), (10, 2), (11, 1), (11, 2)}
        if (major, minor) not in affected_trains:
            return False

        # Prefer patch-line fixed point when available
        fix = patch_fixed.get((major, minor, patch))
        if fix is not None:
            return v < fix

        # Otherwise, if a train-wide fixed point exists, use it
        fix = train_fixed.get((major, minor))
        if fix is not None:
            return v < fix

        # If we don't have an explicit fixed point for this patch line, do not guess.
        # Treat as safe to avoid false positives.
        return False

    # --- Extract PAN-OS version ---
    sysinfo = commands.show_system_info or ""
    m_ver = re.search(r"sw-version:\s*([^\s]+)", sysinfo)
    if not m_ver:
        return
    version_str = m_ver.group(1).strip()

    if not _is_version_vulnerable(version_str):
        return

    # --- Heuristic exposure checks (management web interface reachable) ---
    mgmt_settings = commands.show_management_interface or ""
    mgmt_profiles = commands.show_running_interface_mgmt_profiles or ""

    # 1) Dedicated management interface: is HTTPS/web management enabled?
    # PAN-OS outputs vary; look for common tokens indicating web/https enabled.
    mgmt_https_enabled = bool(
        re.search(
            r"\b(https|web)\b.*\b(enable|enabled|yes|true|on)\b|\b(enable|enabled|yes|true|on)\b.*\b(https|web)\b",
            mgmt_settings,
            re.IGNORECASE,
        )
    )

    # 2) Dataplane exposure via interface management profile allowing https/web
    # Look for "interface-management-profile" blocks that include https or web-management.
    dataplane_https_enabled = bool(
        re.search(
            r"(interface-management-profile|management-profile|interface management profile).*?(https|web-management|webgui|web-ui)\b",
            mgmt_profiles,
            re.IGNORECASE | re.DOTALL,
        )
    )

    # If neither indicates web management is enabled/exposed, treat as safe configuration.
    if not (mgmt_https_enabled or dataplane_https_enabled):
        return

    assert False, (
        f"Device {device.name} is vulnerable to CVE-2025-0108 (PAN-OS authentication bypass in the management web interface). "
        f"Detected affected PAN-OS version: {version_str}. "
        "Heuristic exposure indicators found: management web interface appears enabled and/or exposed "
        "(either HTTPS/WEB enabled on the management interface and/or an interface management profile allows HTTPS/WEB). "
        "An unauthenticated attacker with network access to the management web interface may bypass authentication and invoke certain PHP scripts, "
        "negatively impacting integrity and confidentiality. "
        "Remediate by upgrading to a fixed PAN-OS release for your train (e.g., 10.1.14-h9+, 10.2.7-h24/10.2.8-h21/10.2.9-h21/10.2.10-h14/10.2.11-h12/10.2.12-h6/10.2.13-h3+, "
        "11.1.2-h18/11.1.4-h13/11.1.6-h1+, 11.2.4-h4/11.2.5+) and restricting management interface access to trusted internal IPs only. "
        f"Advisory: {advisory_url}"
    )