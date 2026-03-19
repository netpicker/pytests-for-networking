from comfy import high
import re


@high(
    name="rule_cve20250110",
    platform=["palo_alto_paloalto_panos"],
    commands=dict(
        show_system_info="show system info",
        show_plugins="show plugins installed",
    ),
)
def rule_cve20250110(configuration, commands, device, devices):
    """
    CVE-2025-0110: PAN-OS OpenConfig Plugin command injection via gNMI requests
    to the management web interface (port 9339).

    Affected when:
      1) OpenConfig plugin is enabled/installed, AND
      2) OpenConfig plugin version is < 2.1.2

    Notes:
      - Advisory states exposure requires OpenConfig plugin enabled.
      - Fixed in OpenConfig plugin 2.1.2 and later.
      - PAN-OS version alone is not sufficient to determine vulnerability; plugin version is key.
    """

    advisory_url = "https://security.paloaltonetworks.com/CVE-2025-0110"

    def _parse_version(text: str):
        """
        Parse a dotted version like '2.1.2' (optionally with suffix) into a tuple.
        Examples:
          '2.1.2' -> (2,1,2)
          '2.1.2-1' -> (2,1,2)
          '2.1.2b' -> (2,1,2)
        """
        m = re.search(r"\b(\d+)\.(\d+)\.(\d+)\b", (text or ""))
        if not m:
            return None
        return (int(m.group(1)), int(m.group(2)), int(m.group(3)))

    def _is_version_vulnerable(version_text: str) -> bool:
        """
        Release-train-based matching keyed by (major, minor) -> first fixed version.
        Only trains explicitly covered by the advisory are included.

        Advisory: OpenConfig plugin < 2.1.2 is affected; >= 2.1.2 is fixed.
        We model the explicitly referenced train (2.1).
        """
        v = _parse_version(version_text)
        if v is None:
            return False  # cannot parse => do not flag
        fixed_by_train = {
            (2, 1): (2, 1, 2),
        }
        key = (v[0], v[1])
        fix = fixed_by_train.get(key)
        if fix is None:
            return False  # train not explicitly listed as affected
        return v < fix

    # --- Determine PAN-OS version (for reporting only) ---
    sysinfo = commands.show_system_info or ""
    m_pan = re.search(r"sw-version:\s*([^\s]+)", sysinfo)
    panos_version = (m_pan.group(1).strip() if m_pan else "unknown")

    # --- Determine whether OpenConfig plugin is installed/enabled and its version ---
    plugins_out = commands.show_plugins or ""

    # Heuristic: find a line mentioning openconfig and a version-like token.
    # Accept common renderings: "openconfig 2.1.1", "OpenConfig Plugin 2.1.1", etc.
    m_oc = re.search(
        r"(?im)^\s*(?:\S+\s+)*openconfig(?:\s+plugin)?\b.*?\b(\d+\.\d+\.\d+)\b",
        plugins_out,
    )

    if not m_oc:
        # OpenConfig plugin not detected as installed/currently installed => not exposed per advisory
        return

    oc_version_str = m_oc.group(1).strip()

    if not _is_version_vulnerable(oc_version_str):
        return

    assert not True, (
        f"Device {device.name} is vulnerable to CVE-2025-0110 (PAN-OS OpenConfig plugin command injection). "
        f"Detected OpenConfig plugin version {oc_version_str} (< 2.1.2) with plugin present/enabled. "
        f"PAN-OS version observed: {panos_version}. "
        "An authenticated administrator able to make gNMI requests to the management web interface may be able to "
        "bypass restrictions and execute arbitrary commands. "
        "Remediate by upgrading the OpenConfig plugin to 2.1.2 or later and restricting management interface access "
        "to trusted internal IPs per best practices. "
        f"Advisory: {advisory_url}"
    )