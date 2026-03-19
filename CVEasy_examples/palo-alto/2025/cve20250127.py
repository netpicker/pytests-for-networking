from comfy import high
import re


@high(
    name="rule_cve20250127",
    platform=["palo_alto_paloalto_panos"],
    commands=dict(
        show_system_info="show system info",
        show_vm_series="show system vm-series",
    ),
)
def rule_cve20250127(configuration, commands, device, devices):
    """
    CVE-2025-0127: Authenticated admin command injection in PAN-OS VM-Series.

    Advisory summary:
      - Applies ONLY to PAN-OS VM-Series (virtual firewalls).
      - No special configuration required beyond being VM-Series.
      - Cloud NGFW and Prisma Access are not affected (not targeted by this rule).

    Affected VM-Series versions / fixed versions:
      - PAN-OS 11.0: vulnerable if v < 11.0.4
      - PAN-OS 10.2: vulnerable if v < 10.2.9
      - PAN-OS 10.1: vulnerable if v < 10.1.14-h13
      - PAN-OS 11.1: not affected on VM-Series
      - PAN-OS 11.2: not affected on VM-Series

    Note: Advisory states PAN-OS 11.0 and earlier are EoL; older unsupported versions
    should be presumed affected, but this rule only matches trains explicitly listed
    as affected in the advisory (10.1, 10.2, 11.0).
    """

    advisory_url = "https://security.paloaltonetworks.com/CVE-2025-0127"

    def _parse_version(text: str):
        """
        Parse PAN-OS version into comparable tuple: (major, minor, patch, hotfix)
        Examples:
          10.1.14-h13 -> (10, 1, 14, 13)
          10.2.8      -> (10, 2, 8, 0)
        Returns None if not parseable.
        """
        m = re.search(r"\b(\d+)\.(\d+)\.(\d+)(?:-h(\d+))?\b", (text or "").strip())
        if not m:
            return None
        return (int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4) or 0))

    def _is_version_vulnerable(version_text: str) -> bool:
        """
        Release-train-based matching using first fixed version per affected train.
        Only includes trains explicitly listed as affected in the advisory.
        """
        v = _parse_version(version_text)
        if v is None:
            return False

        fixed_by_train = {
            (11, 0): _parse_version("11.0.4"),
            (10, 2): _parse_version("10.2.9"),
            (10, 1): _parse_version("10.1.14-h13"),
        }

        fix = fixed_by_train.get((v[0], v[1]))
        if fix is None:
            return False

        return v < fix

    # --- Extract PAN-OS version ---
    sysinfo = commands.show_system_info or ""
    m_ver = re.search(r"sw-version:\s*([^\s]+)", sysinfo)
    if not m_ver:
        return
    version_str = m_ver.group(1).strip()

    # --- Determine if this is VM-Series (required for exposure) ---
    # Prefer explicit VM-Series command output; fall back to model string heuristic.
    vm_out = commands.show_vm_series or ""
    is_vm_series = False

    # Heuristic patterns for VM-Series identification.
    # Check for "VM-Series: yes" affirmative, not just the word presence.
    if re.search(r"\bvm-?series\s*:\s*yes\b", vm_out, re.IGNORECASE):
        is_vm_series = True
    else:
        m_model = re.search(r"model:\s*([^\s]+)", sysinfo)
        model = (m_model.group(1).strip() if m_model else "")
        if re.search(r"\bPA-VM\b|\bVM-?Series\b", model, re.IGNORECASE):
            is_vm_series = True

    if not is_vm_series:
        return

    # --- Version vulnerability check (no special config beyond VM-Series) ---
    vulnerable = _is_version_vulnerable(version_str)
    if not vulnerable:
        return

    assert not vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-0127 (PAN-OS VM-Series authenticated admin command injection). "
        f"Detected VM-Series with affected PAN-OS version: {version_str}. "
        "This issue allows an authenticated administrator to bypass system restrictions and run arbitrary commands as root. "
        "Remediate by upgrading to a fixed release (10.1.14-h13+, 10.2.9+, or 11.0.4+ as applicable) or to a supported fixed version. "
        f"Advisory: {advisory_url}"
    )