from comfy import high

import re


@high(
    name="rule_cve202524477",
    platform=["fortinet_fortinet"],
    commands=dict(
        show_version="get system status",
        show_wireless_controller_setting="show wireless-controller setting",
        show_system_interface="show system interface",
    ),
)
def rule_cve202524477(configuration, commands, device, devices):
    """
    CVE-2025-24477 (Fortinet FortiOS) - Heap-based buffer overflow in cw_stad daemon (CWE-122).

    Advisory summary:
      - A heap-based buffer overflow in FortiOS cw_stad daemon may allow an authenticated attacker
        to execute arbitrary code/commands (privilege escalation) via specifically crafted requests/CLI.
      - Impacted models are those configured as a wireless client (per advisory note).

    Affected versions / fixed versions (per Fortinet PSIRT):
      - FortiOS 7.6.0 through 7.6.2  -> fixed in 7.6.3+
      - FortiOS 7.4.0 through 7.4.7  -> fixed in 7.4.8+
      - FortiOS 7.2.4 through 7.2.12 -> fixed in 7.2.13+
      - FortiOS 7.0 / 6.4 not affected

    Vulnerable configuration heuristic (based on advisory note):
      - Device is running an affected FortiOS version, AND
      - Device appears configured as a wireless client (station), i.e. cw_stad is relevant.
        We approximate this by checking wireless-controller setting / interface config for
        "wireless-client enable" or "mode wireless-client".

    Non-vulnerable scenarios:
      - FortiOS version is at/above the fixed version for its train, OR
      - FortiOS version is outside affected trains, OR
      - Version cannot be parsed (return safe), OR
      - Device is not configured as a wireless client (heuristic).
    """
    advisory_url = "https://www.fortiguard.com/psirt"

    version_text = commands.show_version or ""
    wcs_text = (commands.show_wireless_controller_setting or "").lower()
    iface_text = (commands.show_system_interface or "").lower()

    def _parse_version(text: str):
        """
        FortiOS version formats commonly seen:
          - "FortiOS v7.4.7,buildXXXX,...."
          - "Version: 7.4.7"
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
        v = _parse_version(text)
        if not v:
            return False  # per requirements: return early (treat as safe) if unparseable

        # Only trains explicitly listed as affected in the advisory.
        fixed_by_train = {
            (7, 6): (7, 6, 3),
            (7, 4): (7, 4, 8),
            (7, 2): (7, 2, 13),
        }

        train = (v[0], v[1])
        fix = fixed_by_train.get(train)
        if not fix:
            return False

        # Advisory gives affected ranges with a lower bound for 7.2 only.
        if train == (7, 2) and v < (7, 2, 4):
            return False

        # Vulnerable if version is below first fixed version.
        return v < fix

    def _is_wireless_client_configured(wcs_lower: str, iface_lower: str):
        """
        Heuristic indicators that the device is configured as a wireless client/station.
        This is intentionally conservative: only flag when we see explicit enablement.
        """
        indicators = (
            "set wireless-client enable",
            "set wireless_client enable",
            "set mode wireless-client",
            "set mode wireless_client",
            "wireless-client enable",
            "mode wireless-client",
        )
        return any(ind in wcs_lower for ind in indicators) or any(ind in iface_lower for ind in indicators)

    version_vulnerable = _is_version_vulnerable(version_text)
    if not version_vulnerable:
        return

    wireless_client = _is_wireless_client_configured(wcs_text, iface_text)
    if not wireless_client:
        return

    assert not (version_vulnerable and wireless_client), (
        f"Device {device.name} is vulnerable to CVE-2025-24477 (Fortinet FortiOS): "
        "a heap-based buffer overflow in the cw_stad daemon may allow an authenticated attacker to "
        "execute arbitrary code/commands (privilege escalation) via specially crafted CLI/requests. "
        "Detected an affected FortiOS release train/version (below the first fixed version for its train) "
        "and configuration indicators suggest the device is configured as a wireless client (station), "
        "which the advisory notes as impacted. "
        "Remediation: upgrade FortiOS to 7.6.3+/7.4.8+/7.2.13+ as applicable and review wireless-client usage. "
        f"Advisory: {advisory_url}"
    )