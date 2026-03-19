from comfy import high
import re


@high(
    name="rule_cve20250125",
    platform=["palo_alto_paloalto_panos"],
    commands=dict(
        show_system_info="show system info",
        show_mgmt_interface="show interface management",
        show_running_mgmt_profile="show running mgmt-profile",
    ),
)
def rule_cve20250125(configuration, commands, device, devices):
    """
    CVE-2025-0125: Improper input neutralization in PAN-OS management web interface
    allows an authenticated read-write administrator to impersonate another
    authenticated administrator.

    Exposure conditions (best-effort, configuration-based heuristic):
      1) PAN-OS version is in an affected train and below the first fixed version.
      2) Management web interface is reachable from an untrusted network:
         - management interface has a public/routable IP, OR
         - a dataplane interface management profile enables HTTPS/HTTP (mgmt UI).

    Notes:
      - This rule targets PAN-OS firewalls (not Cloud NGFW / Prisma Access).
      - GlobalProtect portals/gateways are not directly vulnerable, but if a
        management profile enables the management web interface on those
        interfaces, exposure exists (covered by mgmt-profile heuristic).
      - If version cannot be parsed, treat as safe (return early).
    """

    advisory_url = "https://security.paloaltonetworks.com/CVE-2025-0125"

    def _parse_version(text: str):
        """
        Parse PAN-OS version into comparable tuple: (major, minor, patch, hotfix)
        Examples:
          10.2.10-h19 -> (10,2,10,19)
          11.1.4      -> (11,1,4,0)
        """
        m = re.search(r"\b(\d+)\.(\d+)\.(\d+)(?:-h(\d+))?\b", (text or "").strip())
        if not m:
            return None
        return (int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4) or 0))

    def _is_version_vulnerable(version_text: str) -> bool:
        v = _parse_version(version_text)
        if not v:
            return False

        # Per advisory "Versions Affected" and "Unaffected" (first fixed versions):
        # 11.2 < 11.2.5
        # 11.1 < 11.1.5
        # 11.0 < 11.0.6
        # 10.2 < 10.2.10-h19 OR 10.2.11+ (i.e., fixed at 10.2.10-h19 within 10.2 train)
        # 10.1 < 10.1.14-h11 (advisory expresses as < 10.1.14-h11; we key on 10.1 train)
        fixed_by_train = {
            (11, 2): (11, 2, 5, 0),
            (11, 1): (11, 1, 5, 0),
            (11, 0): (11, 0, 6, 0),
            (10, 2): (10, 2, 10, 19),
            (10, 1): (10, 1, 14, 11),
        }

        train = (v[0], v[1])
        fix = fixed_by_train.get(train)
        if not fix:
            return False

        return v < fix

    def _is_public_ipv4(ip: str) -> bool:
        """
        Minimal RFC1918/link-local/loopback screening to decide if an IPv4 is public.
        If parsing fails, return False (do not assume exposure).
        """
        m = re.search(r"\b(\d{1,3})(?:\.(\d{1,3})){3}\b", ip or "")
        if not m:
            return False
        parts = [int(x) for x in re.findall(r"\d{1,3}", m.group(0))]
        if any(p < 0 or p > 255 for p in parts):
            return False

        a, b, c, d = parts
        # Private / special ranges
        if a == 10:
            return False
        if a == 172 and 16 <= b <= 31:
            return False
        if a == 192 and b == 168:
            return False
        if a == 127:
            return False
        if a == 169 and b == 254:
            return False
        if a == 0:
            return False
        if a >= 224:
            return False
        return True

    # --- Extract PAN-OS version ---
    sysinfo = commands.show_system_info or ""
    m_ver = re.search(r"sw-version:\s*([^\s]+)", sysinfo)
    if not m_ver:
        return
    version_str = m_ver.group(1).strip()

    if not _is_version_vulnerable(version_str):
        return

    # --- Exposure heuristic: management interface has public IP ---
    mgmt_if = commands.show_mgmt_interface or ""
    # Try common patterns: "ip address: X", "ip: X", "ip-address X"
    m_ip = re.search(r"\bip(?:\s*address|\s*addr|\s*[:=-])\s*[:=-]?\s*(\d{1,3}(?:\.\d{1,3}){3})\b", mgmt_if, re.IGNORECASE)
    mgmt_ip = (m_ip.group(1) if m_ip else "").strip()
    mgmt_public = _is_public_ipv4(mgmt_ip) if mgmt_ip else False

    # --- Exposure heuristic: dataplane interface mgmt-profile enables web (http/https) ---
    mgmt_profile = commands.show_running_mgmt_profile or ""
    # Look for enabled web services in any management profile.
    # PAN-OS mgmt profile typically includes "https yes/no" and/or "http yes/no".
    web_enabled = bool(
        re.search(r"\bhttps\b\s*(?:[:=]?\s*)?(?:yes|enable|enabled|true|on)\b", mgmt_profile, re.IGNORECASE)
        or re.search(r"\bhttp\b\s*(?:[:=]?\s*)?(?:yes|enable|enabled|true|on)\b", mgmt_profile, re.IGNORECASE)
    )

    exposed = mgmt_public or web_enabled
    if not exposed:
        return

    assert not exposed, (
        f"Device {device.name} is vulnerable to CVE-2025-0125 (PAN-OS management web interface improper input neutralization "
        "enabling an authenticated read-write administrator to impersonate another administrator). "
        f"Detected affected PAN-OS version: {version_str}. "
        "Exposure appears present because the management web interface may be reachable from an untrusted network "
        f"({'public management IP detected' if mgmt_public else 'management profile enables HTTP/HTTPS on a dataplane interface'}). "
        "Remediate by upgrading to a fixed PAN-OS release (11.2.5+, 11.1.5+, 11.0.6+, 10.2.10-h19+/10.2.11+, or 10.1.14-h11+) "
        "and restricting management interface access to trusted internal IPs per Palo Alto Networks critical deployment guidelines. "
        f"Advisory: {advisory_url}"
    )