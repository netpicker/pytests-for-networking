from comfy import high
import re


@high(
    name="rule_cve20250105",
    platform=["palo_alto_paloalto_panos"],
    commands=dict(
        show_system_info="show system info",
        show_version="show version",
    ),
)
def rule_cve20250105(configuration, commands, device, devices):
    """
    CVE-2025-0105: Arbitrary file deletion in Palo Alto Networks Expedition (unauthenticated).

    Advisory scope notes:
      - This CVE affects the Expedition migration tool (NOT PAN-OS firewalls / Panorama / Prisma Access).
      - Fixed in Expedition >= 1.2.101; affected Expedition versions are < 1.2.101.
      - No special configuration is required to be affected (network reachable Expedition web app is enough).

    This rule runs on the PAN-OS platform; therefore it should never flag a PAN-OS device as vulnerable.
    We still implement strict version parsing and train-based matching as required, and we only assert
    if we can positively identify Expedition running on the target and its version is vulnerable.
    """

    advisory_url = "https://security.paloaltonetworks.com/PAN-SA-2025-0001"

    def _parse_version(text: str):
        """
        Parse a dotted version like '1.2.100' or '1.2.101' into (major, minor, patch).
        Returns None if not parseable.
        """
        m = re.search(r"\b(\d+)\.(\d+)\.(\d+)\b", (text or ""))
        if not m:
            return None
        return (int(m.group(1)), int(m.group(2)), int(m.group(3)))

    def _is_version_vulnerable(version_text: str) -> bool:
        """
        Expedition affected versions: < 1.2.101
        Implemented as per-train fixed version mapping keyed by (major, minor).
        Only include trains explicitly referenced by the advisory (1.2.x).
        """
        v = _parse_version(version_text)
        if v is None:
            return False  # safe if we cannot parse
        train_key = (v[0], v[1])
        fixed_by_train = {
            (1, 2): (1, 2, 101),
        }
        fix = fixed_by_train.get(train_key)
        if fix is None:
            return False  # only trains listed as affected are evaluated
        return v < fix

    # --- Identify whether the target is Expedition (not PAN-OS) and extract its version if present ---
    # On PAN-OS, these commands will not report Expedition; so this should normally return safe.
    sysinfo = commands.show_system_info or ""
    showver = commands.show_version or ""
    combined = f"{sysinfo}\n{showver}"

    # Heuristic: look for explicit Expedition identification and a version string.
    # We intentionally require an "expedition" marker to avoid false positives on PAN-OS versions.
    if not re.search(r"\bexpedition\b", combined, re.IGNORECASE):
        return

    m_ver = re.search(
        r"\bexpedition\b[^\n]*?\bversion\b\s*[:=]?\s*(\d+\.\d+\.\d+)\b",
        combined,
        re.IGNORECASE,
    )
    if not m_ver:
        return

    expedition_version = m_ver.group(1).strip()
    vulnerable = _is_version_vulnerable(expedition_version)

    assert not vulnerable, (
        f"Device {device.name} appears to be running Palo Alto Networks Expedition and is vulnerable to "
        f"CVE-2025-0105 (arbitrary file deletion as www-data, unauthenticated) because Expedition version "
        f"{expedition_version} is < 1.2.101. No special configuration is required beyond network access to "
        "the Expedition web application. Upgrade Expedition to 1.2.101+ (note: Expedition is EoL) and/or "
        "restrict network access/shut down Expedition when not in use. "
        f"Advisory: {advisory_url}"
    )