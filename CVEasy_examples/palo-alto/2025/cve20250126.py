from comfy import high
import re


@high(
    name="rule_cve20250126",
    platform=["palo_alto_paloalto_panos"],
    commands=dict(
        show_system_info="show system info",
        show_globalprotect_portals="show running global-protect portal",
    ),
)
def rule_cve20250126(configuration, commands, device, devices):
    """
    CVE-2025-0126: Session Fixation Vulnerability in GlobalProtect SAML Login (PAN-OS)

    Affected when ALL are true:
      1) PAN-OS version is in an affected train and below the first fixed version:
         - 11.2.x: < 11.2.3
         - 11.1.x: < 11.1.5
         - 11.0.x: < 11.0.6
         - 10.2.x: < 10.2.4-h25 OR < 10.2.9-h13 OR < 10.2.10-h6 OR < 10.2.11
           (i.e., fixed in 10.2.4-h25, 10.2.9-h13, 10.2.10-h6, and 10.2.11+)
         - 10.1.x: < 10.1.14-h11
         Older EoL releases are presumed affected but not evaluated here (rule matches only trains listed above).
      2) A GlobalProtect portal is configured, AND
      3) The GlobalProtect portal uses SAML authentication.

    Not affected:
      - PAN-OS management interface SAML login (out of scope for this rule)
      - Cloud NGFW and Prisma Access (this rule targets PAN-OS firewalls)
      - Devices without GlobalProtect portal SAML authentication configured
    """

    advisory_url = "https://security.paloaltonetworks.com/CVE-2025-0126"

    def _parse_version(text: str):
        """
        Parse PAN-OS version into comparable tuple: (major, minor, patch, hotfix)
        Examples:
          10.2.4-h25 -> (10,2,4,25)
          10.2.11    -> (10,2,11,0)
        Returns None if parsing fails.
        """
        m = re.search(r"\b(\d+)\.(\d+)\.(\d+)(?:-h(\d+))?\b", (text or "").strip())
        if not m:
            return None
        return (int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4) or 0))

    def _is_version_vulnerable(version_text: str) -> bool:
        """
        Release-train-based matching:
          - For trains with a single fixed version: vulnerable if v < fixed
          - For PAN-OS 10.2: multiple fixed thresholds depending on patch/hotfix.
        Return False (safe) if version cannot be parsed.
        """
        v = _parse_version(version_text)
        if v is None:
            return False

        train = (v[0], v[1])

        # Single-fix trains explicitly listed in the advisory
        fixed_by_train = {
            (11, 2): (11, 2, 3, 0),
            (11, 1): (11, 1, 5, 0),
            (11, 0): (11, 0, 6, 0),
            (10, 1): (10, 1, 14, 11),
        }

        if train in fixed_by_train:
            return v < fixed_by_train[train]

        # PAN-OS 10.2 has multiple fixed points depending on patch/hotfix
        if train == (10, 2):
            # Advisory affected: <10.2.4-h25, <10.2.9-h13, <10.2.10-h6, <10.2.11
            # Unaffected: >=10.2.4-h25, >=10.2.9-h13, >=10.2.10-h6, >=10.2.11
            if v[2] < 4:
                return True
            if v[2] == 4:
                return v < (10, 2, 4, 25)
            if 5 <= v[2] <= 8:
                return True
            if v[2] == 9:
                return v < (10, 2, 9, 13)
            if v[2] == 10:
                return v < (10, 2, 10, 6)
            # 10.2.11 and later are fixed
            return v < (10, 2, 11, 0)

        # Only include trains explicitly listed as affected in the advisory.
        return False

    # --- Extract PAN-OS version ---
    sysinfo = commands.show_system_info or ""
    m_ver = re.search(r"sw-version:\s*([^\s]+)", sysinfo)
    if not m_ver:
        return
    version_str = m_ver.group(1).strip()

    if not _is_version_vulnerable(version_str):
        return

    # --- Determine if GlobalProtect portal is configured and uses SAML auth ---
    gp_portals = commands.show_globalprotect_portals or ""

    # Heuristic: presence of portal config + SAML authentication profile/type.
    # We keep this flexible to accommodate output variations.
    portal_present = bool(re.search(r"\bportal\b", gp_portals, re.IGNORECASE))
    saml_configured = bool(
        re.search(
            r"\b(saml)\b",
            gp_portals,
            re.IGNORECASE,
        )
    )

    if not (portal_present and saml_configured):
        return

    assert not (portal_present and saml_configured), (
        f"Device {device.name} is vulnerable to CVE-2025-0126 (PAN-OS GlobalProtect SAML login session fixation). "
        f"Detected affected PAN-OS version: {version_str}. "
        "Exposure conditions appear met: a GlobalProtect portal is configured and SAML authentication is in use. "
        "An attacker may be able to impersonate a legitimate GlobalProtect user if the user clicks a malicious link. "
        "Remediate by upgrading to a fixed PAN-OS release (11.2.3+, 11.1.5+, 11.0.6+, 10.2.4-h25/10.2.9-h13/10.2.10-h6/10.2.11+, "
        "or 10.1.14-h11+) and/or switching the GlobalProtect portal to a non-SAML authentication method. "
        f"Advisory: {advisory_url}"
    )