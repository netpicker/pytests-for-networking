from comfy import medium

@medium(
    name='rule_cve202520161',
    platform=['cisco_nxos'],
    commands=dict(
        show_version='show version',
        show_boot='show boot',
    ),
)
def rule_cve202520161(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2025-20161 vulnerability in Cisco NX-OS Software.
    The vulnerability in the software upgrade process of Cisco Nexus 3000 Series Switches
    and Cisco Nexus 9000 Series Switches in standalone NX-OS mode could allow an authenticated,
    local attacker with valid Administrator credentials to execute a command injection attack
    on the underlying operating system of an affected device.
    
    This vulnerability is due to insufficient validation of specific elements within a software image.
    An attacker could exploit this vulnerability by installing a crafted image.
    
    Note: This rule checks if the device is a vulnerable platform (Nexus 3000 or 9000 in standalone mode).
    The actual exploitation requires installing a crafted image, which cannot be detected through
    configuration checks alone. Administrators should validate the hash of any software image before installation.
    """
    # Extract the version information from the command output
    version_output = commands.show_version
    boot_output = commands.show_boot
    
    # Check if device is Nexus 3000 or 9000 Series
    is_nexus_3000 = 'Nexus 3' in version_output or 'Nexus3' in version_output
    is_nexus_9000 = 'Nexus 9' in version_output or 'Nexus9' in version_output
    
    # Check if device is in ACI mode (not vulnerable)
    is_aci_mode = 'ACI' in version_output or 'aci' in version_output.lower()
    
    # If not a vulnerable platform or in ACI mode, device is not vulnerable
    if not (is_nexus_3000 or is_nexus_9000) or is_aci_mode:
        return
    
    # All Cisco Nexus 3000 and 9000 Series Switches in standalone NX-OS mode are affected
    # regardless of device configuration, according to the advisory
    # The vulnerability is in the software upgrade process itself
    
    # Since all versions are vulnerable and there are no workarounds or configuration-based
    # mitigations, we need to check if the device is a vulnerable platform
    # The advisory states "regardless of device configuration"
    
    # List of vulnerable versions - According to the advisory, this affects all versions
    # until fixed releases are applied. Since no specific version ranges are excluded,
    # we assume all current versions are vulnerable unless patched.
    
    # Common vulnerable version patterns for NX-OS
    vulnerable_version_patterns = [
        '6.0(2)', '7.0(3)', '9.2', '9.3', '10.1', '10.2', '10.3', '10.4'
    ]
    
    # Check if the current device's software version matches vulnerable patterns
    version_vulnerable = any(pattern in version_output for pattern in vulnerable_version_patterns)
    
    # If we can't determine version vulnerability, assume vulnerable for safety
    if not version_vulnerable:
        # Check for any NX-OS version format
        if 'NXOS' in version_output or 'NX-OS' in version_output:
            version_vulnerable = True
    
    # Assert that the device is not vulnerable
    # Since this vulnerability affects the upgrade process and cannot be mitigated through
    # configuration, we flag all vulnerable platforms as potentially at risk
    assert not version_vulnerable, (
        f"Device {device.name} may be vulnerable to CVE-2025-20161. "
        "This Cisco Nexus 3000 or 9000 Series Switch in standalone NX-OS mode is affected by a "
        "command injection vulnerability in the software upgrade process. "
        "An authenticated, local attacker with Administrator credentials could exploit this by installing a crafted image. "
        "There are no workarounds available. Apply fixed software and always validate the hash of any software image before installation. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-ici-dpOjbWxk"
    )