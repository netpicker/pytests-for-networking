from comfy import high
import re


@high(
    name='rule_cve20211227',
    platform=['cisco_nxos'],
    commands=dict(
        show_version='show version',
        check_nxapi='show running-config | include feature nxapi'
    ),
)
def rule_cve20211227(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2021-1227 vulnerability in Cisco NX-OS Software.
    The vulnerability is due to insufficient CSRF protections for the NX-API feature.
    An unauthenticated, remote attacker could exploit this vulnerability by persuading
    a user of the NX-API to follow a malicious link, allowing them to perform arbitrary
    actions with the privilege level of the affected user.
    Note: The NX-API feature is disabled by default.
    """
    version_output = commands.show_version
    nxapi_output = commands.check_nxapi

    # Check if NX-API is enabled
    nxapi_enabled = 'feature nxapi' in nxapi_output
    if not nxapi_enabled:
        return

    # Extract exact version string like '8.4(2a)'
    match = re.search(r'Version\s+(\d+\.\d+\(\d+[a-z]?\))', version_output, re.IGNORECASE)
    if not match:
        return  # Could not determine version

    version = match.group(1)

    # Vulnerable only if version == 8.4(2a)
    if version.strip() == "8.4(2a)":
        assert False, (
            f"Device {device.name} is vulnerable to CVE-2021-1227. "
            f"Running NX-OS version {version} with NX-API enabled, which may allow "
            "an unauthenticated attacker to perform CSRF-based privilege escalation. "
            "For more information, see "
            "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-nxapi-csrf-wRMzWL9z"
        )
