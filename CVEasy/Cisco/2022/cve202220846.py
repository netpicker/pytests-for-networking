from comfy import high


@high(
    name='rule_cve202220846',
    platform=['cisco_xr'],
    commands=dict(
        show_version='show version',
        check_cdp='show running-config | include cdp'
    ),
)
def rule_cve202220846(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2022-20846 vulnerability in Cisco IOS XR Software.
    The vulnerability is due to a heap buffer overflow in certain Cisco Discovery Protocol messages.
    An unauthenticated, adjacent attacker could exploit this vulnerability by sending malicious
    Cisco Discovery Protocol packets to an affected device, causing the CDP process to reload.
    """
    # List of vulnerable versions
    vulnerable_versions = [
        '6.5.1', '6.5.2', '6.5.3', '6.5.15', '6.5.25', '6.5.26', '6.5.28', '6.5.29',
        '6.5.31', '6.5.32', '6.5.90', '6.5.92', '6.5.93',
        '6.6.1', '6.6.2', '6.6.3', '6.6.4', '6.6.11', '6.6.12', '6.6.25',
        '6.7.1', '6.7.2', '6.7.3', '6.7.4', '6.7.35',
        '6.8.1', '6.8.2', '6.9.1',
        '7.0.0', '7.0.1', '7.0.2', '7.0.11', '7.0.12', '7.0.14', '7.0.90',
        '7.1.1', '7.1.2', '7.1.3', '7.1.15', '7.1.25',
        '7.2.0', '7.2.1', '7.2.2', '7.2.12',
        '7.3.1', '7.3.2', '7.3.3', '7.3.4', '7.3.15', '7.3.16', '7.3.27',
        '7.4.1', '7.4.2', '7.4.15', '7.4.16',
        '7.5.1', '7.5.2', '7.5.12',
        '7.6.1', '7.6.15'
    ]

    # Extract the version information
    version_output = commands.show_version

    # Check if version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Extract the output of the command to check CDP configuration
    cdp_output = commands.check_cdp

    # Check if CDP is enabled (CDP is enabled by default unless explicitly disabled)
    cdp_disabled = 'no cdp' in cdp_output

    # Assert that the device is not vulnerable
    assert cdp_disabled, (
        f"Device {device.name} is vulnerable to CVE-2022-20846. "
        "The device is running a vulnerable version with CDP enabled, "
        "which could allow an adjacent attacker to cause a denial of service through malicious CDP packets. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-xr-cdp-wnALzvT2"
    )
