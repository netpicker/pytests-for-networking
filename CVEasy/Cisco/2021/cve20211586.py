from comfy import high


@high(
    name='rule_cve20211586',
    platform=['cisco_nxos'],
    commands=dict(
        show_version='show version',
        check_multipod='show running-config | include multipod|multi-site'
    ),
)
def rule_cve20211586(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2021-1586 vulnerability in Cisco NX-OS Software.
    The vulnerability is due to improper sanitization of TCP traffic sent to a specific port
    in Multi-Pod or Multi-Site configurations. An unauthenticated, remote attacker could exploit
    this vulnerability by sending crafted TCP data to a specific port that is listening on a
    public-facing IP address, causing the device to restart unexpectedly and resulting in a DoS condition.
    """
    # Extract the output of the commands
    version_output = commands.show_version
    multipod_output = commands.check_multipod

    # Check if device is a Nexus 9000 in ACI mode
    is_n9k_aci = 'Nexus 9000' in version_output and 'ACI' in version_output

    # If not a Nexus 9000 in ACI mode, device is not vulnerable
    if not is_n9k_aci:
        return

    # Check if Multi-Pod or Multi-Site is configured
    multipod_configured = any(feature in multipod_output for feature in [
        'multipod',
        'multi-site'
    ])

    # Device is vulnerable if it's a Nexus 9000 in ACI mode with Multi-Pod or Multi-Site configured
    is_vulnerable = is_n9k_aci and multipod_configured

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2021-1586. "
        "The device is a Nexus 9000 in ACI mode with Multi-Pod or Multi-Site configured, which could allow "
        "an unauthenticated attacker to cause a denial of service through crafted TCP packets. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-n9kaci-tcp-dos-YXukt6gM"
    )
