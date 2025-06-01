from comfy import high


@high(
    name='rule_cve202220761',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        check_ap='show running-config | include autonomous-ap'
    ),
)
def rule_cve202220761(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2022-20761 vulnerability in Cisco IOS Software.
    The vulnerability is due to insufficient input validation in the integrated wireless access point (AP)
    packet processing of the Cisco 1000 Series Connected Grid Router (CGR1K). An attacker could exploit
    this vulnerability by sending crafted traffic to an affected device, causing the integrated AP to stop
    processing traffic and resulting in a denial of service condition.
    """
    # Extract the output of the command to check AP configuration
    ap_output = commands.check_ap

    # Check if integrated AP is configured
    ap_configured = 'autonomous-ap' in ap_output

    # Assert that the device is not vulnerable
    assert not ap_configured, (
        f"Device {device.name} is vulnerable to CVE-2022-20761. "
        "The device has integrated wireless access point configured, "
        "which could allow an adjacent attacker to cause a denial of service through crafted traffic. "
        "For more information, see "
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cgr1k-ap-dos-mSZR4QVh"
    )
