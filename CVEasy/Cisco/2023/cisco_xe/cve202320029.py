from comfy import high


@high(
    name='rule_cve202320029',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_meraki='show running-config | include meraki'
    ),
)
def rule_cve202320029(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2023-20029 vulnerability in Cisco IOS XE Software.
    The vulnerability is due to insufficient memory protection in the Meraki onboarding feature.
    An attacker could exploit this vulnerability by modifying the Meraki registration parameters,
    which could allow them to elevate privileges to root.
    """
    # Extract the output of the command to check Meraki configuration
    meraki_output = commands.check_meraki

    # Check if Meraki onboarding is configured
    meraki_configured = 'meraki' in meraki_output

    # Assert that the device is not vulnerable
    assert not meraki_configured, (
        f"Device {device.name} is vulnerable to CVE-2023-20029. "
        "The device has Meraki onboarding feature enabled, "
        "which could allow an attacker to elevate privileges to root. "
        "For more information, see"
        "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-priv-esc-sABD8hcU"
    )
