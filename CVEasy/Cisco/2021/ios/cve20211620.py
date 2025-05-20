from comfy import high


@high(
    name='rule_cve20211620',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        check_ikev2='show running-config | include crypto ikev2'
    ),
)
def rule_cve20211620(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2021-1620 vulnerability in Cisco IOS Software.
    The vulnerability is due to insufficient IP address management in the IKEv2 AutoReconnect feature.
    An authenticated, remote attacker could exploit this vulnerability by attempting to connect
    with a non-AnyConnect client, causing IP addresses in the local pool to not be released,
    eventually leading to IP address exhaustion and a denial of service condition.
    """
    # Extract the output of the command to check IKEv2 configuration
    ikev2_output = commands.check_ikev2

    # Check if IKEv2 AutoReconnect is configured
    ikev2_enabled = any(feature in ikev2_output for feature in [
        'crypto ikev2 client configuration group',
        'crypto ikev2 authorization policy'
    ])

    # If IKEv2 is not enabled, device is not vulnerable
    if not ikev2_enabled:
        return

    # Assert that the device is not vulnerable
    assert not ikev2_enabled, (
        f"Device {device.name} is vulnerable to CVE-2021-1620. "
        "The device has IKEv2 client configuration enabled, which could allow an authenticated attacker "
        "to cause IP address exhaustion and denial of service through non-AnyConnect client connections. "
        "For more information, see "
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ikev2-ebFrwMPr"
    )
