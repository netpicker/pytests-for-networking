from comfy import high


@high(
    name='rule_cve202134705',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        check_voice='show running-config | include voice service|dial-peer voice|fxo'
    ),
)
def rule_cve202134705(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2021-34705 vulnerability in Cisco IOS Software.
    The vulnerability is due to insufficient validation of dial strings at Foreign Exchange Office (FXO) interfaces.
    An unauthenticated, remote attacker could exploit this vulnerability by sending a malformed dial string
    to an affected device via either the ISDN protocol or SIP, allowing them to bypass configured destination
    patterns and dial arbitrary numbers, potentially resulting in toll fraud.
    """
    # Extract the output of the command to check voice configuration
    voice_output = commands.check_voice

    # Check if FXO interfaces or voice services are configured
    voice_enabled = any(feature in voice_output for feature in [
        'voice service',
        'dial-peer voice',
        'fxo'
    ])

    # If voice services are not enabled, device is not vulnerable
    if not voice_enabled:
        return

    # Assert that the device is not vulnerable
    assert not voice_enabled, (
        f"Device {device.name} is vulnerable to CVE-2021-34705. "
        "The device has voice services configured with FXO interfaces, which could allow an unauthenticated attacker "
        "to bypass configured destination patterns and conduct toll fraud through malformed dial strings. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fxo-pattern-bypass-jUXgygYv"
    )
