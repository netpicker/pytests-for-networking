from comfy import high


@high(
    name='rule_cve202134699',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        check_trustsec='show running-config | include cts|trustsec'
    ),
)
def rule_cve202134699(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2021-34699 vulnerability in Cisco IOS Software.
    The vulnerability is due to an improper interaction between the web UI and the TrustSec CLI parser.
    An authenticated, remote attacker could exploit this vulnerability by requesting a particular CLI
    command to be run through the web UI, causing the device to reload and resulting in a denial of service.
    Note: The TrustSec feature must be enabled for the device to be vulnerable.
    """
    # Extract the output of the command to check TrustSec configuration
    trustsec_output = commands.check_trustsec

    # Check if TrustSec is enabled
    trustsec_enabled = any(feature in trustsec_output for feature in [
        'cts',
        'trustsec'
    ])

    # If TrustSec is not enabled, device is not vulnerable
    if not trustsec_enabled:
        return

    # Assert that the device is not vulnerable
    assert not trustsec_enabled, (
        f"Device {device.name} is vulnerable to CVE-2021-34699. "
        "The device has TrustSec enabled, which could allow an authenticated attacker "
        "to cause a denial of service through crafted CLI commands via the web UI. "
        "For more information, see "
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-trustsec-dos-7fuXDR2"
    )
