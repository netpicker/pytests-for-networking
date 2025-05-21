from comfy import high


@high(
    name='rule_cve20211313',
    platform=['cisco_xr'],
    commands=dict(
        show_version='show version',
        check_enf='show running-config | include enf|enforcement'
    ),
)
def rule_cve20211313(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2021-1313 vulnerability in Cisco IOS XR Software.
    The vulnerability is due to improper handling of ingress packets in the enforcement broker
    function. An unauthenticated, remote attacker could exploit this vulnerability by sending
    crafted packets to an affected device, causing a denial of service (DoS) condition through
    resource exhaustion.
    """
    # Extract the output of the commands
    version_output = commands.show_version
    enf_output = commands.check_enf

    # Check if enforcement features are enabled
    has_enf_features = any(feature in enf_output for feature in [
        'enf',
        'enforcement'
    ])

    # If no enforcement features are enabled, device is not vulnerable
    if not has_enf_features:
        return

    # Assert that the device is not vulnerable
    assert not has_enf_features, (
        f"Device {device.name} is vulnerable to CVE-2021-1313. "
        "The device has enforcement broker features enabled, which could allow "
        "an unauthenticated attacker to cause a denial of service through crafted packets. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-dos-WwDdghs2"
    )
