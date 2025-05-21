from comfy import high


@high(
    name='rule_cve20211288',
    platform=['cisco_xr'],
    commands=dict(
        show_version='show version',
        check_ingress='show running-config | include ingress|qos'
    ),
)
def rule_cve20211288(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2021-1288 vulnerability in Cisco IOS XR Software.
    The vulnerability is due to improper handling of ingress packets in the packet processing function.
    An unauthenticated, remote attacker could exploit this vulnerability by sending crafted packets
    to an affected device, causing a denial of service (DoS) condition through resource exhaustion.
    """
    # Extract the output of the commands
    version_output = commands.show_version
    ingress_output = commands.check_ingress

    # Check if ingress packet processing features are enabled
    has_ingress_features = any(feature in ingress_output for feature in [
        'ingress',
        'qos'
    ])

    # If no ingress features are enabled, device is not vulnerable
    if not has_ingress_features:
        return

    # Assert that the device is not vulnerable
    assert not has_ingress_features, (
        f"Device {device.name} is vulnerable to CVE-2021-1288. "
        "The device has ingress packet processing features enabled, which could allow "
        "an unauthenticated attacker to cause a denial of service through crafted packets. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-dos-WwDdghs2""
    )
