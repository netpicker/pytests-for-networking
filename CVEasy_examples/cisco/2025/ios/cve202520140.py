from comfy import high


@high(
    name='rule_cve202520140',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        show_ipv6_config=r'show run all | include wireless\ ipv6\ client'
    ),
)
def rule_cve202520140(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20140 vulnerability in Cisco IOS XE Software for WLCs.
    The vulnerability is due to improper memory management in the Wireless Network Control daemon (wncd),
    which can be exploited by an unauthenticated, adjacent wireless attacker to cause a denial of service (DoS)
    condition by sending a series of IPv6 network requests from an associated wireless IPv6 client.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if this is a Cisco IOS XE device with WLC capabilities
    # Affected products: Catalyst 9800 Series, Catalyst 9300/9400/9500 with Embedded WLC, Catalyst 9800-CL
    is_wlc_device = any(keyword in version_output for keyword in [
        'Catalyst 9800',
        'C9800',
        '9800-CL',
        'Embedded Wireless Controller'
    ])

    # If not a WLC device, not vulnerable
    if not is_wlc_device:
        return

    # Check if the device is running IOS XE (not IOS)
    is_ios_xe = 'IOS XE' in version_output or 'IOS-XE' in version_output

    # If not IOS XE, not vulnerable
    if not is_ios_xe:
        return

    # Extract configuration for IPv6 wireless client support
    ipv6_config_output = commands.show_ipv6_config

    # Check if wireless IPv6 client support is enabled (enabled by default)
    # If the command returns "wireless ipv6 client", the feature is enabled
    # We need to check for "no wireless ipv6 client" first to avoid false positives
    ipv6_client_enabled = 'wireless ipv6 client' in ipv6_config_output and 'no wireless ipv6 client' not in ipv6_config_output

    # Device is vulnerable if it's a WLC running IOS XE with IPv6 client support enabled
    is_vulnerable = ipv6_client_enabled

    # Assert that the device is not vulnerable
    # If the device is vulnerable, the test will fail, indicating the presence of the vulnerability
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20140. "
        "The device is running Cisco IOS XE Software for WLC with wireless IPv6 client support enabled, "
        "which makes it susceptible to DoS attacks via IPv6 network requests from associated wireless clients. "
        "Mitigation: Disable wireless IPv6 clients using 'no wireless ipv6 client' command if not in use. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-wlc-wncd-p6Gvt6HL"
    )