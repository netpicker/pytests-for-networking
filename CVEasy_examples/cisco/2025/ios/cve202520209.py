from comfy import high


@high(
    name='rule_cve202520209',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        show_udp_brief='show udp brief'
    ),
)
def rule_cve202520209(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20209 vulnerability in Cisco IOS XR Software.
    The vulnerability is due to improper handling of malformed IKEv2 packets, which can be exploited by an
    unauthenticated, remote attacker to prevent the device from processing any control plane UDP packets,
    resulting in a denial of service (DoS) condition.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions and trains
    vulnerable_versions = [
        '7.10', '7.11',
        '24.1', '24.2'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = False
    for version in vulnerable_versions:
        if version in version_output:
            # Check if it's a fixed version
            if '7.11.21' in version_output or '24.2.2' in version_output:
                version_vulnerable = False
                break
            # Check if it's 24.3 or later (not vulnerable)
            if '24.3' in version_output:
                version_vulnerable = False
                break
            version_vulnerable = True
            break

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # If version is vulnerable, check if IKEv2 is enabled
    udp_output = commands.show_udp_brief

    # Check if the device is listening on ports 4500 and 500 (IKEv2 enabled)
    ikev2_enabled = (':4500' in udp_output and ':500' in udp_output)

    # If IKEv2 is enabled on a vulnerable version, the device is vulnerable
    is_vulnerable = ikev2_enabled

    # Assert that the device is not vulnerable
    # If the device is vulnerable, the test will fail, indicating the presence of the vulnerability
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20209. "
        "The device is running a vulnerable version of Cisco IOS XR Software AND has IKEv2 enabled "
        "(listening on UDP ports 500 and 4500), which makes it susceptible to DoS attacks via malformed IKEv2 packets. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-xrike-9wYGpRGq"
    )