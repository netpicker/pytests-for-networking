from comfy import high

@high(
    name='rule_cve202520141',
    platform=['cisco_ios-xr'],
    commands=dict(show_version='show version'),
)
def rule_cve202520141(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20141 in Cisco IOS XR Software.
    A vulnerability in the handling of specific packets that are punted from a line card
    to a route processor in Cisco IOS XR Software Release 7.9.2 could allow an unauthenticated,
    adjacent attacker to cause control plane traffic to stop working, resulting in a DoS condition.
    
    Affected Products:
    - IOS XR White box (IOSXRWBD)
    - Network Convergence System (NCS) 540 Series Routers (NCS540-iosxr base image)
    - NCS 5500 Series
    - NCS 5700 Series (NCS5500-iosxr base image)
    
    Only affects Cisco IOS XR Release 7.9.2
    """

    # Extract the output of the 'show version' command
    show_version_output = commands.show_version

    # Define the vulnerable software version
    vulnerable_version = '7.9.2'

    # Check if the device's software version is the vulnerable version
    is_vulnerable = vulnerable_version in show_version_output

    # Assert that the device is not running the vulnerable version
    # If the device is running version 7.9.2, the test will fail
    assert not is_vulnerable, (
        f"Device {device.name} is running Cisco IOS XR Software Release 7.9.2, which is vulnerable to CVE-2025-20141. "
        "This vulnerability could allow an unauthenticated, adjacent attacker to cause control plane traffic to stop working, "
        "resulting in a denial of service (DoS) condition. "
        "Please apply the SMU on 7.9.2 or migrate to a fixed release (7.10 or later, or 7.8 and earlier). "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-xr792-bWfVDPY"
    )