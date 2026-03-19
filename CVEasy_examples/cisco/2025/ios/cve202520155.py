from comfy import high


@high(
    name='rule_cve202520155',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        show_sdwan_config='show sdwan running-config',
        show_running_config='show running-config | include sdwan|sd-routing'
    ),
)
def rule_cve202520155(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20155 vulnerability in Cisco IOS XE Software.
    The vulnerability is due to insufficient input validation of the bootstrap file that is read
    by the system software when a device is first deployed in SD-WAN mode or when an administrator
    configures SD-Routing on the device. An attacker could exploit this vulnerability by modifying
    a bootstrap file and loading it into the device, allowing arbitrary file writes to the underlying
    operating system.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if this is IOS XE Software (vulnerability only affects IOS XE)
    if 'IOS XE Software' not in version_output:
        return

    # List of vulnerable software versions (based on advisory - devices supporting SD-WAN or SD-Routing)
    # The advisory states all versions supporting SD-WAN/SD-Routing are vulnerable until fixed
    vulnerable_version_patterns = [
        '17.3', '17.4', '17.5', '17.6', '17.7', '17.8', '17.9',
        '17.10', '17.11', '17.12', '17.13', '17.14', '17.15'
    ]

    # Check if the current device's software version matches vulnerable patterns
    version_vulnerable = any(pattern in version_output for pattern in vulnerable_version_patterns)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if SD-WAN or SD-Routing is configured
    config_output = commands.show_running_config
    sdwan_config_output = commands.show_sdwan_config

    # Check if SD-WAN mode is enabled (but not disabled with "no sdwan")
    sdwan_enabled = ('sdwan' in config_output.lower() or 'sd-wan' in config_output.lower()) and \
                    'no sdwan' not in config_output.lower() and 'no sd-wan' not in config_output.lower()

    # Check if SD-Routing is configured (but not disabled with "no sd-routing")
    sd_routing_enabled = 'sd-routing' in config_output.lower() and 'no sd-routing' not in config_output.lower()

    # Check if device has SD-WAN configuration
    has_sdwan_config = sdwan_config_output and len(sdwan_config_output.strip()) > 0 and 'sdwan' in sdwan_config_output.lower()

    # If SD-WAN or SD-Routing is enabled/configured, the device is vulnerable
    is_vulnerable = sdwan_enabled or sd_routing_enabled or has_sdwan_config

    # Assert that the device is not vulnerable
    # If the device is vulnerable, the test will fail, indicating the presence of the vulnerability
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20155. "
        "The device is running a vulnerable version of IOS XE Software AND has SD-WAN or SD-Routing configured, "
        "which makes it susceptible to arbitrary file write attacks through malicious bootstrap files. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-bootstrap-KfgxYgdh"
    )