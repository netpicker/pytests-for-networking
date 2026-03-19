from comfy import high


@high(
    name='rule_cve202520202',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        show_running_config='show running-config | section ap profile'
    ),
)
def rule_cve202520202(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20202 vulnerability in Cisco IOS XE Wireless Controller Software.
    The vulnerability is due to insufficient input validation of access point (AP) Cisco Discovery Protocol (CDP)
    neighbor reports when they are processed by the wireless controller. An attacker could exploit this vulnerability
    by sending a crafted CDP packet to an AP, causing an unexpected reload of the wireless controller.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if this is a Cisco IOS XE device with wireless controller capabilities
    # Vulnerable products: Catalyst 9800 series and embedded wireless controllers
    is_wireless_controller = any(keyword in version_output for keyword in [
        'Catalyst 9800',
        '9800-CL',
        'C9800',
        'Embedded Wireless Controller'
    ])

    # If not a wireless controller, device is not vulnerable
    if not is_wireless_controller:
        return

    # Extract the configuration output
    config_output = commands.show_running_config

    # Check if any AP profile exists
    has_ap_profile = 'ap profile' in config_output

    # If no AP profiles exist, device is not vulnerable
    if not has_ap_profile:
        return

    # Parse AP profiles to check if CDP is enabled on any profile
    # CDP is enabled by default unless explicitly disabled with "no cdp"
    lines = config_output.split('\n')
    
    current_profile = None
    profiles_with_cdp_enabled = []
    
    for line in lines:
        line = line.strip()
        if line.startswith('ap profile '):
            # Extract profile name
            current_profile = line.replace('ap profile ', '').strip()
            # Assume CDP is enabled by default for each profile
            profiles_with_cdp_enabled.append(current_profile)
        elif line == 'no cdp' and current_profile:
            # CDP is explicitly disabled for this profile
            if current_profile in profiles_with_cdp_enabled:
                profiles_with_cdp_enabled.remove(current_profile)

    # If at least one AP profile has CDP enabled, the device is vulnerable
    is_vulnerable = len(profiles_with_cdp_enabled) > 0

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20202. "
        f"The device is a wireless controller with CDP enabled on AP profile(s): {', '.join(profiles_with_cdp_enabled)}. "
        "This makes it susceptible to DoS attacks via crafted CDP packets sent to managed APs. "
        "Mitigation: Disable CDP on all AP profiles using 'no cdp' command if CDP is not required. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ewlc-cdp-dos-fpeks9K"
    )