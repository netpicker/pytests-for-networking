from comfy import high


@high(
    name='rule_cve202520181',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        show_inventory='show inventory'
    ),
)
def rule_cve202520181(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20181 vulnerability in Cisco Catalyst switches.
    The vulnerability is due to missing signature verification for specific files that may be loaded
    during the device boot process. An authenticated, local attacker with privilege level 15 or an
    unauthenticated attacker with physical access to the device could execute persistent code at boot
    time and break the chain of trust.
    """
    # Extract the version and inventory information from the command output
    version_output = commands.show_version
    inventory_output = commands.show_inventory

    # List of vulnerable product models
    vulnerable_models = [
        'WS-C2960X',
        'WS-C2960XR',
        'WS-C2960CX',
        'WS-C3560CX'
    ]

    # Check if the current device is one of the vulnerable models
    model_vulnerable = any(model in inventory_output for model in vulnerable_models)

    # If model is not vulnerable, no need to check further
    if not model_vulnerable:
        return

    # Check if device is running Cisco IOS Software (not IOS XE)
    is_ios = 'Cisco IOS Software' in version_output and 'IOS-XE' not in version_output

    # If not running IOS, device is not vulnerable
    if not is_ios:
        return

    # If we reach here, the device is vulnerable
    # This vulnerability affects all versions of IOS on the affected platforms
    # because it's a secure boot bypass vulnerability that exists regardless of configuration
    is_vulnerable = True

    # Assert that the device is not vulnerable
    # If the device is vulnerable, the test will fail, indicating the presence of the vulnerability
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20181. "
        "The device is a Catalyst 2960X, 2960XR, 2960CX, or 3560CX Series Switch running Cisco IOS Software "
        "and is susceptible to a Secure Boot bypass vulnerability. An authenticated attacker with privilege level 15 "
        "or an unauthenticated attacker with physical access could execute persistent code at boot time. "
        "Upgrade to a fixed software version. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-c2960-3560-sboot-ZtqADrHq"
    )