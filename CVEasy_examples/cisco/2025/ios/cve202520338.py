from comfy import high


@high(
    name='rule_cve202520338',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
    ),
)
def rule_cve202520338(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20338 vulnerability in Cisco IOS XE Software.
    The vulnerability is due to insufficient validation of user arguments that are passed to specific CLI commands.
    An authenticated, local attacker with administrative privileges could exploit this vulnerability to execute
    arbitrary commands as root on the underlying operating system of an affected device.
    
    Note: This vulnerability affects all Cisco IOS XE Software versions at the time of publication,
    regardless of device configuration. The vulnerability requires administrative (level 15) credentials
    to exploit, so this test checks if the device is running vulnerable IOS XE software.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if the device is running Cisco IOS XE Software
    # The advisory states that all IOS XE versions are vulnerable at the time of publication
    is_ios_xe = 'IOS XE' in version_output or 'IOS-XE' in version_output

    # If not running IOS XE, device is not vulnerable
    if not is_ios_xe:
        return

    # Check if running a fixed version
    # Since the advisory doesn't specify fixed versions in the provided text,
    # we assume all IOS XE versions are vulnerable unless proven otherwise
    # Customers should use Cisco Software Checker to determine fixed versions
    
    # For this test, we'll check for presence of IOS XE which indicates vulnerability
    # In a real scenario, you would check against a list of fixed versions
    is_vulnerable = is_ios_xe

    # Assert that the device is not vulnerable
    # If the device is vulnerable, the test will fail, indicating the presence of the vulnerability
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20338. "
        "The device is running Cisco IOS XE Software which is affected by a CLI argument injection vulnerability. "
        "An authenticated attacker with administrative privileges could execute arbitrary commands as root. "
        "Please upgrade to a fixed software version using the Cisco Software Checker. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-arg-inject-EyDDbh4e"
    )