from comfy import high

@high(
    name='rule_cve202560006',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_system_software='show system software'
    ),
)
def rule_cve202560006(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-60006 vulnerability in Juniper Networks Junos OS Evolved.
    The vulnerability allows OS Command Injection through crafted CLI commands due to
    improper neutralization of special elements in CLI scripts, enabling privilege escalation
    and unauthorized command execution.
    """
    # Extract the version information from the command output
    version_output = commands.show_version
    software_output = commands.show_system_software

    # Check if this is Junos OS Evolved
    is_evolved = 'Junos OS Evolved' in version_output or 'EVO' in version_output or 'evolved' in software_output.lower()

    # If not Junos OS Evolved, device is not vulnerable
    if not is_evolved:
        return

    # Define the vulnerable versions for Junos OS Evolved
    vulnerable_24_2_versions = [
        '24.2R1-EVO', '24.2R1-S1-EVO', '24.2R2-EVO', '24.2R2-S1-EVO'
    ]
    
    vulnerable_24_4_versions = [
        '24.4R1-EVO', '24.4R1-S1-EVO'
    ]

    # Check if the current version is vulnerable
    version_vulnerable = False
    
    # Check 24.2 versions (before 24.2R2-S2-EVO)
    if '24.2' in version_output:
        version_vulnerable = any(version in version_output for version in vulnerable_24_2_versions)
    
    # Check 24.4 versions (before 24.4R2-EVO)
    if '24.4' in version_output:
        version_vulnerable = any(version in version_output for version in vulnerable_24_4_versions)

    # Assert that the device is not vulnerable
    assert not version_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-60006. "
        "The device is running a vulnerable version of Junos OS Evolved with OS Command Injection "
        "vulnerability in CLI that allows privilege escalation and unauthorized command execution. "
        "Upgrade to 24.2R2-S2-EVO or 24.4R2-EVO or later. "
        "For more information, see https://supportportal.juniper.net/JSA88588"
    )