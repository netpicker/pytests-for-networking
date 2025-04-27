from comfy import high

@high(
    name='rule_cve202423110',
    platform=['fortinet'],
    commands=dict(
        show_version='get system status'
    ),
)
def rule_cve202423110(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2024-23110 vulnerability in Fortinet FortiOS.
    The vulnerability is a stack-based buffer overflow that allows an attacker to execute
    unauthorized code or commands via specially crafted commands.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions
    vulnerable_versions = [
        '7.4.0', '7.4.1', '7.4.2',
        '7.2.0', '7.2.1', '7.2.2', '7.2.3', '7.2.4', '7.2.5', '7.2.6',
        '7.0.0', '7.0.1', '7.0.2', '7.0.3', '7.0.4', '7.0.5', '7.0.6', '7.0.7', '7.0.8', '7.0.9', '7.0.10', '7.0.11', '7.0.12', '7.0.13',
        '6.4.0', '6.4.1', '6.4.2', '6.4.3', '6.4.4', '6.4.5', '6.4.6', '6.4.7', '6.4.8', '6.4.9', '6.4.10', '6.4.11', '6.4.12', '6.4.13', '6.4.14',
        '6.2.0', '6.2.1', '6.2.2', '6.2.3', '6.2.4', '6.2.5', '6.2.6', '6.2.7', '6.2.8', '6.2.9', '6.2.10', '6.2.11', '6.2.12', '6.2.13', '6.2.14', '6.2.15',
        '6.0.0', '6.0.1', '6.0.2', '6.0.3', '6.0.4', '6.0.5', '6.0.6', '6.0.7', '6.0.8', '6.0.9', '6.0.10', '6.0.11', '6.0.12', '6.0.13', '6.0.14', '6.0.15', '6.0.16', '6.0.17', '6.0.18'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # Assert that the device is not vulnerable
    assert not version_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2024-23110. "
        "The device is running a vulnerable version, which makes it susceptible to stack-based buffer overflow attacks. "
        "For more information, see https://fortiguard.com/psirt/FG-IR-23-460"
    )
