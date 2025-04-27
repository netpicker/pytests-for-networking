from comfy import high

@high(
    name='rule_cve20242973',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_ha='show configuration | display set | match "high-availability"'
    )
)
def rule_cve20242973(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-2973 vulnerability in Juniper Networks Session Smart Router (SSR),
    Session Smart Conductor, and WAN Assurance Router. The vulnerability allows an unauthenticated,
    network-based attacker to bypass authentication and take full control of devices in redundant
    router deployments.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # Extract version information
    version_output = commands.show_version

    # List of vulnerable software versions
    vulnerable_versions = [
        # SSR versions before 5.6.15
        '5.6.14', '5.6.13', '5.6.12', '5.6.11', '5.6.10',
        '5.6.9', '5.6.8', '5.6.7', '5.6.6', '5.6.5',
        '5.6.4', '5.6.3', '5.6.2', '5.6.1', '5.6.0',
        # 6.0 versions before 6.1.9-lts
        '6.0.0', '6.0.1', '6.0.2', '6.0.3', '6.0.4',
        '6.1.0', '6.1.1', '6.1.2', '6.1.3', '6.1.4',
        '6.1.5', '6.1.6', '6.1.7', '6.1.8',
        # 6.2 versions before 6.2.5-sts
        '6.2.0', '6.2.1', '6.2.2', '6.2.3', '6.2.4'
    ]

    # Check if version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if high-availability is configured
    ha_config = commands.show_config_ha
    ha_enabled = 'high-availability' in ha_config

    assert not ha_enabled, (
        f"Device {device.name} is vulnerable to CVE-2024-2973. "
        "The device is running a vulnerable version with high-availability configured. "
        "This configuration can allow an attacker to bypass authentication and take full control. "
        "Please upgrade to one of the following fixed versions: "
        "SSR-5.6.15, SSR-6.1.9-lts, SSR-6.2.5-sts, or later. "
        "For Conductor-managed deployments, upgrading Conductor nodes is sufficient. "
        "For more information, see https://supportportal.juniper.net/JSA83126"
    )
