from comfy import high

@high(
    name='rule_cve202530644',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_config_dhcp='show configuration | display set | match "dhcp-relay"'
    ),
)
def rule_cve202530644(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-30644 vulnerability in Juniper Networks Junos OS.
    The vulnerability is a Heap-based Buffer Overflow in the FPC that allows an attacker
    to send a specific DHCP packet to cause FPC crash and DoS, with potential for RCE
    when DHCP Option 82 is enabled.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define the vulnerable versions
    vulnerable_versions = [
        # All versions before 21.4R3-S9
        '21.4R1', '21.4R2', '21.4R3', '21.4R3-S1', '21.4R3-S2', '21.4R3-S3', '21.4R3-S4', '21.4R3-S5', '21.4R3-S6', '21.4R3-S7', '21.4R3-S8',
        '21.2', '21.3', '20.4', '20.3', '20.2', '20.1', '19.4', '19.3', '19.2', '19.1',
        # from 22.2 before 22.2R3-S5
        '22.2R1', '22.2R2', '22.2R3', '22.2R3-S1', '22.2R3-S2', '22.2R3-S3', '22.2R3-S4',
        # from 22.4 before 22.4R3-S5
        '22.4R1', '22.4R2', '22.4R3', '22.4R3-S1', '22.4R3-S2', '22.4R3-S3', '22.4R3-S4',
        # from 23.2 before 23.2R2-S3
        '23.2R1', '23.2R2', '23.2R2-S1', '23.2R2-S2',
        # from 23.4 before 23.4R2-S3
        '23.4R1', '23.4R2', '23.4R2-S1', '23.4R2-S2',
        # from 24.2 before 24.2R2
        '24.2R1', '24.2R1-S1'
    ]

    # Check if the current version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check if device is one of the vulnerable platforms
    chassis_output = commands.show_chassis_hardware
    vulnerable_platforms = ['EX2300', 'EX3400', 'EX4100', 'EX4300', 'EX4300MP', 'EX4400', 'EX4600', 'EX4650-48Y', 'QFX5']
    
    is_vulnerable_platform = any(platform in chassis_output for platform in vulnerable_platforms)

    if not is_vulnerable_platform:
        return

    # Check if DHCP relay (including Option 82) is configured
    dhcp_config = commands.show_config_dhcp
    has_dhcp_relay = 'dhcp-relay' in dhcp_config and dhcp_config.strip() != ''

    # Assert that the device is not vulnerable
    assert not has_dhcp_relay, (
        f"Device {device.name} is vulnerable to CVE-2025-30644. "
        "The device is running a vulnerable version of Junos OS on a vulnerable platform with DHCP relay configured, "
        "which makes it susceptible to heap-based buffer overflow via malicious DHCP packets, leading to FPC crash, DoS, and potential RCE. "
        "For more information, see https://supportportal.juniper.net/JSA88888"
    )