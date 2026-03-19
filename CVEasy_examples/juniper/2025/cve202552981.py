from comfy import high

@high(
    name='rule_cve202552981',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_config_pim='show configuration protocols pim | display set',
        show_flowd_crashes='show system core-dumps | match flowd'
    ),
)
def rule_cve202552981(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-52981 vulnerability in Juniper Networks Junos OS.
    The vulnerability allows an unauthenticated, network-based attacker to cause a DoS
    by sending specific PIM packets that crash the flow processing daemon (flowd).
    Affects SRX1600, SRX2300, SRX 4000 Series, and SRX5000 Series with SPC3.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define the vulnerable versions
    vulnerable_versions = [
        # All versions before 21.2R3-S9
        '21.2R1', '21.2R2', '21.2R3', '21.2R3-S1', '21.2R3-S2', '21.2R3-S3', '21.2R3-S4', '21.2R3-S5', '21.2R3-S6', '21.2R3-S7', '21.2R3-S8',
        # 21.4 versions before 21.4R3-S11
        '21.4R1', '21.4R2', '21.4R3', '21.4R3-S1', '21.4R3-S2', '21.4R3-S3', '21.4R3-S4', '21.4R3-S5', '21.4R3-S6', '21.4R3-S7', '21.4R3-S8', '21.4R3-S9', '21.4R3-S10',
        # 22.2 versions before 22.2R3-S7
        '22.2R1', '22.2R2', '22.2R3', '22.2R3-S1', '22.2R3-S2', '22.2R3-S3', '22.2R3-S4', '22.2R3-S5', '22.2R3-S6',
        # 22.4 versions before 22.4R3-S6
        '22.4R1', '22.4R2', '22.4R3', '22.4R3-S1', '22.4R3-S2', '22.4R3-S3', '22.4R3-S4', '22.4R3-S5',
        # 23.2 versions before 23.2R2-S4
        '23.2R1', '23.2R2', '23.2R2-S1', '23.2R2-S2', '23.2R2-S3',
        # 23.4 versions before 23.4R2-S4
        '23.4R1', '23.4R2', '23.4R2-S1', '23.4R2-S2', '23.4R2-S3',
        # 24.2 versions before 24.2R2
        '24.2R1', '24.2R1-S1', '24.2R1-S2'
    ]

    # Check if the current version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check if device is SRX Series with SPC3
    chassis_output = commands.show_chassis_hardware
    is_srx_platform = any(model in chassis_output for model in ['SRX1600', 'SRX2300', 'SRX4', 'SRX5'])
    has_spc3 = 'SPC3' in chassis_output

    if not (is_srx_platform and has_spc3):
        return

    # Check if PIM is configured
    pim_config = commands.show_config_pim
    has_pim_configured = 'set protocols pim' in pim_config and pim_config.strip() != ''

    # Check for flowd crashes
    flowd_crashes = commands.show_flowd_crashes
    has_flowd_crashes = 'flowd' in flowd_crashes and flowd_crashes.strip() != ''

    # Assert that the device is not vulnerable
    assert not has_pim_configured, (
        f"Device {device.name} is vulnerable to CVE-2025-52981. "
        "The device is running a vulnerable version of Junos OS on SRX Series hardware with SPC3, "
        "and has PIM protocol configured, which makes it susceptible to flowd crashes through "
        "specially crafted PIM packets from unauthenticated network-based attackers. "
        "For more information, see https://supportportal.juniper.net/JSA88133"
    )