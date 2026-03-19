import re
from comfy import high

@high(
    name='rule_cve202552986',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_rib_sharding='show configuration | display set | match "routing-options rib-sharding"',
        show_task_memory='show task memory detail | match task_shard_mgmt_cookie'
    ),
)
def rule_cve202552986(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-52986 vulnerability in Juniper Networks Junos OS and Junos OS Evolved.
    The vulnerability allows a local, low-privileged user to cause memory leaks in rpd when RIB sharding
    is enabled and routing-related 'show' commands are executed, eventually leading to rpd crash.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define the vulnerable versions for Junos OS
    vulnerable_versions = [
        # All versions before 21.2R3-S9
        '21.2R1', '21.2R2', '21.2R3', '21.2R3-S1', '21.2R3-S2', '21.2R3-S3', '21.2R3-S4', '21.2R3-S5', '21.2R3-S6', '21.2R3-S7', '21.2R3-S8',
        # 21.4 versions before 21.4R3-S11
        '21.4R1', '21.4R2', '21.4R3', '21.4R3-S1', '21.4R3-S2', '21.4R3-S3', '21.4R3-S4', '21.4R3-S5', '21.4R3-S6', '21.4R3-S7', '21.4R3-S8', '21.4R3-S9', '21.4R3-S10',
        # 22.2 versions before 22.2R3-S7
        '22.2R1', '22.2R2', '22.2R3', '22.2R3-S1', '22.2R3-S2', '22.2R3-S3', '22.2R3-S4', '22.2R3-S5', '22.2R3-S6',
        # 22.4 versions before 22.4R3-S7
        '22.4R1', '22.4R2', '22.4R3', '22.4R3-S1', '22.4R3-S2', '22.4R3-S3', '22.4R3-S4', '22.4R3-S5', '22.4R3-S6',
        # 23.2 versions before 23.2R2-S4
        '23.2R1', '23.2R2', '23.2R2-S1', '23.2R2-S2', '23.2R2-S3',
        # 23.4 versions before 23.4R2-S4
        '23.4R1', '23.4R2', '23.4R2-S1', '23.4R2-S2', '23.4R2-S3',
        # 24.2 versions before 24.2R2
        '24.2R1', '24.2R1-S1',
        # 24.4 versions before 24.4R1-S2, 24.4R2
        '24.4R1', '24.4R1-S1',
        # Junos OS Evolved versions
        # All versions before 22.2R3-S7-EVO
        '22.2R1-EVO', '22.2R2-EVO', '22.2R3-EVO', '22.2R3-S1-EVO', '22.2R3-S2-EVO', '22.2R3-S3-EVO', '22.2R3-S4-EVO', '22.2R3-S5-EVO', '22.2R3-S6-EVO',
        # 22.4-EVO versions before 22.4R3-S7-EVO
        '22.4R1-EVO', '22.4R2-EVO', '22.4R3-EVO', '22.4R3-S1-EVO', '22.4R3-S2-EVO', '22.4R3-S3-EVO', '22.4R3-S4-EVO', '22.4R3-S5-EVO', '22.4R3-S6-EVO',
        # 23.2-EVO versions before 23.2R2-S4-EVO
        '23.2R1-EVO', '23.2R2-EVO', '23.2R2-S1-EVO', '23.2R2-S2-EVO', '23.2R2-S3-EVO',
        # 23.4-EVO versions before 23.4R2-S4-EVO
        '23.4R1-EVO', '23.4R2-EVO', '23.4R2-S1-EVO', '23.4R2-S2-EVO', '23.4R2-S3-EVO',
        # 24.2-EVO versions before 24.2R2-EVO
        '24.2R1-EVO', '24.2R1-S1-EVO',
        # 24.4-EVO versions before 24.4R2-EVO
        '24.4R1-EVO', '24.4R1-S1-EVO'
    ]

    # Extract exact version token and check if it is vulnerable
    match = re.search(r'Junos:\s+(\S+)', version_output)
    version = match.group(1) if match else ""
    version_vulnerable = version in vulnerable_versions

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check if RIB sharding is enabled
    rib_sharding_output = commands.show_config_rib_sharding
    rib_sharding_enabled = 'routing-options' in rib_sharding_output and 'rib-sharding' in rib_sharding_output

    # If RIB sharding is not enabled, the device is not vulnerable
    if not rib_sharding_enabled:
        return

    # Assert that the device is not vulnerable
    assert False, (
        f"Device {device.name} is vulnerable to CVE-2025-52986. "
        "The device is running a vulnerable version of Junos OS with RIB sharding enabled, "
        "which makes it susceptible to memory leaks in rpd when routing-related 'show' commands are executed. "
        "This can lead to rpd crash and restart when all available memory is consumed. "
        "For more information, see https://supportportal.juniper.net/JSA88986"
    )