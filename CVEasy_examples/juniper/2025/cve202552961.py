import re
from comfy import high


@high(
    name='rule_cve202552961',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_config_cfm=(
            'show configuration protocols oam ethernet'
            ' connectivity-fault-management | display set'
        ),
        show_system_processes=(
            'show system processes extensive | match cfmman'
        )
    ),
)
def rule_cve202552961(configuration, commands, device, devices):
    """
    CVE-2025-52961: Junos OS Evolved cfmman memory leak on PTX platforms.
    An unauthenticated adjacent attacker can send specific valid traffic to
    cause cfmd CPU spike and cfmman memory leak, leading to FPC crash.
    """
    version_output = commands.show_version

    # Only applies to Junos OS Evolved
    if 'Junos OS Evolved' not in version_output:
        return

    # Define the vulnerable versions for Junos OS Evolved
    vulnerable_versions = [
        # 23.2 before 23.2R2-S4-EVO
        '23.2R1-EVO', '23.2R2-EVO',
        '23.2R2-S1-EVO', '23.2R2-S2-EVO', '23.2R2-S3-EVO',
        # 23.4 before 23.4R2-S4-EVO
        '23.4R1-EVO', '23.4R1-S1-EVO', '23.4R1-S2-EVO',
        '23.4R2-EVO', '23.4R2-S1-EVO', '23.4R2-S2-EVO', '23.4R2-S3-EVO',
        # 24.2 before 24.2R2-EVO
        '24.2R1-EVO', '24.2R1-S1-EVO', '24.2R1-S2-EVO',
        # 24.4 before 24.4R1-S2-EVO, 24.4R2-EVO
        '24.4R1-EVO', '24.4R1-S1-EVO',
    ]

    version_match = re.search(
        r'Junos\s+OS\s+Evolved\s+(\S+)', version_output
    )
    extracted_version = version_match.group(1) if version_match else ""
    if extracted_version not in vulnerable_versions:
        return

    # Check if device is one of the vulnerable PTX platforms
    chassis_output = commands.show_chassis_hardware
    vulnerable_platforms = [
        'PTX10001-36MR',
        'PTX10002-36QDD',
        'PTX10004',
        'PTX10008',
        'PTX10016',
    ]
    if not any(p in chassis_output for p in vulnerable_platforms):
        return

    # Check if CFM (Connectivity Fault Management) is configured
    cfm_config = commands.show_config_cfm
    cfm_lines = [
        line for line in cfm_config.splitlines()
        if not line.strip().startswith('#')
    ]
    has_cfm_configured = any(
        'connectivity-fault-management' in line for line in cfm_lines
    )

    # Check for indicators of compromise - high memory usage in cfmman
    processes_output = commands.show_system_processes
    has_memory_leak = False
    for line in processes_output.splitlines():
        if 'cfmman' not in line:
            continue
        parts = line.split()
        # Scan all numeric-looking columns for a value > 1GB (1000000 KB)
        for part in parts:
            try:
                if int(part) > 1000000:
                    has_memory_leak = True
                    break
            except ValueError:
                pass

    assert not (has_cfm_configured or has_memory_leak), (
        f"Device {device.name} is vulnerable to CVE-2025-52961. "
        "The device runs a vulnerable Junos OS Evolved on a PTX platform "
        "with CFM configured or cfmman showing signs of memory leak. "
        "An unauthenticated adjacent attacker can send specific valid traffic "
        "to cause cfmd CPU spike and cfmman memory leak, leading to FPC "
        "crash and restart. "
        "See https://supportportal.juniper.net/JSA88888"
    )
