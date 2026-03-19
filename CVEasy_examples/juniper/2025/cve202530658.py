import re
from comfy import high


@high(
    name='rule_cve202530658',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_security_utm='show configuration security utm | display set',
        show_jbuf_utilization='show system buffers'
    ),
)
def rule_cve202530658(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-30658 vulnerability in Juniper Networks Junos OS.
    The vulnerability allows an unauthenticated, network-based attacker to cause a DoS
    by triggering a jbuf memory leak in Anti-Virus processing on SRX Series devices.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define the vulnerable version ranges
    vulnerable_versions = []

    # All versions before 21.2R3-S9
    vulnerable_versions.extend([
        '21.2R1', '21.2R2', '21.2R3', '21.2R3-S1', '21.2R3-S2', '21.2R3-S3',
        '21.2R3-S4', '21.2R3-S5', '21.2R3-S6', '21.2R3-S7', '21.2R3-S8'
    ])

    # 21.4 versions before 21.4R3-S10
    vulnerable_versions.extend([
        '21.4R1', '21.4R2', '21.4R3', '21.4R3-S1', '21.4R3-S2', '21.4R3-S3',
        '21.4R3-S4', '21.4R3-S5', '21.4R3-S6', '21.4R3-S7', '21.4R3-S8',
        '21.4R3-S9'
    ])

    # 22.2 versions before 22.2R3-S6
    vulnerable_versions.extend([
        '22.2R1', '22.2R2', '22.2R3', '22.2R3-S1', '22.2R3-S2', '22.2R3-S3',
        '22.2R3-S4', '22.2R3-S5'
    ])

    # 22.4 versions before 22.4R3-S6
    vulnerable_versions.extend([
        '22.4R1', '22.4R2', '22.4R3', '22.4R3-S1', '22.4R3-S2', '22.4R3-S3',
        '22.4R3-S4', '22.4R3-S5'
    ])

    # 23.2 versions before 23.2R2-S3
    vulnerable_versions.extend([
        '23.2R1', '23.2R2', '23.2R2-S1', '23.2R2-S2'
    ])

    # 23.4 versions before 23.4R2-S3
    vulnerable_versions.extend([
        '23.4R1', '23.4R2', '23.4R2-S1', '23.4R2-S2'
    ])

    # 24.2 versions before 24.2R2
    vulnerable_versions.extend([
        '24.2R1', '24.2R1-S1', '24.2R1-S2'
    ])

    # Check if the current version is vulnerable
    version_match = re.search(r'Junos:\s+(\S+)', version_output)
    extracted_version = version_match.group(1) if version_match else ""
    version_vulnerable = extracted_version in vulnerable_versions

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check if device is SRX Series
    chassis_output = commands.show_chassis_hardware
    is_srx_platform = 'SRX' in chassis_output

    if not is_srx_platform:
        return

    # Check if Anti-Virus is enabled
    utm_config = commands.show_security_utm
    utm_lines = [
        line for line in utm_config.splitlines()
        if not line.strip().startswith('#')
    ]
    has_antivirus_enabled = any(
        'anti-virus' in line.lower() or 'utm feature-profile' in line.lower()
        for line in utm_lines
    )

    # Assert that the device is not vulnerable
    assert not has_antivirus_enabled, (
        f"Device {device.name} is vulnerable to CVE-2025-30658. "
        "The device is running a vulnerable version of Junos OS on SRX Series "
        "hardware with Anti-Virus enabled, which makes it susceptible to jbuf "
        "memory leak causing Denial-of-Service when specific HTTP response "
        "content is processed. The device will require a manual reboot to "
        "recover from jbuf exhaustion. "
        "For more information, see https://supportportal.juniper.net/JSA88588"
    )
