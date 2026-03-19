import re
from comfy import high

@high(
    name='rule_cve202521601',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_config_jweb=(
            'show configuration | display set'
            ' | match "system services web-management"'
        ),
        show_config_captive_portal=(
            'show configuration | display set | match "captive-portal"'
        ),
        show_config_dot1x=(
            'show configuration | display set | match "dot1x"'
        ),
        show_config_jsc=(
            'show configuration | display set | match "juniper-secure-connect"'
        ),
        show_httpd_process=(
            'show system processes extensive | match httpd'
        )
    ),
)
def rule_cve202521601(configuration, commands, device, devices):
    """
    CVE-2025-21601: An unauthenticated network-based attacker can cause CPU
    exhaustion through web management services (J-Web, Captive Portal,
    802.1X, JSC), leading to a sustained DoS condition.
    """
    version_output = commands.show_version

    vulnerable_versions = [
        # All versions before 21.4R3-S9
        '21.4R1', '21.4R2', '21.4R3',
        '21.4R3-S1', '21.4R3-S2', '21.4R3-S3', '21.4R3-S4',
        '21.4R3-S5', '21.4R3-S6', '21.4R3-S7', '21.4R3-S8',
        # from 22.2 before 22.2R3-S5
        '22.2R1', '22.2R2', '22.2R3',
        '22.2R3-S1', '22.2R3-S2', '22.2R3-S3', '22.2R3-S4',
        # from 22.4 before 22.4R3-S4
        '22.4R1', '22.4R2', '22.4R3',
        '22.4R3-S1', '22.4R3-S2', '22.4R3-S3',
        # from 23.2 before 23.2R2-S3
        '23.2R1', '23.2R2', '23.2R2-S1', '23.2R2-S2',
        # from 23.4 before 23.4R2-S3
        '23.4R1', '23.4R2', '23.4R2-S1', '23.4R2-S2',
        # from 24.2 before 24.2R1-S1, 24.2R2
        '24.2R1',
    ]

    version_match = re.search(r'Junos:\s+(\S+)', version_output)
    extracted_version = version_match.group(1) if version_match else ""
    if extracted_version not in vulnerable_versions:
        return

    # Check if device is on affected platform
    chassis_output = commands.show_chassis_hardware
    affected_platforms = ['SRX', 'EX', 'MX240', 'MX480', 'MX960', 'QFX5120']
    if not any(p in chassis_output for p in affected_platforms):
        return

    # Check if vulnerable web management services are enabled
    def active_lines(output):
        return [
            line for line in output.splitlines()
            if not line.strip().startswith('#')
        ]

    jweb_lines = active_lines(commands.show_config_jweb)
    captive_lines = active_lines(commands.show_config_captive_portal)
    dot1x_lines = active_lines(commands.show_config_dot1x)
    jsc_lines = active_lines(commands.show_config_jsc)

    has_jweb = any(
        'system services web-management' in line and 'http' in line
        for line in jweb_lines
    )
    has_captive_portal = any(
        'captive-portal' in line for line in captive_lines
    )
    has_dot1x = any('dot1x' in line for line in dot1x_lines)
    has_jsc = any('juniper-secure-connect' in line for line in jsc_lines)

    has_vulnerable_service = (
        has_jweb or has_captive_portal or has_dot1x or has_jsc
    )

    # Check for high httpd CPU usage as indicator of compromise
    httpd_output = commands.show_httpd_process
    high_cpu_usage = False
    if httpd_output:
        for line in httpd_output.splitlines():
            if 'httpd' not in line:
                continue
            for part in line.split():
                if '%' not in part:
                    continue
                try:
                    if float(part.replace('%', '')) > 50:
                        high_cpu_usage = True
                except ValueError:
                    pass

    assert not has_vulnerable_service, (
        f"Device {device.name} is vulnerable to CVE-2025-21601. "
        "The device runs a vulnerable Junos OS with web management services "
        "enabled (J-Web, Captive Portal, 802.1X, or Juniper Secure Connect), "
        "susceptible to CPU exhaustion DoS from unauthenticated attackers. "
        + (
            "HIGH CPU USAGE DETECTED IN httpd - POSSIBLE ACTIVE EXPLOITATION! "
            if high_cpu_usage else ""
        )
        + "See https://supportportal.juniper.net/JSA88143"
    )
