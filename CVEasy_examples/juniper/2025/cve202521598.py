import re
from comfy import high

@high(
    name='rule_cve202521598',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_bgp='show configuration protocols bgp | display set',
        show_config_traceoptions='show configuration protocols bgp traceoptions | display set',
        show_log_messages='show log messages | match "Malformed"'
    ),
)
def rule_cve202521598(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-21598 vulnerability in Juniper Networks Junos OS.
    The vulnerability allows an unauthenticated, network-based attacker to send malformed
    BGP packets to a device configured with packet receive trace options enabled to crash rpd.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define the vulnerable versions
    vulnerable_versions = [
        '21.2R3-S8',
        '21.4R3-S7', '21.4R3-S8',
        '22.2R3-S4',
        '22.3R3-S2', '22.3R3-S3',
        '22.4R3', '22.4R3-S1', '22.4R3-S2', '22.4R3-S3', '22.4R3-S4',
        '23.2R2', '23.2R2-S1',
        '23.4R1', '23.4R1-S1', '23.4R1-S2', '23.4R2',
        '24.2R1', '24.2R2'
    ]

    # Check if the current version is vulnerable
    version_match = re.search(r'Junos:\s+(\S+)', version_output)
    extracted_version = version_match.group(1) if version_match else ""
    version_vulnerable = extracted_version in vulnerable_versions

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check if BGP is configured
    bgp_config = commands.show_config_bgp
    has_bgp = 'protocols bgp' in bgp_config and bgp_config.strip()

    if not has_bgp:
        return

    # Check if BGP traceoptions with packet receive is configured
    traceoptions_config = commands.show_config_traceoptions
    has_packet_receive_trace = 'receive' in traceoptions_config or 'packet' in traceoptions_config

    if not has_packet_receive_trace:
        return

    # Check for indicators of compromise in logs
    log_output = commands.show_log_messages
    has_malformed_updates = 'Malformed' in log_output or 'malformed update' in log_output

    # Assert that the device is not vulnerable
    assert not has_packet_receive_trace, (
        f"Device {device.name} is vulnerable to CVE-2025-21598. "
        "The device is running a vulnerable version of Junos OS with BGP configured and "
        "packet receive trace options enabled, which makes it susceptible to rpd crashes "
        "through malformed BGP packets. "
        f"{'Malformed BGP packets have been detected in logs. ' if has_malformed_updates else ''}"
        "Disable BGP traceoptions or upgrade to a patched version. "
        "For more information, see https://supportportal.juniper.net/JSA88318"
    )