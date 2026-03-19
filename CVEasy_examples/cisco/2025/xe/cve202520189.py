from comfy import high

@high(
    name='rule_cve202520189',
    platform=['cisco_ios-xe'],
    commands=dict(
        show_version='show version',
        show_platform='show platform',
        show_process_memory='show process memory platform sorted | include RSS|uea_mgr'
    ),
)
def rule_cve202520189(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20189 vulnerability in Cisco IOS XE Software
    for Cisco ASR 903 Aggregation Services Routers with Route Switch Processor 3 (RSP3C).
    
    The vulnerability is due to improper memory management when processing ARP messages,
    which could allow an unauthenticated, adjacent attacker to trigger a denial of service
    condition by exhausting system resources.
    """
    # Extract the version and platform information from the command output
    version_output = commands.show_version
    platform_output = commands.show_platform
    
    # Check if the device is a Cisco ASR 903 with RSP3C
    is_asr903 = 'ASR 903' in platform_output or 'ASR903' in platform_output or 'ASR 903' in version_output or 'ASR903' in version_output
    has_rsp3c = 'RSP3C' in platform_output or 'RSP3' in platform_output
    
    # If not ASR 903 with RSP3C, device is not vulnerable
    if not (is_asr903 and has_rsp3c):
        return
    
    # List of vulnerable software versions
    # Based on the advisory, all versions are vulnerable until fixed releases
    vulnerable_versions = [
        # 16.x versions
        '16.3.1', '16.3.2', '16.3.3', '16.3.1a', '16.3.4', '16.3.5', '16.3.5b', '16.3.6', '16.3.7', '16.3.8',
        '16.3.9', '16.3.10', '16.3.11',
        '16.4.1', '16.4.2', '16.4.3',
        '16.5.1', '16.5.1a', '16.5.1b', '16.5.2', '16.5.3',
        '16.6.1', '16.6.2', '16.6.3', '16.6.4', '16.6.5', '16.6.4a', '16.6.5a', '16.6.6', '16.6.7', '16.6.8',
        '16.6.9', '16.6.10',
        '16.7.1', '16.7.2', '16.7.3',
        '16.8.1', '16.8.1a', '16.8.1b', '16.8.1s', '16.8.1c', '16.8.2', '16.8.3',
        '16.9.1', '16.9.2', '16.9.1a', '16.9.1b', '16.9.1s', '16.9.3', '16.9.4', '16.9.3a', '16.9.5', '16.9.5f',
        '16.9.6', '16.9.7', '16.9.8',
        '16.10.1', '16.10.1a', '16.10.1b', '16.10.1s', '16.10.1e', '16.10.2', '16.10.3',
        '16.11.1', '16.11.1a', '16.11.1b', '16.11.2', '16.11.1s',
        '16.12.1', '16.12.1s', '16.12.1a', '16.12.1c', '16.12.2', '16.12.2a', '16.12.3', '16.12.8', '16.12.2s',
        '16.12.1t', '16.12.4', '16.12.3s', '16.12.3a', '16.12.4a', '16.12.5', '16.12.6', '16.12.5a', '16.12.5b',
        '16.12.6a', '16.12.7', '16.12.9', '16.12.10', '16.12.10a', '16.12.11',
        # 17.x versions
        '17.1.1', '17.1.1a', '17.1.1s', '17.1.1t', '17.1.3',
        '17.2.1', '17.2.1r', '17.2.1a', '17.2.1v', '17.2.2', '17.2.3',
        '17.3.1', '17.3.2', '17.3.3', '17.3.1a', '17.3.2a', '17.3.4', '17.3.5', '17.3.4a', '17.3.6', '17.3.4b',
        '17.3.4c', '17.3.5a', '17.3.5b', '17.3.7', '17.3.8', '17.3.8a',
        '17.4.1', '17.4.2', '17.4.1a', '17.4.1b', '17.4.2a',
        '17.5.1', '17.5.1a',
        '17.6.1', '17.6.2', '17.6.1a', '17.6.3', '17.6.3a', '17.6.4', '17.6.5', '17.6.6', '17.6.6a', '17.6.5a',
        '17.7.1', '17.7.1a', '17.7.1b', '17.7.2',
        '17.8.1', '17.8.1a',
        '17.9.1', '17.9.2', '17.9.1a', '17.9.3', '17.9.2a', '17.9.3a', '17.9.4', '17.9.4a',
        '17.10.1', '17.10.1a', '17.10.1b',
        '17.11.1', '17.11.1a', '17.11.99SW',
        '17.12.1', '17.12.1a', '17.12.2', '17.12.2a'
    ]
    
    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)
    
    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return
    
    # Check for indicators of compromise - high RSS memory usage of uea_mgr process
    process_memory_output = commands.show_process_memory
    
    # Parse RSS memory usage for uea_mgr process
    if 'uea_mgr' in process_memory_output:
        lines = process_memory_output.split('\n')
        for line in lines:
            if 'uea_mgr' in line:
                parts = line.split()
                # RSS is typically the 6th column in the output
                if len(parts) >= 6:
                    try:
                        rss_memory = int(parts[5])
                        # Normal RSS memory usage is around 1,048,576 bytes (1 GB)
                        # Vulnerable state is when it goes well beyond this value
                        if rss_memory > 1300000:  # 1.3 GB threshold
                            assert False, (
                                f"Device {device.name} is vulnerable to CVE-2025-20189. "
                                f"The device is a Cisco ASR 903 with RSP3C running a vulnerable version "
                                f"AND shows signs of exploitation with elevated uea_mgr RSS memory usage ({rss_memory} bytes). "
                                "This vulnerability is due to improper memory management when processing ARP messages. "
                                "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asr903-rsp3-arp-dos-WmfzdvJZ"
                            )
                    except (ValueError, IndexError):
                        pass
    
    # Device is vulnerable but not currently showing signs of active exploitation
    assert False, (
        f"Device {device.name} is vulnerable to CVE-2025-20189. "
        f"The device is a Cisco ASR 903 with RSP3C running a vulnerable version of IOS XE Software. "
        "This vulnerability could allow an unauthenticated, adjacent attacker to trigger a DoS condition "
        "by sending crafted ARP messages at a high rate. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asr903-rsp3-arp-dos-WmfzdvJZ"
    )