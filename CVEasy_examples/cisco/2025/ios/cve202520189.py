from comfy import high


@high(
    name='rule_cve202520189',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        show_inventory='show inventory',
        show_process_memory='show process memory platform sorted | include RSS|uea_mgr'
    ),
)
def rule_cve202520189(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20189 vulnerability in Cisco ASR 903 
    Aggregation Services Routers with RSP3C running Cisco IOS XE Software.
    The vulnerability is due to improper memory management when processing ARP messages,
    which can be exploited by an unauthenticated, adjacent attacker to cause a denial of 
    service (DoS) condition by exhausting system resources and triggering an RSP reload.
    """
    # Extract the version information from the command output
    version_output = commands.show_version
    inventory_output = commands.show_inventory

    # Check if this is an ASR 903 router
    is_asr903 = 'ASR 903' in version_output or 'ASR903' in version_output or 'ASR 903' in inventory_output or 'ASR903' in inventory_output

    # If not ASR 903, device is not vulnerable
    if not is_asr903:
        return

    # Check if RSP3C is present
    has_rsp3c = 'RSP3C' in inventory_output or 'RSP3C' in version_output

    # If no RSP3C, device is not vulnerable
    if not has_rsp3c:
        return

    # Check if running IOS XE Software
    is_ios_xe = 'IOS XE' in version_output or 'IOS-XE' in version_output

    # If not IOS XE, device is not vulnerable
    if not is_ios_xe:
        return

    # List of vulnerable software versions (based on advisory, specific versions would be listed in Fixed Software section)
    # Since the advisory doesn't specify exact vulnerable versions, we check for IOS XE on ASR 903 with RSP3C
    # In a real scenario, you would check against specific version ranges from the Fixed Software section
    
    # Check for indicators of compromise if available
    memory_output = commands.show_process_memory
    high_memory_usage = False
    
    if memory_output and 'uea_mgr' in memory_output:
        # Parse RSS memory usage for uea_mgr process
        for line in memory_output.split('\n'):
            if 'uea_mgr' in line:
                parts = line.split()
                if len(parts) >= 6:
                    try:
                        rss_memory = int(parts[5])
                        # Normal usage is around 1,048,576 bytes (1 GB)
                        # High usage indicating potential exploitation is around 1,782,580 bytes (1.7 GB)
                        if rss_memory > 1500000:  # 1.5 GB threshold
                            high_memory_usage = True
                    except (ValueError, IndexError):
                        pass

    # Device is vulnerable if it's ASR 903 with RSP3C running IOS XE
    is_vulnerable = is_asr903 and has_rsp3c and is_ios_xe

    # Assert that the device is not vulnerable
    # If the device is vulnerable, the test will fail, indicating the presence of the vulnerability
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20189. "
        "The device is a Cisco ASR 903 Aggregation Services Router with RSP3C running IOS XE Software, "
        "which makes it susceptible to DoS attacks via crafted ARP messages that exhaust system resources. "
        f"{'WARNING: High memory usage detected in uea_mgr process, possible active exploitation. ' if high_memory_usage else ''}"
        "Upgrade to a fixed software version. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asr903-rsp3-arp-dos-WmfzdvJZ"
    )