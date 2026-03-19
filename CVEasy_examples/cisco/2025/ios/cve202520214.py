from comfy import high


@high(
    name='rule_cve202520214',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        show_nacm_config='show running-config | section netconf-yang|restconf|gnmi',
        show_aaa_config='show running-config | include aaa|privilege'
    ),
)
def rule_cve202520214(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20214 vulnerability in Cisco IOS XE Software.
    The vulnerability exists in the Network Configuration Access Control Module (NACM) and allows
    an authenticated, remote attacker to obtain unauthorized read access to configuration or
    operational data through NETCONF, RESTCONF, or gNMI protocols when NACM is configured to
    provide restricted read access for lower-privileged users.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if this is IOS XE (vulnerability only affects IOS XE, not IOS)
    if 'IOS XE' not in version_output:
        return

    # List of vulnerable software versions (based on advisory - specific versions not listed, so checking for IOS XE presence)
    # The advisory states vulnerable releases exist but doesn't specify exact versions
    # In practice, you would need to check against the Cisco Software Checker
    # For this rule, we'll assume IOS XE versions are potentially vulnerable and check configuration
    
    # Check for model-driven programmability protocols configuration
    nacm_config_output = commands.show_nacm_config
    aaa_config_output = commands.show_aaa_config

    # Check if NETCONF, RESTCONF, or gNMI is enabled
    netconf_enabled = 'netconf-yang' in nacm_config_output
    restconf_enabled = 'restconf' in nacm_config_output
    gnmi_enabled = 'gnmi' in nacm_config_output

    model_driven_enabled = netconf_enabled or restconf_enabled or gnmi_enabled

    # Check if NACM is configured (indicated by presence of model-driven protocols with AAA)
    nacm_configured = model_driven_enabled and ('aaa' in aaa_config_output or 'authorization' in nacm_config_output)

    # Check if there are users with privilege level lower than 15
    lower_privilege_users = False
    if 'privilege' in aaa_config_output:
        # Check for privilege levels 0-14
        for level in range(0, 15):
            if f'privilege {level}' in aaa_config_output or f'privilege level {level}' in aaa_config_output:
                lower_privilege_users = True
                break

    # Device is vulnerable if:
    # 1. Running IOS XE
    # 2. Has model-driven programmability protocols enabled (NETCONF/RESTCONF/gNMI)
    # 3. Has NACM configured with restricted read access
    # 4. Has users with privilege level lower than 15
    is_vulnerable = model_driven_enabled and nacm_configured and lower_privilege_users

    # Assert that the device is not vulnerable
    # If the device is vulnerable, the test will fail, indicating the presence of the vulnerability
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20214. "
        "The device is running Cisco IOS XE Software with model-driven programmability protocols "
        "(NETCONF, RESTCONF, or gNMI) enabled, has NACM configured to provide restricted read access, "
        "and has users with privilege levels lower than 15. This allows authenticated attackers to bypass "
        "NACM authorization and obtain unauthorized read access to configuration or operational data. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-netconf-nacm-bypass-TGZV9pmQ"
    )