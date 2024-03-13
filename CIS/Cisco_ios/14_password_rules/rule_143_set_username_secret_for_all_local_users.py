from comfy.compliance import medium


@medium(
  name='rule_143_set_username_secret_for_all_local_users',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_143_set_username_secret_for_all_local_users(configuration):
    uri = (
        "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9600/software/releas"
        "e/16-12/configuration_guide/sec/b_1612_sec_9600_cg/controlling_switch_access_with_passwords_and_privilege_levels.html"
    )

    remediation = (f"""
    Remediation: hostname(config)#username <LOCAL_USERNAME> secret <LOCAL_PASSWORD>

    References: {uri}

    """)

    for line in configuration:
        if 'username' in line:
            if 'secret' in line:
                return
            else:
                assert False, remediation
            
