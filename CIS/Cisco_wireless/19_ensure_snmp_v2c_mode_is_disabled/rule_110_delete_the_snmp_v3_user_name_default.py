from comfy.compliance import medium


@medium(
  name='rule_110_delete_the_snmp_v3_user_name_default',
  platform=['cisco_wlc'],
  commands=dict(chk_cmd='show snmpv3user')
)
def rule_110_delete_the_snmp_v3_user_name_default(commands):
    uri = (
        "http://www.cisco.com/en/US/docs/wireless/controller/7.0/command/reference/cli7"
        ""
    )

    remediation = (f"""
    Remediation: -

    References: {uri}

    """)

    assert 'show snmpv3user' in commands.chk_cmd, remediation
