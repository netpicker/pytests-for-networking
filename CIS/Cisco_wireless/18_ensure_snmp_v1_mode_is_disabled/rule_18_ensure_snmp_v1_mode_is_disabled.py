from comfy.compliance import medium


@medium(
  name='rule_18_ensure_snmp_v1_mode_is_disabled',
  platform=['cisco_wlc'],
  commands=dict(chk_cmd='show snmpversion')
)
def rule_18_ensure_snmp_v1_mode_is_disabled(commands):
    uri = (
        "http://www.cisco.com/en/US/docs/wireless/controller/7.0/command/reference/cli7"
        ""
    )

    remediation = (f"""
    Remediation: -

    References: {uri}

    """)

    assert 'show snmpversion' in commands.chk_cmd, remediation
