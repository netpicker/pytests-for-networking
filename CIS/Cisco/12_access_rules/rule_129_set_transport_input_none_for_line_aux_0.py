from comfy.compliance import medium


@medium(
  name='rule_129_set_transport_input_none_for_line_aux_0',
  platform=['cisco_ios', 'cisco_xe'],
  commands=dict(chk_cmd='sh line aux 0 | incl input transports')
)
def rule_129_set_transport_input_none_for_line_aux_0(commands):
    uri = (
        "http://www.cisco.com/en/US/docs/ios/termserv/command/reference/tsv_shtml#"
        ""
    )

    remediation = (f"""
    Remediation: hostname(config-line)#transport input none

    References: {uri}

    """)

    assert 'input transports' in commands.chk_cmd, remediation
