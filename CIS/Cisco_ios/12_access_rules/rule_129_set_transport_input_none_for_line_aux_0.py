from comfy.compliance import medium


@medium(
  name='rule_129_set_transport_input_none_for_line_aux_0',
  platform=['cisco_ios', 'cisco_xe'],
  commands=dict(chk_cmd='sh line aux 0 | incl input transport')
)
def rule_129_set_transport_input_none_for_line_aux_0(commands):
    uri = (
        "http://www.cisco.com/en/US/docs/ios/termserv/command/reference/tsv_s1.html#"
        "wp1069219"
    )

    remediation = (f"""
    Remediation: hostname(config)#line aux 0
                 hostname(config-line)#transport input none

    References: {uri}

    """)

    assert 'transport input none' in commands.chk_cmd, remediation
