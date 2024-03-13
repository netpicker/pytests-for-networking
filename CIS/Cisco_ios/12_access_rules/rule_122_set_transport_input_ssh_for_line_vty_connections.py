from comfy.compliance import medium


@medium(
  name='rule_122_set_transport_input_ssh_for_line_vty_connections',
  platform=['cisco_ios', 'cisco_xe'],
  commands=dict(chk_cmd='show running-config | sec vty')
)
def rule_122_set_transport_input_ssh_for_line_vty_connections(commands):
    uri = (
        "http://www.cisco.com/en/US/docs/ios/termserv/command/reference/tsv_s1.html#"
        "wp1069219"
    )

    remediation = (f"""
    Remediation: hostname(config)#line vty <line-number> <ending-line-number>
                 hostname(config-line)#transport input ssh

    References: {uri}

    """)

    assert ' transport input ssh' in commands.chk_cmd, remediation
