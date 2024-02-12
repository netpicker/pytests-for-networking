from comfy.compliance import low


@low(
  name='rule_112_configure_an_authorized_ip_address_for_ntp_server',
  platform=['cisco_wlc'],
  commands=dict(chk_cmd='show time')
)
def rule_112_configure_an_authorized_ip_address_for_ntp_server(commands):
    uri = (
        "http://www.cisco.com/en/US/docs/wireless/controller/7.0/command/reference/cli7"
        ""
    )

    remediation = (f"""
    Remediation: -

    References: {uri}

    """)

    assert 'show time' in commands.chk_cmd, remediation
