from comfy.compliance import medium


@medium(
  name='rule_111_configure_an_authorized_ip_address_for_logging_syslog',
  platform=['cisco_wlc'],
  commands=dict(chk_cmd='show logging')
)
def rule_111_configure_an_authorized_ip_address_for_logging_syslog(commands):
    uri = (
        "http://www.cisco.com/en/US/docs/wireless/controller/7.0/command/reference/cli7"
        ""
    )

    remediation = (f"""
    Remediation: -

    References: {uri}

    """)

    assert 'show logging' in commands.chk_cmd, remediation
