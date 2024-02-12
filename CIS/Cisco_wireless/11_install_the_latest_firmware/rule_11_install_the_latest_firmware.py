from comfy.compliance import medium


@medium(
  name='rule_11_install_the_latest_firmware',
  platform=['cisco_wlc'],
  commands=dict(chk_cmd='show sysinfo')
)
def rule_11_install_the_latest_firmware(commands):
    uri = (
        "http://www.cisco.com/en/US/docs/wireless/controller/7.0/command/reference/cli7"
        ""
    )

    remediation = (f"""
    Remediation: -

    References: {uri}

    """)

    assert 'show sysinfo' in commands.chk_cmd, remediation
