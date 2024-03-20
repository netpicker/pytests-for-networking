from comfy.compliance import medium


uri = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9500/software/releas"
    ""
)

remediation = (f"""
    Remediation: hostname(config)#ip  admission auth-proxy-banner http {{banner-text | filepath}}

    References: {uri}

    """)


@medium(
  name='rule_134_set_the_banner_text_for_webauth_banner',
  platform=['cisco_ios', 'cisco_xe'],
  commands=dict(chk_cmd='show ip admission auth-proxy-banner http')
)
def rule_134_set_the_banner_text_for_webauth_banner(commands):
    assert 'hostname#show ip admission auth-proxy-banner http' in commands.chk_cmd, remediation
