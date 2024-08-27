from comfy.compliance import medium


@medium(
    name='rule_134_set_the_banner_text_for_webauth_banner',
    platform=['cisco_ios', 'cisco_xe'],
    commands={'chk_cmd': 'show ip admission auth-proxy-banner http'}
)
def rule_134_set_the_banner_text_for_webauth_banner(commands, ref):
    banner_text = commands.chk_cmd
    assert 'Unauthorized access is prohibited' in banner_text, ref + " - Missing or incorrect banner text."
