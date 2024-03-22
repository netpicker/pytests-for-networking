from comfy.compliance import medium


@medium(
    name='rule_132_set_the_banner_text_for_banner_login',
    platform=['cisco_ios', 'cisco_xe'],
)
def rule_132_set_the_banner_text_for_banner_login(configuration, ref):
    assert 'banner login' in configuration, ref
