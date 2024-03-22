from comfy.compliance import medium


@medium(
    name='rule_131_set_the_banner_text_for_banner_exec',
    platform=['cisco_ios', 'cisco_xe'],
)
def rule_131_set_the_banner_text_for_banner_exec(configuration, ref):
    assert 'banner exec' in configuration, ref
