from comfy.compliance import medium


@medium(
    name='rule_133_set_the_banner_text_for_banner_motd',
    platform=['cisco_ios', 'cisco_xe'],
)
def rule_133_set_the_banner_text_for_banner_motd(configuration, ref):
    assert 'banner motd' in configuration, ref
