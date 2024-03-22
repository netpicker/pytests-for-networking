from comfy.compliance import low


@low(
    name='rule_312_set_no_ip_proxy_arp',
    platform=['cisco_ios', 'cisco_xe'],
    commands=dict(chk_cmd='sh inter | incl Interface|proxy-arp')
)
def rule_312_set_no_ip_proxy_arp(commands, ref):
    assert 'proxy-arp' in commands.chk_cmd, ref
