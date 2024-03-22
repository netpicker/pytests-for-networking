from comfy.compliance import medium


@medium(
    name='rule_313_set_no_interface_tunnel',
    platform=['cisco_ios', 'cisco_xe'],
    commands=dict(chk_cmd='sh ip int brief | incl Tunnel')
)
def rule_313_set_no_interface_tunnel(commands, ref):
    assert 'Tunnel' in commands.chk_cmd, ref
