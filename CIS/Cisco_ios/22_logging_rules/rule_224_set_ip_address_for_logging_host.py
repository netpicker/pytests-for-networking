from comfy.compliance import medium


@medium(
    name='rule_224_set_ip_address_for_logging_host',
    platform=['cisco_ios', 'cisco_xe'],
    commands=dict(chk_cmd='sh log | incl logging host')
)
def rule_224_set_ip_address_for_logging_host(commands, ref):
    assert 'logging host' in commands.chk_cmd, ref
