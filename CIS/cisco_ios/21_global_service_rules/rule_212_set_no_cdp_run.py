from comfy.compliance import medium


@medium(
    name='rule_212_set_no_cdp_run',
    platform=['cisco_ios', 'cisco_xe'],
    commands=dict(chk_cmd='show  cdp')
)
def rule_212_set_no_cdp_run(commands, ref):
    assert 'CDP is not enabled' in commands.chk_cmd, ref
