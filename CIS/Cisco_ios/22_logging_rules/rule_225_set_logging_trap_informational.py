from comfy.compliance import medium


@medium(
    name='rule_225_set_logging_trap_informational',
    platform=['cisco_ios', 'cisco_xe'],
    commands=dict(chk_cmd='sh log | incl logging trap')
)
def rule_225_set_logging_trap_informational(commands, ref):
    assert 'logging trap informational' in commands.chk_cmd, ref
