from comfy.compliance import low


@low(
  name='rule_162_autosecure',
  platform=['cisco_ios', 'cisco_xe'],
  commands=dict(chk_cmd='show auto secure config')
)
def rule_162_autosecure(commands, ref):
    assert 'auto secure ' in commands.chk_cmd, ref
