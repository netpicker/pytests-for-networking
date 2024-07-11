from comfy.compliance import medium


@medium(
      name='rule_6_10_1_4_ensure_ssh_rate_limit_is_configured',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_6_10_1_4_ensure_ssh_rate_limit_is_configured(commands, ref):
    assert '' in commands.chk_cmd, ref
