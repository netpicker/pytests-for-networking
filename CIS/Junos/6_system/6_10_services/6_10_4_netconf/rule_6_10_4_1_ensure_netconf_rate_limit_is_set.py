from comfy.compliance import medium


@medium(
      name='rule_6_10_4_1_ensure_netconf_rate_limit_is_set',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_6_10_4_1_ensure_netconf_rate_limit_is_set(commands, ref):
    assert '' in commands.chk_cmd, ref
