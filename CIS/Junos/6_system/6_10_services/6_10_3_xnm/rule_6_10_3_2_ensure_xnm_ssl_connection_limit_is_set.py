from comfy.compliance import low


@low(
      name='rule_6_10_3_2_ensure_xnm_ssl_connection_limit_is_set',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_6_10_3_2_ensure_xnm_ssl_connection_limit_is_set(commands, ref):
    assert '' in commands.chk_cmd, ref
