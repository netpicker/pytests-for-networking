from comfy.compliance import low


@low(
      name='rule_6_10_3_3_ensure_xnm_ssl_rate_limit_is_set',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_6_10_3_3_ensure_xnm_ssl_rate_limit_is_set(commands, ref):
    assert '' in commands.chk_cmd, ref
