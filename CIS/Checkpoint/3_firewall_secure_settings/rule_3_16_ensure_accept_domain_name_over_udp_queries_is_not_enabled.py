from comfy.compliance import low


@low(
      name='rule_3_16_ensure_accept_domain_name_over_udp_queries_is_not_enabled',
      platform=['checkpoint'],
      commands=dict(chk_cmd='')
)
def rule_3_16_ensure_accept_domain_name_over_udp_queries_is_not_enabled(commands, ref):
    assert '' in commands.chk_cmd, ref
