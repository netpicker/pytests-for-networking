from comfy.compliance import low


@low(
      name='rule_3_15_ensure_accept_domain_name_over_tcp_zone_transfer_is_not_enabled',
      platform=['checkpoint'],
      commands=dict(chk_cmd='')
)
def rule_3_15_ensure_accept_domain_name_over_tcp_zone_transfer_is_not_enabled(commands, ref):
    assert '' in commands.chk_cmd, ref
