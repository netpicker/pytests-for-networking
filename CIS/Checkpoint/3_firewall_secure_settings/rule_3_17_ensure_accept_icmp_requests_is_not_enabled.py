from comfy.compliance import low


@low(
      name='rule_3_17_ensure_accept_icmp_requests_is_not_enabled',
      platform=['checkpoint'],
      commands=dict(chk_cmd='')
)
def rule_3_17_ensure_accept_icmp_requests_is_not_enabled(commands, ref):
    assert '' in commands.chk_cmd, ref
