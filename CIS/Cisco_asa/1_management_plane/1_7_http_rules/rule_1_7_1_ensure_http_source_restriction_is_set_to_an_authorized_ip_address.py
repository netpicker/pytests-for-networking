from comfy.compliance import low


@low(
      name='rule_1_7_1_ensure_http_source_restriction_is_set_to_an_authorized_ip_address',
      platform=['cisco_asa'],
      commands=dict(chk_cmd='')
)
def rule_1_7_1_ensure_http_source_restriction_is_set_to_an_authorized_ip_address(commands, ref):
    assert '' in commands.chk_cmd, ref
