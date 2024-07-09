from comfy.compliance import medium


@medium(
      name='rule_2_1_6_ensure_dns_server_is_configured',
      platform=['checkpoint'],
      commands=dict(chk_cmd='')
)
def rule_2_1_6_ensure_dns_server_is_configured(commands, ref):
    assert '' in commands.chk_cmd, ref
