from comfy.compliance import medium


@medium(
      name='rule_2_5_4_ensure_radius_or_tacacs__server_is_configured',
      platform=['checkpoint'],
      commands=dict(chk_cmd='')
)
def rule_2_5_4_ensure_radius_or_tacacs__server_is_configured(commands, ref):
    assert '' in commands.chk_cmd, ref
