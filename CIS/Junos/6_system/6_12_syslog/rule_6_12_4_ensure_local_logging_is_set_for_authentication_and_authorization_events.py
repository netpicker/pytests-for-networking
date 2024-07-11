from comfy.compliance import medium


@medium(
      name='rule_6_12_4_ensure_local_logging_is_set_for_authentication_and_authorization_events',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_6_12_4_ensure_local_logging_is_set_for_authentication_and_authorization_events(commands, ref):
    assert '' in commands.chk_cmd, ref
