from comfy.compliance import medium


@medium(
      name='rule_6_12_3_ensure_local_logging_is_set_for_firewall_events',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_6_12_3_ensure_local_logging_is_set_for_firewall_events(commands, ref):
    assert '' in commands.chk_cmd, ref
