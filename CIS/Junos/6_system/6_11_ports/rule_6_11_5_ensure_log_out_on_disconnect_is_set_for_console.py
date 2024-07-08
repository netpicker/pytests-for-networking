from comfy.compliance import medium


@medium(
      name='rule_6_11_5_ensure_log_out_on_disconnect_is_set_for_console',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_6_11_5_ensure_log_out_on_disconnect_is_set_for_console(commands, ref):
    assert '' in commands.chk_cmd, ref
