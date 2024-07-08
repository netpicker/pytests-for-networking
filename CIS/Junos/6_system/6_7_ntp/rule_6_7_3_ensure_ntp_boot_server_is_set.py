from comfy.compliance import low


@low(
      name='rule_6_7_3_ensure_ntp_boot_server_is_set',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_6_7_3_ensure_ntp_boot_server_is_set(commands, ref):
    assert '' in commands.chk_cmd, ref
