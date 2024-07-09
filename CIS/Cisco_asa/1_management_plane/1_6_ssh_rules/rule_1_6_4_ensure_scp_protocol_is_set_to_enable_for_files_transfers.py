from comfy.compliance import low


@low(
      name='rule_1_6_4_ensure_scp_protocol_is_set_to_enable_for_files_transfers',
      platform=['cisco_asa'],
      commands=dict(chk_cmd='')
)
def rule_1_6_4_ensure_scp_protocol_is_set_to_enable_for_files_transfers(commands, ref):
    assert '' in commands.chk_cmd, ref
