from comfy.compliance import medium


@medium(
      name='rule_6_10_1_1_ensure_ssh_service_is_configured_if_remote_cli_is_required',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_6_10_1_1_ensure_ssh_service_is_configured_if_remote_cli_is_required(commands, ref):
    assert '' in commands.chk_cmd, ref
