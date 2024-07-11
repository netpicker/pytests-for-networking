from comfy.compliance import medium


@medium(
      name='rule_6_1_1_ensure_accounting_destination_is_configured',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='show configuration system accounting destination | match "server" | count')
)
def rule_6_1_1_ensure_accounting_destination_is_configured(commands, ref):
    assert int(commands.chk_cmd.strip()) >= 1, ref
