from comfy.compliance import low


@low(
    name='rule_display_set',
    platform=['juniper', 'juniper_junos'],
    commands=dict(display_set='show config | display set')
)
def rule_display_set(configuration, commands, device):
    assert True
