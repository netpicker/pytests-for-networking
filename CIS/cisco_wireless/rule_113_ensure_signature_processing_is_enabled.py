from comfy.compliance import medium


@medium(
    name='rule_113_ensure_signature_processing_is_enabled',
    platform=['cisco_wlc'],
    commands=dict(chk_cmd='show wps summary')
)
def rule_113_ensure_signature_processing_is_enabled(commands, ref):
    assert 'Signature Processing........................... Enabled' in commands.chk_cmd, ref
