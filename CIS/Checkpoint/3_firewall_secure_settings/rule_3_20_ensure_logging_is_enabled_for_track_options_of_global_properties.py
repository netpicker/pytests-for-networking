from comfy.compliance import medium


@medium(
      name='rule_3_20_ensure_logging_is_enabled_for_track_options_of_global_properties',
      platform=['checkpoint'],
      commands=dict(chk_cmd='')
)
def rule_3_20_ensure_logging_is_enabled_for_track_options_of_global_properties(commands, ref):
    assert '' in commands.chk_cmd, ref
