from comfy.compliance import low


@low(
      name='rule_6_6_7_ensure_remote_login_class_for_authorization_through_external_aaa',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_6_6_7_ensure_remote_login_class_for_authorization_through_external_aaa(commands, ref):
    assert '' in commands.chk_cmd, ref
