from comfy.compliance import low


@low(
      name='rule_1_1_5_local_users,_groups_and_tasks',
      platform=['cisco_xr'],
      commands=dict(chk_cmd='')
)
def rule_1_1_5_local_users,_groups_and_tasks(commands, ref):
    assert '' in commands.chk_cmd, ref
