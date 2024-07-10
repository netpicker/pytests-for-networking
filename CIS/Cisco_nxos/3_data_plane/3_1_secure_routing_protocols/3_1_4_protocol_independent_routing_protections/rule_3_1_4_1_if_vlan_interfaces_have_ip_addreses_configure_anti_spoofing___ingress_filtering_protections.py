from comfy.compliance import medium


@medium(
      name='rule_3_1_4_1_if_vlan_interfaces_have_ip_addreses_configure_anti_spoofing___ingress_filtering_protections',
      platform=['cisco_nxos'],
      commands=dict(chk_cmd='')
)
def rule_3_1_4_1_if_vlan_interfaces_have_ip_addreses_configure_anti_spoofing___ingress_filtering_protections(commands, ref):
    assert '' in commands.chk_cmd, ref
