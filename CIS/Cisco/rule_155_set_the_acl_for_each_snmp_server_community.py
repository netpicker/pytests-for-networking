
import pytest
from comfy.compliance import Source, low

@low(
  name = rule_155_set_the_acl_for_each_snmp_server_community,
  platform = ['cisco_ios']
)
def rule_155_set_the_acl_for_each_snmp_server_community(configuration,commands,device):
    assert 'snmp -server community' in configuration  

#Remediation: hostname(config)#snmp -server community <<em>community_string</em>> ro 

#References: 1. http://www.cisco.com/en/US/docs/ios -xml/ios/snmp/com mand/nm -snmp -cr-
