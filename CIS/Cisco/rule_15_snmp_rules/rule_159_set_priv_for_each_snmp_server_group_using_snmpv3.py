import pytest
from comfy.compliance import *

@low(
  name = 'rule_159_set_priv_for_each_snmp_server_group_using_snmpv3',
  platform = ['cisco_ios']
)
def rule_159_set_priv_for_each_snmp_server_group_using_snmpv3(configuration,commands,device):
    assert 'hostname#show snmp group' in configuration  

#Remediation: hostname(config)#snmp -server group {<em>group_name</em>} v3 priv  

#References: 1. http://www.cisco.com/en/US/docs/ios -xml/ios/snmp/command/nm -snmp -cr-
