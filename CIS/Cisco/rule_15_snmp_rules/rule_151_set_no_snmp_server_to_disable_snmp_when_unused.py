import pytest
from comfy.compliance import *

@medium(
  name = 'rule_151_set_no_snmp_server_to_disable_snmp_when_unused',
  platform = ['cisco_ios']
)
def rule_151_set_no_snmp_server_to_disable_snmp_when_unused(configuration,commands,device):
    assert 'hostname#show snmp community' in configuration  

#Remediation: hostname(config)#no snmp -server  

#References: 1. http://www.cisco.com/en/US/docs/ios -xml/ios/snmp/command/nm -snmp -cr-
