import pytest
from comfy.compliance import *

@low(
  name = 'rule_321_set_ip_access_list_extended_to_forbid_privat_e_source',
  platform = ['cisco_ios']
)
def rule_321_set_ip_access_list_extended_to_forbid_privat_e_source(configuration,commands,device):
    assert '' in configuration  

#Remediation: hostname(config)#interface <external_<em>interface</em>>  

#References: 1. http://www.cisco.com/en/US/docs/ios -xml/ios/security/d1/sec -cr-i1.html#GUID -
