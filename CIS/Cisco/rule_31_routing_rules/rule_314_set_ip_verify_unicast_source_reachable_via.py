import pytest
from comfy.compliance import *

@medium(
  name = 'rule_314_set_ip_verify_unicast_source_reachable_via',
  platform = ['cisco_ios']
)
def rule_314_set_ip_verify_unicast_source_reachable_via(configuration,commands,device):
    assert '' in configuration  

#Remediation: hostname(config)#interface {<em>interface_name</em>}  

#References: 1. http://www.cisco.com/en/U S/docs/ios -xml/ios/security/d1/sec -cr-i3.html#GUID -
