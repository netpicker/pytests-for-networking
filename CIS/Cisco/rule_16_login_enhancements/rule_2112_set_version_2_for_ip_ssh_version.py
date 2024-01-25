import pytest
from comfy.compliance import *

@medium(
  name = 'rule_2112_set_version_2_for_ip_ssh_version',
  platform = ['cisco_ios']
)
def rule_2112_set_version_2_for_ip_ssh_version(configuration,commands,device):
    assert '' in configuration  

#Remediation: hostname(config)#ip ssh version 2  

#References: 1. http://www.cisco.com/en/US/docs/ios -xml/ios/security/d1/sec -cr-i3.html#GUID -
