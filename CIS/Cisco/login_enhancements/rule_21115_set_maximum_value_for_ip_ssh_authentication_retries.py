import pytest
from comfy.compliance import *

@medium(
  name = 'rule_21115_set_maximum_value_for_ip_ssh_authentication_retries',
  platform = ['cisco_ios']
)
def rule_21115_set_maximum_value_for_ip_ssh_authentication_retries(configuration, commands, device):
    assert '' in configuration

# Remediation: hostname(config)#ip ssh authentication -retries [<em>3</em>]  

# References: 1. http://www.cisco.com/en/US/docs/ios -xml/ios/security/d1/sec -cr-i3.html#GUID -
