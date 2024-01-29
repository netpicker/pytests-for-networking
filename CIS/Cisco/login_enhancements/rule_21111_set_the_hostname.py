import pytest
from comfy.compliance import *

@medium(
  name = 'rule_21111_set_the_hostname',
  platform = ['cisco_ios']
)
def rule_21111_set_the_hostname(configuration, commands, device):
    assert '' in configuration

# Remediation: hostname(config)#hostname {<em>router_name</em>}  

# References: 1. http://www.cisco.com/en/US/docs/ios -
