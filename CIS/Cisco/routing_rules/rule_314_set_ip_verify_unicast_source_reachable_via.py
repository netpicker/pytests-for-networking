import pytest
from comfy.compliance import *

@medium(
  name = 'rule_314_set_ip_verify_unicast_source_reachable_via',
  platform = ['cisco_ios']
)
def rule_314_set_ip_verify_unicast_source_reachable_via(configuration, commands, device):
    assert 'hostname#sh ip int {<em>interface</em>} | incl verify source' in configuration

# Remediation: hostname(config)#interface {<em>interface_name</em>}  

# References: 2. https://community.cisco.com/t5/routing/ip-verify-unicast-source-reachable-via-
