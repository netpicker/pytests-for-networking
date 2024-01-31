import pytest
from comfy.compliance import *

@low(
  name = 'rule_3311_set_key_chain',
  platform = ['cisco_ios'],
  commands=dict(check_command='sh run | sec key chain')
)
def rule_3311_set_key_chain(configuration, commands, device):
    assert f' key chain' in commands.check_command,"
# Remediation: hostname(config)#key chain {<em>key-chain_name</em>}  
# References: 1.http://www.cisco.com/en/US/docs/ios-xml/ios/iproute_pi/command/iri-cr-a1.html#GUID-A62E89F5-0B8B-4CF0-B4EB-08F2762D88BB


