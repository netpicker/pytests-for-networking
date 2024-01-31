import pytest
from comfy.compliance import *

@low(
  name = 'rule_3313_set_key_string',
  platform = ['cisco_ios'],
  commands=dict(check_command='sh  run | sec key chain')
)
def rule_3313_set_key_string(configuration, commands, device):
    assert f' key chain' in commands.check_command

# Remediation: 

# References: 1.http://www.cisco.com/en/US/docs/ios-xml/ios/iproute_pi/command/iri-cr-a1.html#GUID-D7A8DC18-2E16-4EA5-8762-8B68B94CC43E
