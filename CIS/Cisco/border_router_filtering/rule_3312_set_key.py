import pytest
from comfy.compliance import *

@low(
  name = 'rule_3312_set_key',
  platform = ['cisco_ios']
)
def rule_3312_set_key(configuration, commands, device):
    assert 'hostname#sh run | sec key chain' in configuration

# Remediation: 

# References: 1.http://www.cisco.com/en/US/docs/ios-xml/ios/iproute_pi/command/iri-cr-a1.html#GUID-3F31B2E0-0E4B-4F49-A4A8-8ADA1CA0D73F