import pytest
from comfy.compliance import *

@medium(
  name = 'rule_21113_set_modulus_to_greater_than_or_equal_to_2048_for_crypto',
  platform = ['cisco_ios']
)
def rule_21113_set_modulus_to_greater_than_or_equal_to_2048_for_crypto(configuration, commands, device):
    assert '' in configuration

# Remediation: hostname(config)#crypto key generate rsa general-keys modulus <em>2048</em>  

# References: 1. http://www.cisco.com/en/US/docs/ios-xml/ios/security/a1/sec-cr-c4.html#GUID -
