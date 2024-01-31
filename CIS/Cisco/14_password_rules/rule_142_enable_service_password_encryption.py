import pytest
from comfy.compliance import *

@medium(
  name = 'rule_142_enable_service_password_encryption',
  platform = ['cisco_ios']
)
def rule_142_enable_service_password_encryption(configuration, commands, device):
    assert 'service password-encryption' in configuration

# Remediation: hostname(config)#service password-encryption  

# References: 1.http://www.cisco.com/en/US/docs/ios-xml/ios/security/s1/sec-cr-s1.html#GUID-CC0E305A-604E-4A74-8A1A-975556CE5871
