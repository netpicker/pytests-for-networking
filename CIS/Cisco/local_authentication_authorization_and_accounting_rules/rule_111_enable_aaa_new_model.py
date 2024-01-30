import pytest
from comfy.compliance import *

@medium(
  name = 'rule_111_enable_aaa_new_model',
  platform = ['cisco_ios']
)
def rule_111_enable_aaa_new_model(configuration, commands, device):
    assert 'hostname#show running-config | inc aaa new-model' in configuration

# Remediation: hostname(config)#aaa new-model 

# References: 1.http://www.cisco.com/en/US/docs/ios-xml/ios/security/a1/sec-cr-a2.html#GUID-E05C2E00-C01E-4053-9D12-EC37C7E8EEC5