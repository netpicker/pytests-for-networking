import pytest
from comfy.compliance import *

@low(
  name = 'rule_2312_set_ntp_authentication_key',
  platform = ['cisco_ios']
)
def rule_2312_set_ntp_authentication_key(configuration, commands, device):
    assert 'ntp authentication-key' in configuration,"
# Remediation: hostname(config)#ntp authentication-key {ntp_key_id} md5 {ntp_key_hash}  
# References: 1.http://www.cisco.com/en/US/docs/ios-xml/ios/bsm/command/bsm-cr-n1.html#GUID-0435BFD1-D7D7-41D4-97AC-7731C11226BC


