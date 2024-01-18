
import pytest
from comfy.compliance import Source, low

@low(
  name = rule_2312_set_ntp_authentication_key,
  platform = ['cisco_ios']
)
def rule_2312_set_ntp_authentication_key(configuration,commands,device):
    assert 'ude ntp authentication -key' in configuration  

#Remediation: hostname(config)#ntp authentication -key {ntp_key_id} md5 {ntp_key_hash}  

#References: 1. http://www.cisco.com/en/US/docs/ios -xml/ios/bsm/command/bsm -cr-
