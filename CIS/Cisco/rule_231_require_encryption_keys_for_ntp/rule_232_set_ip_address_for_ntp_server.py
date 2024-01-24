import pytest
from comfy.compliance import *

@medium(
  name = rule_232_set_ip_address_for_ntp_server,
  platform = ['cisco_ios']
)
def rule_232_set_ip_address_for_ntp_server(configuration,commands,device):
    assert '' in configuration  

#Remediation: hostname(config)#ntp server {ntp server vrf [vrf name] ip address}  

#References: 1. http://www.cisco.com/en/US/docs/ios -xml/ios/bsm/command/bsm -cr-
