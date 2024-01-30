import pytest
from comfy.compliance import *

@low(
  name = 'rule_244_set_ip_tftp_source_interface_to_the_loopback_interface',
  platform = ['cisco_ios']
)
def rule_244_set_ip_tftp_source_interface_to_the_loopback_interface(configuration, commands, device):
    assert 'hostname#sh run | incl tftp source-interface' in configuration

# Remediation: hostname(config)#ip tftp source-interface loopback 

# References: 1.http://www.cisco.com/en/US/docs/ios-xml/ios/fundamentals/command/F_through_K.html#GUID-9AA27050-A578-47CD-9F1D-5A8E2B449209
