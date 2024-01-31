import pytest
from comfy.compliance import *

@medium(
  name = 'rule_217_set_service_tcp_keepalives_out',
  platform = ['cisco_ios']
)
def rule_217_set_service_tcp_keepalives_out(configuration, commands, device):
    assert 'service tcp' in configuration,"\n# Remediation: hostname(config)#service tcp-keepalives-out \n# References: 1.http://www.cisco.com/en/US/docs/ios-xml/ios/fundamentals/command/R_through_setup.html#GUID-9321ECDC-6284-4BF6-BA4A-9CEEF5F993E5\n\n
