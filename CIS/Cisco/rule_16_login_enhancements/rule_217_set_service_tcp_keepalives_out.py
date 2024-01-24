import pytest
from comfy.compliance import *

@medium(
  name = rule_217_set_service_tcp_keepalives_out,
  platform = ['cisco_ios']
)
def rule_217_set_service_tcp_keepalives_out(configuration,commands,device):
    assert 'service tcp' in configuration  

#Remediation: hostname(config)#service tcp -keepalives -out 

#References: 1. http://www.cisco.com/en/US/docs/ios -
