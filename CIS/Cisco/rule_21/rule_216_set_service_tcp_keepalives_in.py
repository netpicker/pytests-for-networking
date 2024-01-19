import pytest
from comfy.compliance import *

@medium(
  name = rule_216_set_service_tcp_keepalives_in,
  platform = ['cisco_ios']
)
def rule_216_set_service_tcp_keepalives_in(configuration,commands,device):
    assert 'service tcp' in configuration  

#Remediation: hostname(config)#serv ice tcp-keepalives -in 

#References: 1. http://www.cisco.com/en/US/docs/ios -
