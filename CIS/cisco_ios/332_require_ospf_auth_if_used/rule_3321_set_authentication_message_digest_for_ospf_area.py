from comfy import medium
import re


@medium(
    name='rule_3321_set_authentication_message_digest_for_ospf_area',
    platform=['cisco_ios', 'cisco_xe'],
)
def rule_3321_set_authentication_message_digest_for_ospf_area(configuration, device, ref):
    config = str(configuration)
    interfaces = re.split(r'\ninterface ', config)
    failed_interfaces = []

    for section in interfaces[1:]:  # skip any preamble before the first interface
        lines = section.strip().splitlines()
        if not lines:
            continue

        interface_name = lines[0].strip()

        # exclude loopbacks
        if interface_name.lstrip().lower().startswith('loopback'):
            continue

        # Check if this interface has OSPF enabled
        has_ospf = any(re.search(r'\bip ospf\b', line) for line in lines)

        if has_ospf:
            # Check for authentication
            has_auth = any(
                re.search(r'\bip ospf authentication message-digest\b', line)
                for line in lines
            )
            if not has_auth:
                failed_interfaces.append(interface_name)

    combined_message = {
        "message": (
            "OSPF authentication (message-digest) missing on interfaces: "
            + ", ".join(failed_interfaces)
        ),
        "ref": ref,
    }
    assert (
        len(failed_interfaces) == 0
    ), combined_message
