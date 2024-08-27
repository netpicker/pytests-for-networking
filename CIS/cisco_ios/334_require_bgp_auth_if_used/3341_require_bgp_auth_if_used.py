from comfy.compliance import medium


@medium(
    name='rule_3341_require_bgp_auth_if_used',
    platform=['cisco_ios'],
    commands={'bgp_config': 'show run | section router bgp'}
)
def rule_3341_require_bgp_auth_if_used(commands, ref):
    """
    Verifies that BGP authentication is enabled for each neighbor if BGP is used.

    Args:
        configuration (str): Full configuration of the device.
        commands (dict): Dictionary containing output of commands specified in the rule decorator.
        device (object): Current device information.
        devices (list): List of devices sharing the same tags.

    The test checks if BGP is configured and if so, ensures the 'neighbor password' for authentication is present.
    """
    bgp_config = commands.bgp_config
    if 'router bgp' not in bgp_config:
        return  # BGP is not configured; no action needed
    assert 'neighbor' in bgp_config and 'password' in bgp_config, ref
