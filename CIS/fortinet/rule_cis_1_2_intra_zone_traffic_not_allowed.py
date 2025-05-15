from comfy import medium


@medium(
    name='rule_cis_1_2_intra_zone_traffic_not_allowed',
    platform=['fortinet'],
)
def rule_cis_1_2_intra_zone_traffic_not_allowed(configuration, commands, device):
    zone_output = device.cli('show system zone')

    # Split config into zone blocks
    zone_blocks = zone_output.split('edit ')
    
    for block in zone_blocks:
        lines = block.strip().splitlines()
        if not lines:
            continue

        zone_name = lines[0].strip('" ')
        if zone_name.lower() == 'trust':
            continue

        # Check if 'set intrazone deny' exists in this block
        if 'set intrazone deny' not in block:
            raise AssertionError(f"Zone '{zone_name}' does not have 'set intrazone deny'")
