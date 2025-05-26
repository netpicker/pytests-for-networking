from comy import medium

@medium(
    name='rule_slurpit',
)
async def rule_slurpit(slurpit):
    # Set up these environment variables for the x-api in docker-compose.override.yml first:
    # SLURPIT_APIKEY: slurpit_apikey_here
    # SLURPIT_URL: "https://slurpit-endpoint/"
    # Slurp'it SDK documentation: https://gitlab.com/slurpit.io/slurpit_sdk/

    devices = await slurpit.device.get_devices()

    for d in devices:
        print(d.hostname)

    assert any(d.hostname == 'sandbox-iosxr-1.cisco.com' for d in devices)
