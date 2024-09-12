from comfy.compliance import medium
from infrahub_sdk import Config, InfrahubClientSync


@medium(
    name='rule_infrahub',
)
def rule_infrahub(configuration, commands, device):
    # https://github.com/opsmill/infrahub
    # https://docs.infrahub.app/python-sdk/

    endpoint = "http://hostname:80"
    api_token = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    branch = "main"

    infrahub = InfrahubClientSync(address=endpoint, config=Config(api_token=api_token))

    # devices = infrahub.all(kind='InfraDevice', branch=branch)
    # device_names = [device.name.value for device in devices]

    # for name in device_names:
    #     print(name)

    infrahub_device = infrahub.get(kind='InfraDevice', branch=branch, name__value=device.name, include=["interfaces"])

    assert infrahub_device is not None, f"Device '{device.name}' not found in Infrahub."

    infrahub_device.interfaces.fetch()

    interfaces = infrahub_device.interfaces.peers

    # for interface in interfaces:
    #     print(interface.peer.enabled.value, interface.display_label, interface.typename, interface.peer.name.value)

    if not interfaces:
        print(f"No interfaces found for device '{device.name}'.")
        return

    show_interfaces_output = device.cli('show interfaces')

    cli_interfaces = {}
    for line in show_interfaces_output.splitlines():
        if ' is ' in line:
            parts = line.split()
            interface_name = parts[0]
            if 'up' in line:
                interface_status = 'enabled'
            else:
                interface_status = 'disabled'
            cli_interfaces[interface_name] = interface_status

    mismatches = []

    for interface in interfaces:
        infrahub_interface_name = interface.peer.name.value
        infrahub_interface_status = 'enabled' if interface.peer.enabled.value else 'disabled'

        cli_interface_status = cli_interfaces.get(infrahub_interface_name, 'unknown')

        if infrahub_interface_status != cli_interface_status:
            mismatches.append(
                f"Status mismatch for {infrahub_interface_name}: "
                f"Infrahub = {infrahub_interface_status}, CLI = {cli_interface_status}\n"
            )

    assert not mismatches, " ".join(mismatches)
