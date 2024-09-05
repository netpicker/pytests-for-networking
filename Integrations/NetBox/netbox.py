from comfy.compliance import medium


@medium(
    name='rule_netbox',
)
def rule_netbox(configuration, commands, device, netbox):
    # The next lines are used to disable SSL certificate verification
    # https://pynetbox.readthedocs.io/en/stable/advanced.html#ssl-verification
    import requests
    my_cert_ignoring_session = requests.Session()
    my_cert_ignoring_session.verify = False
    netbox.http_session = my_cert_ignoring_session

    devices = netbox.dcim.devices.all()
    device_names = [device.name for device in devices]

    for name in device_names:
        print(name)

    # Get the device by name
    netbox_device = netbox.dcim.devices.get(name=device.name)

    assert netbox_device is not None, f"Device '{device.name}' not found in NetBox."

    # Fetch interfaces for the device
    interfaces = netbox.dcim.interfaces.filter(device_id=netbox_device.id)

    if not interfaces:
        print(f"No interfaces found for device '{device.name}'.")
        return

    # Execute the 'show interfaces' command
    show_interfaces_output = device.cli('show interfaces')

    # Parse the output of 'show interfaces'
    cli_interfaces = {}
    for line in show_interfaces_output.splitlines():
        if ' is ' in line:  # Identify lines that contain interface status
            parts = line.split()
            interface_name = parts[0]  # The interface name is the first part
            if 'up' in line:
                interface_status = 'enabled'
            else:
                interface_status = 'disabled'
            cli_interfaces[interface_name] = interface_status

    # List to accumulate mismatch messages
    mismatches = []

    # Loop through each interface and compare with NetBox
    for interface in interfaces:
        # NetBox interface name
        netbox_interface_name = interface.name
        # NetBox interface status
        netbox_interface_status = 'enabled' if interface.enabled else 'disabled'

        # Get the corresponding interface status from the CLI output
        cli_interface_status = cli_interfaces.get(netbox_interface_name, 'unknown')

        # Check for mismatches
        if netbox_interface_status != cli_interface_status:
            mismatches.append(
                f"Status mismatch for {netbox_interface_name}: "
                f"NetBox = {netbox_interface_status}, CLI = {cli_interface_status}\n"
            )

    # Perform a single assertion at the end
    assert not mismatches, " ".join(mismatches)
