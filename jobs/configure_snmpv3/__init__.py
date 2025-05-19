import logging
from comfy.automate import job

@job(platform='cisco*')
def configure_snmpv3(
    device,
    username: str,
    auth_password: str,
    priv_password: str,
    auth_protocol: str = "sha",
    priv_protocol: str = "aes",
    view: str = "v1default",
    group: str = "snmpv3group"
):
    """
    Configures SNMPv3 on a Cisco IOS / NX-OS device with authentication and privacy.

    Args:
        device: The Netpicker device object.
        username (str): SNMPv3 username.
        auth_password (str): Authentication password.
        priv_password (str): Privacy password.
        auth_protocol (str): Authentication protocol ('md5' or 'sha').
        priv_protocol (str): Privacy protocol ('aes' or 'des').
        view (str): SNMP view to apply.
        group (str): SNMP group name.
    """
    log_prefix = f"Device {device.ipaddress}:"
    logging.info(f"{log_prefix} Starting SNMPv3 configuration job...")

    config_commands = [
        f"snmp-server group {group} v3 priv read {view}",
        f"snmp-server user {username} {group} v3 auth {auth_protocol} {auth_password} priv {priv_protocol} {priv_password}"
    ]

    if device.platform == "cisco_nxos":
        config_commands.append("copy running-config startup-config")
    else:
        config_commands.append("write memory")

    try:
        result = device.cli.send_config_set(config_commands)
        logging.info(f"{log_prefix} SNMPv3 configured successfully.")
        logging.debug(f"{log_prefix} Output: {result}")
        return result
    except Exception as e:
        logging.error(f"{log_prefix} Error configuring SNMPv3: {e}")
        raise
