import logging
from comfy.automate import job

@job(platform='cisco*')
def configure_logging_server(device, logging_host: str, severity: str = "informational", vrf: str = None):
    """
    Configures a remote syslog server on a Cisco IOS / NX-OS device.

    Args:
        device: The Netpicker device object.
        logging_host (str): The IP or hostname of the syslog server.
        severity (str): The logging severity level (default: informational).
        vrf (str): Optional VRF to use for logging (for NX-OS).
    """
    log_prefix = f"Device {device.ipaddress}:"
    logging.info(f"{log_prefix} Starting logging server configuration job...")

    config_commands = []

    if device.platform == "cisco_nxos" and vrf:
        config_commands.append(f"logging server {logging_host} use-vrf {vrf} severity {severity}")
    else:
        config_commands.append(f"logging host {logging_host} {severity}")

    # Save the config
    if device.platform == 'cisco_nxos':
        config_commands.append("copy running-config startup-config")
    else:
        config_commands.append("write memory")

    try:
        result = device.cli.send_config_set(config_commands)
        logging.info(f"{log_prefix} Logging server configured successfully.")
        logging.debug(f"{log_prefix} Output: {result}")
        return result
    except Exception as e:
        logging.error(f"{log_prefix} Error configuring logging server: {e}")
        raise
