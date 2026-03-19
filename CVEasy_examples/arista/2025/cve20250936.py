from comfy import high
import re


@high(
    name="rule_cve20250936",
    platform=["arista_eos"],
    commands=dict(
        show_version="show version",
        show_running_config="show running-config",
        show_logging="show logging",
    ),
)
def rule_cve20250936(configuration, commands, device, devices):
    """
    CVE-2025-0936 (Arista EOS)

    Description:
      On affected platforms running Arista EOS with a gNMI transport enabled, running the gNOI
      File TransferToRemote RPC with credentials for a remote server may cause these remote-server
      credentials to be logged or accounted on the local EOS device or possibly on other remote
      accounting servers (i.e. TACACS, RADIUS, etc).

    Advisory access note:
      The Arista advisory content is not machine-retrievable here (CAPTCHA). This rule uses a
      conservative heuristic for versioning:
        - Treat EOS 4.x as potentially affected.
        - Treat EOS 5.x+ as not vulnerable for this rule.

    Vulnerable configuration (for this rule):
      - gNMI is enabled (management API transport enabled).
      - gNOI file transfer is used (cannot be reliably detected from config alone), and AAA accounting
        to TACACS/RADIUS is configured (increases likelihood of credential exposure via accounting/logging).

    Non-vulnerable scenarios (for this rule):
      - EOS 5.x+ (heuristic).
      - gNMI not enabled.
      - No AAA accounting configured (TACACS/RADIUS) (reduces exposure path described in CVE).
    """
    version_output = commands.show_version or ""
    config_output = commands.show_running_config or ""
    logging_output = commands.show_logging or ""

    # --- Version parsing (best-effort) ---
    # Common EOS output includes:
    #   "Software image version: 4.30.2F"
    #   "Software image version: 4.31.1M"
    #   "Software image version: 4.29.3.1F"
    m = re.search(
        r"Software image version:\s*([0-9]+)\.([0-9]+)\.([0-9]+)",
        version_output,
        re.I,
    )
    if not m:
        # Cannot determine version => do not assert vulnerability based on version alone.
        return

    major, minor, patch = map(int, m.groups())

    # --- Vulnerable versions (heuristic due to advisory CAPTCHA) ---
    version_vulnerable = (major == 4)

    if not version_vulnerable:
        assert True
        return

    # --- Vulnerable configuration heuristics ---
    # gNMI enabled indications in EOS config:
    #   management api gnmi
    #     transport grpc <...>
    #     transport <...> (varies)
    gnmi_enabled = bool(
        re.search(r"^\s*management\s+api\s+gnmi\b", config_output, re.M | re.I)
        and re.search(r"^\s*transport\s+\S+", config_output, re.M | re.I)
    )

    if not gnmi_enabled:
        assert True
        return

    # AAA accounting to remote servers (TACACS/RADIUS) increases risk of credential exposure via accounting.
    # Heuristics:
    #   aaa accounting ... group tacacs+
    #   aaa accounting ... group radius
    #   tacacs-server host ...
    #   radius-server host ...
    aaa_accounting_configured = bool(
        re.search(r"^\s*aaa\s+accounting\b.*\bgroup\s+(tacacs\+|radius)\b", config_output, re.M | re.I)
        or re.search(r"^\s*tacacs-server\s+host\b", config_output, re.M | re.I)
        or re.search(r"^\s*radius-server\s+host\b", config_output, re.M | re.I)
    )

    if not aaa_accounting_configured:
        assert True
        return

    # Optional: look for any log hints that gNOI/gnmi file transfer activity is present.
    # This is not required to flag, but can strengthen the message.
    log_hint = bool(
        re.search(r"\bgnoi\b", logging_output, re.I)
        or re.search(r"\bTransferToRemote\b", logging_output, re.I)
        or re.search(r"\bfile\s+transfer\b", logging_output, re.I)
    )

    hint_text = (
        "Operational logs include gNOI/TransferToRemote-related hints. "
        if log_hint
        else "No gNOI/TransferToRemote log hints were detected (this does not rule out exposure). "
    )

    assert False, (
        f"Device {device.name} is vulnerable to CVE-2025-0936. "
        f"Detected Arista EOS {major}.{minor}.{patch} (heuristic: EOS 4.x treated as potentially affected), "
        "gNMI transport appears enabled, and AAA accounting/remote AAA servers (TACACS/RADIUS) are configured. "
        "On affected EOS versions, invoking the gNOI File TransferToRemote RPC with remote-server credentials "
        "may cause those credentials to be logged locally and/or sent to remote accounting servers. "
        f"{hint_text}"
        "Mitigation: upgrade to a fixed EOS release per Arista advisory and/or disable gNMI/gNOI file transfer "
        "or adjust AAA accounting/logging to prevent credential exposure until upgraded. "
        "Advisory: https://www.arista.com/en/support/advisories-notices/security-advisory"
    )