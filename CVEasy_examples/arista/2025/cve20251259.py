from comfy import high
import re


@high(
    name="rule_cve20251259",
    platform=["arista_eos"],
    commands=dict(
        show_version="show version",
        show_running_config="show running-config",
    ),
)
def rule_cve20251259(configuration, commands, device, devices):
    """
    CVE-2025-1259 (Arista EOS)

    Description:
      On affected platforms running Arista EOS with OpenConfig configured, a gNOI request can be run when it
      should have been rejected. This issue can result in users retrieving data that should not have been
      available.

    Advisory access note:
      The Arista advisory content is not machine-retrievable here (CAPTCHA). This rule uses a conservative
      heuristic for versioning:
        - Treat EOS 4.x as potentially affected.
        - Treat EOS 5.x+ as not vulnerable for this rule.

    Vulnerable configuration (for this rule):
      - OpenConfig is configured/enabled (management API / OpenConfig paths present).
      - gNMI/gNOI service is enabled (e.g., TerminAttr / gNMI transport) OR OpenConfig management is enabled.

    Non-vulnerable scenarios (for this rule):
      - EOS 5.x+ (heuristic).
      - OpenConfig not configured.
      - gNMI/gNOI not enabled (no TerminAttr/gNMI indications).
    """
    version_output = commands.show_version or ""
    config_output = commands.show_running_config or ""

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
    # OpenConfig indications in running-config (best-effort):
    # - "openconfig" keyword
    # - management api gnmi / openconfig style enablement
    # - TerminAttr (often used to expose gNMI/OpenConfig telemetry)
    openconfig_configured = bool(
        re.search(r"\bopenconfig\b", config_output, re.I)
        or re.search(r"^\s*management\s+api\s+gnmi\b", config_output, re.M | re.I)
        or re.search(r"^\s*management\s+api\b.*\bgnmi\b", config_output, re.M | re.I)
        or re.search(r"^\s*daemon\s+TerminAttr\b", config_output, re.M | re.I)
        or re.search(r"\bterminattr\b", config_output, re.I)
    )

    if not openconfig_configured:
        assert True
        return

    # gNOI is typically served over gRPC alongside gNMI; look for gNMI/gRPC enablement hints.
    # If OpenConfig is configured but we cannot find explicit gNMI/gRPC, still treat as potentially exposed
    # (conservative) when TerminAttr is present.
    gnoi_path_exposed = bool(
        re.search(r"\bgnoi\b", config_output, re.I)
        or re.search(r"\bgnmi\b", config_output, re.I)
        or re.search(r"\bgrpc\b", config_output, re.I)
        or re.search(r"^\s*daemon\s+TerminAttr\b", config_output, re.M | re.I)
        or re.search(r"\bterminattr\b", config_output, re.I)
    )

    if not gnoi_path_exposed:
        assert True
        return

    assert False, (
        f"Device {device.name} is vulnerable to CVE-2025-1259. "
        f"Detected Arista EOS {major}.{minor}.{patch} (heuristic: EOS 4.x treated as potentially affected) "
        "with OpenConfig/gNMI/gNOI indications in running configuration. "
        "On affected platforms running Arista EOS with OpenConfig configured, a gNOI request can be run when "
        "it should have been rejected, potentially allowing retrieval of data that should not have been "
        "available. "
        "Mitigation: upgrade to a fixed EOS release per Arista advisory and restrict/disable gNMI/gNOI/OpenConfig "
        "exposure until upgraded (e.g., limit management-plane access, disable TerminAttr/gNMI where not needed). "
        "Advisory: https://www.arista.com/en/support/advisories-notices/security-advisory"
    )