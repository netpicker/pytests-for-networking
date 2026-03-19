from comfy import high
import re


@high(
    name="rule_cve20251260",
    platform=["arista_eos"],
    commands=dict(
        show_version="show version",
        show_running_config="show running-config",
    ),
)
def rule_cve20251260(configuration, commands, device, devices):
    """
    CVE-2025-1260 (Arista EOS)

    Description:
      On affected platforms running Arista EOS with OpenConfig configured, a gNOI request can be run
      when it should have been rejected. This issue can result in unexpected configuration/operations
      being applied to the switch.

    Advisory access note:
      The Arista advisory content is not machine-retrievable here (CAPTCHA). This rule uses a conservative
      heuristic for versioning:
        - Treat EOS 4.x as potentially affected.
        - Treat EOS 5.x+ as not vulnerable for this rule.

    Vulnerable configuration (heuristics):
      - OpenConfig management is configured/enabled (e.g., management api gnmi / openconfig).
      - gNOI is enabled/available (heuristic: presence of "gnoi" in management API config).

    Non-vulnerable scenarios (for this rule):
      - EOS 5.x+ (heuristic).
      - OpenConfig/gNMI not configured.
      - No indication of gNOI enablement.
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
    # OpenConfig / gNMI configuration indications in EOS running-config commonly appear under:
    #   management api gnmi
    # and may include "transport grpc", "provider openconfig", etc.
    openconfig_configured = bool(
        re.search(r"^\s*management\s+api\s+gnmi\b", config_output, re.M | re.I)
        or re.search(r"\bopenconfig\b", config_output, re.I)
        or re.search(r"^\s*gnmi\b", config_output, re.M | re.I)
    )

    if not openconfig_configured:
        assert True
        return

    # gNOI indication (best-effort):
    # Some platforms/configs may explicitly reference gNOI; otherwise it may be implied by gNMI/OpenConfig.
    # To reduce false positives, require an explicit "gnoi" token somewhere in config.
    gnoi_indicated = bool(re.search(r"\bgnoi\b", config_output, re.I))

    if not gnoi_indicated:
        assert True
        return

    assert False, (
        f"Device {device.name} is vulnerable to CVE-2025-1260. "
        f"Detected Arista EOS {major}.{minor}.{patch} (heuristic: EOS 4.x treated as potentially affected) "
        "with OpenConfig/gNMI configured and gNOI indicated in the running configuration. "
        "On affected platforms, a gNOI request can be run when it should have been rejected, which can result "
        "in unexpected configuration/operations being applied to the switch. "
        "Mitigation: upgrade to a fixed EOS release per Arista advisory and/or disable OpenConfig/gNMI/gNOI "
        "until upgraded. "
        "Advisory: https://www.arista.com/en/support/advisories-notices/security-advisory"
    )