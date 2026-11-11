"""PowerShell scripts: syntax for all, behaviour for the lockdown and isolation checks.

Runs only when PowerShell 7 (pwsh) is available (set HDV_PWSH or put pwsh on PATH). Nothing
here touches a real Arc agent, VM or network beyond localhost: azcmagent is replaced by a fake,
and .vmx files are synthetic.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import stat
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
PWSH = os.environ.get("HDV_PWSH") or shutil.which("pwsh")
SCRIPTS = sorted((REPO_ROOT / "lab" / "powershell").rglob("*.ps1"))
LOCKDOWN = REPO_ROOT / "lab" / "powershell" / "arc-onboarding" / "Set-HdvArcAgentLockdown.ps1"
VMX_CHECK = REPO_ROOT / "lab" / "powershell" / "isolation" / "Test-HdvVmxNetworking.ps1"
ISOLATION = REPO_ROOT / "lab" / "powershell" / "isolation" / "Test-HdvLabIsolation.ps1"

pytestmark = pytest.mark.skipif(PWSH is None, reason="PowerShell 7 (pwsh) not available")


def pwsh(command: str, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    # Stop on any error so that parameter-binding failures cannot masquerade as exit code 0.
    return subprocess.run(
        [PWSH, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "$ErrorActionPreference = 'Stop'; " + command],
        capture_output=True, text=True, timeout=timeout,
    )


def test_scripts_exist() -> None:
    assert {p.name for p in SCRIPTS} >= {LOCKDOWN.name, VMX_CHECK.name, ISOLATION.name}


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_script_parses_without_errors(script: Path) -> None:
    result = pwsh(
        "$t=$null; $e=$null; [void][System.Management.Automation.Language.Parser]::ParseFile("
        f"'{script}', [ref]$t, [ref]$e); $e | ForEach-Object {{ $_.Message }}; exit @($e).Count"
    )
    assert result.returncode == 0, result.stdout + result.stderr


# --------------------------------------------------------------------------- #
# Set-HdvArcAgentLockdown.ps1 against a fake azcmagent
# --------------------------------------------------------------------------- #
FAKE_AZCMAGENT = textwrap.dedent(
    """\
    #!{python}
    import json, sys
    from pathlib import Path
    state = Path(__file__).with_suffix(".json")
    log = Path(__file__).with_suffix(".log")
    config = json.loads(state.read_text())
    args = sys.argv[1:]
    with log.open("a") as handle:
        handle.write(" ".join(args) + "\\n")
    if args[:2] == ["config", "get"]:
        print(json.dumps({{"value": config.get(args[2], "")}}))
    elif args[:2] == ["config", "set"]:
        config[args[2]] = args[3]
        state.write_text(json.dumps(config))
    else:
        sys.exit(3)
    """
)


@pytest.fixture
def fake_agent(tmp_path: Path) -> Path:
    agent = tmp_path / "azcmagent"
    agent.write_text(FAKE_AZCMAGENT.format(python=sys.executable), encoding="utf-8")
    agent.chmod(agent.stat().st_mode | stat.S_IXUSR)
    agent.with_suffix(".json").write_text(
        json.dumps({"incomingconnections.enabled": "true", "guestconfiguration.enabled": "true", "extensions.allowlist": ""}),
        encoding="utf-8",
    )
    return agent


def _sets(agent: Path) -> list[str]:
    log = agent.with_suffix(".log")
    return [line for line in log.read_text().splitlines() if line.startswith("config set")] if log.exists() else []


def test_lockdown_verify_only_reports_and_changes_nothing(fake_agent: Path) -> None:
    result = pwsh(f"& '{LOCKDOWN}' -VerifyOnly -AzcmagentPath '{fake_agent}'; exit $LASTEXITCODE")
    assert result.returncode == 1
    assert _sets(fake_agent) == []


def test_lockdown_whatif_changes_nothing(fake_agent: Path) -> None:
    pwsh(f"& '{LOCKDOWN}' -WhatIf -AzcmagentPath '{fake_agent}'; exit $LASTEXITCODE")
    assert _sets(fake_agent) == []


def test_lockdown_applies_microsoft_settings_and_is_idempotent(fake_agent: Path) -> None:
    first = pwsh(f"& '{LOCKDOWN}' -Confirm:$false -AzcmagentPath '{fake_agent}'; exit $LASTEXITCODE")
    assert first.returncode == 0, first.stdout + first.stderr
    config = json.loads(fake_agent.with_suffix(".json").read_text())
    assert config == {
        "incomingconnections.enabled": "false",
        "guestconfiguration.enabled": "false",
        "extensions.allowlist": "Microsoft.Azure.Monitor/AzureMonitorWindowsAgent",
    }
    assert len(_sets(fake_agent)) == 3
    second = pwsh(f"& '{LOCKDOWN}' -Confirm:$false -AzcmagentPath '{fake_agent}'; exit $LASTEXITCODE")
    assert second.returncode == 0 and len(_sets(fake_agent)) == 3  # no further changes


@pytest.mark.parametrize(
    "extension",
    ["Microsoft.CPlat.Core/RunCommandHandlerWindows", "Microsoft.Compute/CustomScriptExtension", "not-a-valid-name"],
)
def test_lockdown_refuses_dangerous_or_invalid_extensions(fake_agent: Path, extension: str) -> None:
    result = pwsh(f"& '{LOCKDOWN}' -Confirm:$false -AllowedExtensions '{extension}' -AzcmagentPath '{fake_agent}'")
    assert result.returncode != 0
    assert _sets(fake_agent) == []


def test_lockdown_unknown_output_fails_closed(tmp_path: Path) -> None:
    agent = tmp_path / "azcmagent"
    agent.write_text(f"#!{sys.executable}\nimport sys\nprint('unexpected')\n", encoding="utf-8")
    agent.chmod(agent.stat().st_mode | stat.S_IXUSR)
    result = pwsh(f"& '{LOCKDOWN}' -VerifyOnly -AzcmagentPath '{agent}'; exit $LASTEXITCODE")
    assert result.returncode == 1


# --------------------------------------------------------------------------- #
# Test-HdvVmxNetworking.ps1 against synthetic .vmx files
# --------------------------------------------------------------------------- #
def _vmx(path: Path, nics: list[dict[str, str]]) -> Path:
    lines = ['displayName = "{}"'.format(path.stem)]
    for index, nic in enumerate(nics):
        lines.append(f'ethernet{index}.present = "TRUE"')
        for key, value in nic.items():
            lines.append(f'ethernet{index}.{key} = "{value}"')
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _vmx_check(root: Path, firewall: Path) -> subprocess.CompletedProcess[str]:
    return pwsh(f"& '{VMX_CHECK}' -Path '{root}' -LabNetworks VMnet10 -FirewallVmx '{firewall}' | Format-List | Out-String -Width 200; exit $LASTEXITCODE")


@pytest.fixture
def good_lab(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "vms"
    firewall = _vmx(root / "FW01" / "FW01.vmx", [{"connectionType": "nat"}, {"connectionType": "custom", "vnet": "VMnet10"}])
    _vmx(root / "DC01" / "DC01.vmx", [{"connectionType": "custom", "vnet": "VMnet10"}])
    _vmx(root / "SYNC01" / "SYNC01.vmx", [{"connectionType": "custom", "vnet": "VMnet10"}])
    return root, firewall


def test_vmx_isolated_lab_passes_with_manual_host_adapter_item(good_lab: tuple[Path, Path]) -> None:
    result = _vmx_check(*good_lab)
    assert result.returncode == 2, result.stdout + result.stderr  # only the MANUAL host-adapter item remains
    assert "FAIL" not in result.stdout


@pytest.mark.parametrize(
    ("nic", "expected"),
    [
        ({"connectionType": "bridged"}, "bridged"),
        ({"connectionType": "nat"}, "not an allowed network"),
        ({"connectionType": "custom", "vnet": "VMnet0"}, "not an allowed network"),
        ({"vnet": "VMnet10"}, "connectionType missing"),
    ],
)
def test_vmx_misconfigured_lab_vm_fails(good_lab: tuple[Path, Path], nic: dict[str, str], expected: str) -> None:
    root, firewall = good_lab
    _vmx(root / "WS01" / "WS01.vmx", [nic])
    result = _vmx_check(root, firewall)
    assert result.returncode == 1 and expected in result.stdout, result.stdout + result.stderr


def test_vmx_shared_folder_on_lab_vm_fails(good_lab: tuple[Path, Path]) -> None:
    root, firewall = good_lab
    vmx = root / "DC01" / "DC01.vmx"
    vmx.write_text(vmx.read_text(encoding="utf-8") + 'sharedFolder0.present = "TRUE"\nsharedFolder0.enabled = "TRUE"\n', encoding="utf-8")
    result = _vmx_check(root, firewall)
    assert result.returncode == 1 and "bypassing FW01" in result.stdout, result.stdout + result.stderr


def test_vmx_shared_folder_allowed_on_mgmt_only(good_lab: tuple[Path, Path]) -> None:
    root, firewall = good_lab
    mgmt = _vmx(root / "MGMT" / "MGMT.vmx", [{"connectionType": "custom", "vnet": "VMnet10"}])
    mgmt.write_text(mgmt.read_text(encoding="utf-8") + 'sharedFolder0.enabled = "TRUE"\n', encoding="utf-8")
    result = pwsh(
        f"& '{VMX_CHECK}' -Path '{root}' -LabNetworks VMnet10 -FirewallVmx '{firewall}' -SharedFoldersAllowedVmx '{mgmt}' "
        "| Format-List | Out-String -Width 200; exit $LASTEXITCODE"
    )
    assert result.returncode == 2 and "explicitly allowed" in result.stdout, result.stdout + result.stderr


def test_vmx_firewall_with_two_lab_nics_fails(tmp_path: Path) -> None:
    root = tmp_path / "vms"
    firewall = _vmx(root / "FW01" / "FW01.vmx", [{"connectionType": "custom", "vnet": "VMnet10"}] * 2)
    result = _vmx_check(root, firewall)
    assert result.returncode == 1 and "lab NICs=2" in result.stdout


# --------------------------------------------------------------------------- #
# Test-HdvLabIsolation.ps1 fails closed
# --------------------------------------------------------------------------- #
def test_isolation_reachable_forbidden_target_fails() -> None:
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen()
        port = server.getsockname()[1]
        result = pwsh(
            f"& '{ISOLATION}' -ExpectedGateway 10.0.0.1 -ForbiddenTargets 127.0.0.1 -ForbiddenPorts {port} "
            "-RequiredEndpoints @() -TimeoutMs 500 | Format-List | Out-String -Width 200; exit $LASTEXITCODE"
        )
    assert result.returncode == 1
    assert "Connected" in result.stdout


@pytest.mark.skipif(os.name == "nt", reason="on Windows Get-NetRoute exists")
def test_isolation_missing_cmdlet_fails_closed() -> None:
    result = pwsh(
        f"& '{ISOLATION}' -ExpectedGateway 10.0.0.1 -ForbiddenTargets 192.0.2.1 -ExcludeTargets 192.0.2.1 "
        "-RequiredEndpoints @() | Format-List | Out-String -Width 200; exit $LASTEXITCODE"
    )
    assert result.returncode == 1 and "cmdlet unavailable" in result.stdout
