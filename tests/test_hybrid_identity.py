"""Module 2.1 (hybrid identity) PowerShell scripts, tested against MOCKED environments.

Typed confirmations are exercised with REAL Read-Host: run_interactive() drives PowerShell
through a pseudo-terminal and types the answer, exactly as an operator would. Nothing mocks
Read-Host; non-interactive and piped runs must be refused.

Every AD, ADSync, CIM, registry, event-log and Microsoft Graph cmdlet used by the scripts is
replaced by a PowerShell function (functions take precedence over cmdlets). Mocks of MODIFYING
cmdlets log their calls to a file, so tests can assert exactly what would have been changed.
Nothing touches a real directory, tenant or machine.

Test data uses reserved example values only: lab.example (RFC 2606), 192.0.2.0/24 (RFC 5737),
and obviously synthetic GUIDs/SIDs. Runs only when PowerShell 7 is available (HDV_PWSH or PATH).
"""

from __future__ import annotations

import json
import os
import pty
import re
import select
import shutil
import subprocess
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
HI = REPO_ROOT / "lab" / "powershell" / "hybrid-identity"
PWSH = os.environ.get("HDV_PWSH") or shutil.which("pwsh")
pytestmark = pytest.mark.skipif(PWSH is None, reason="PowerShell 7 (pwsh) not available")

TENANT = "11111111-1111-1111-1111-111111111111"
APP = "22222222-2222-2222-2222-222222222222"
OTHER_TENANT = "99999999-9999-9999-9999-999999999999"
INITIAL = "hdvlab.onmicrosoft.com"
PASSWORD = "Correct-Horse-Battery-Staple-2026!"
LAB_DNS = "lab.example"
LAB_SID = "S-1-5-21-1000000000-2000000000-3000000000"
DOMAIN_DN = "DC=lab,DC=example"
ROOT = f"OU=HDV-Lab,{DOMAIN_DN}"
USERS_OU = f"OU=Users,{ROOT}"
GROUPS_OU = f"OU=Groups,{ROOT}"
TIER0_OU = f"OU=Tier0,{ROOT}"
CONNECTOR_DN = f"CN=svc-hdv-adsync,{TIER0_OU}"
APPLY = "-Apply -Confirm:$false"  # -Confirm:$false only skips per-change prompts


def write_config(tmp_path: Path, *, app_id: str = APP, staging: bool = True, phs: bool = True, tenant: str = TENANT,
                 dns: str = LAB_DNS, sid: str = LAB_SID, dn: str = DOMAIN_DN, initial: str = INITIAL,
                 canary_sam: str = "hdv-sync-canary", canary_display: str = "HDV Sync Canary", canary_group: str = "HDV-Sync-Canary",
                 connector: str = "svc-hdv-adsync") -> Path:
    path = tmp_path / "hybrid-identity.config.local.psd1"
    path.write_text(
        "@{\n"
        "  SchemaVersion = 1\n"
        f"  ActiveDirectory = @{{ ExpectedDnsRoot = '{dns}'; ExpectedDomainSid = '{sid}'; DomainDN = '{dn}'; "
        "LabRootOuName = 'HDV-Lab'; SyncedOuNames = @('Users','Groups'); NonSyncedOuNames = @('Tier0') }\n"
        f"  ConnectorAccount = @{{ SamAccountName = '{connector}'; OuName = 'Tier0' }}\n"
        f"  Canary = @{{ UserSamAccountName = '{canary_sam}'; UserDisplayName = '{canary_display}'; GroupName = '{canary_group}' }}\n"
        "  EntraConnect = @{ MinimumVersion = '2.6.84.0'; ExpectedIdentityType = 'Application'; "
        f"ExpectPasswordHashSync = ${str(phs).lower()}; ExpectStagingMode = ${str(staging).lower()}; ApplicationId = '{app_id}'; MaxSyncAgeMinutes = 120 }}\n"
        f"  Tenant = @{{ TenantId = '{tenant}'; ExpectedInitialDomain = '{initial}' }}\n"
        "}\n",
        encoding="utf-8",
    )
    return path


# Shared mocks: the LIVE (mocked) lab domain, an in-memory directory, and call logging for
# every MODIFYING cmdlet. Tests change $global:Live* to simulate a different (production) domain.
BASE_MOCKS = r"""
$global:HdvLog = $env:HDV_MOCK_LOG
function global:Log-Call([string] $Name, [hashtable] $Params) {
    $pairs = @($Params.GetEnumerator() | Where-Object { $_.Key -ne 'AccountPassword' -and $_.Key -ne 'Credential' } |
        Sort-Object Key | ForEach-Object { "$($_.Key)=$($_.Value)" })
    $extra = ''
    if ($Params.ContainsKey('AccountPassword')) { $extra = ' AccountPasswordType=' + $Params['AccountPassword'].GetType().Name }
    # -WhatIf:$false: the WhatIf preference of the script under test must not suppress the mock log.
    Add-Content -LiteralPath $global:HdvLog -Value ("$Name " + ($pairs -join ';') + $extra) -WhatIf:$false
}
$global:LiveDns = 'lab.example'; $global:LiveSid = 'S-1-5-21-1000000000-2000000000-3000000000'; $global:LiveDN = 'DC=lab,DC=example'
$global:ForestDomains = @('lab.example')
$global:Ous = New-Object System.Collections.Generic.List[string]
$global:Users = @{}
$global:Groups = @{}
$global:Protected = @()
$global:Memberships = @{}
function global:Get-ADDomain { [pscustomobject]@{ DNSRoot = $global:LiveDns; DomainSID = $global:LiveSid; DistinguishedName = $global:LiveDN; NetBIOSName = 'LAB' } }
function global:Get-ADForest { [pscustomobject]@{ Name = $global:ForestDomains[0]; Domains = $global:ForestDomains; ForestMode = 'Windows2016Forest' } }
function global:Get-ADOrganizationalUnit { param($LDAPFilter, $SearchBase, $SearchScope, $Identity, $ErrorAction)
    if ($Identity) { if ($global:Ous -contains $Identity) { return [pscustomobject]@{ DistinguishedName = $Identity } } throw "not found: $Identity" }
    if ($LDAPFilter -match '^\(ou=(.+)\)$') { $dn = "OU=$($Matches[1]),$SearchBase"; if ($global:Ous -contains $dn) { [pscustomobject]@{ DistinguishedName = $dn } } }
}
function global:New-ADOrganizationalUnit { param($Name, $Path, $Description, $ProtectedFromAccidentalDeletion)
    Log-Call 'New-ADOrganizationalUnit' $PSBoundParameters; $global:Ous.Add("OU=$Name,$Path") }
function global:Get-ADUser { param($LDAPFilter, $Properties, $ErrorAction, $Identity)
    if ($LDAPFilter -eq '(adminCount=1)') { return @($global:Protected | Where-Object { $_.Kind -eq 'user' }) }
    if ($LDAPFilter -match '^\(sAMAccountName=(.+)\)$' -and $global:Users.ContainsKey($Matches[1])) { return $global:Users[$Matches[1]] }
}
function global:New-ADUser { param($Name, $DisplayName, $SamAccountName, $Path, $AccountPassword, $Enabled, $PasswordNeverExpires, $CannotChangePassword, $AccountNotDelegated, $Description)
    Log-Call 'New-ADUser' $PSBoundParameters
    $global:Users[$SamAccountName] = [pscustomobject]@{ DistinguishedName = "CN=$Name,$Path"; SID = 'S-1-5-21-1000000000-2000000000-3000000000-1105'; adminCount = $null } }
function global:Get-ADGroup { param($LDAPFilter, $Properties, $ErrorAction)
    if ($LDAPFilter -eq '(adminCount=1)') { return @($global:Protected | Where-Object { $_.Kind -eq 'group' }) }
    if ($LDAPFilter -match '^\(sAMAccountName=(.+)\)$' -and $global:Groups.ContainsKey($Matches[1])) { return $global:Groups[$Matches[1]] }
}
function global:New-ADGroup { param($Name, $SamAccountName, $GroupScope, $GroupCategory, $Path, $Description)
    Log-Call 'New-ADGroup' $PSBoundParameters; $global:Groups[$Name] = [pscustomobject]@{ DistinguishedName = "CN=$Name,$Path" } }
function global:Get-ADPrincipalGroupMembership { param($Identity) if ($global:Memberships.ContainsKey($Identity)) { $global:Memberships[$Identity] } }
"""

PRODUCTION_DOMAIN = "$global:LiveDns = 'corp.example'; $global:LiveDN = 'DC=corp,DC=example'\n"
PRODUCTION_SID = "$global:LiveSid = 'S-1-5-21-1111111111-2222222222-3333333333'\n"
MULTI_DOMAIN = "$global:ForestDomains = @('lab.example','child.lab.example')\n"


def run(script: str, args: str, mocks: str, tmp_path: Path, timeout: int = 120) -> tuple[subprocess.CompletedProcess[str], list[str]]:
    log = tmp_path / "calls.log"
    log.write_text("", encoding="utf-8")
    command = (
        "$ErrorActionPreference = 'Stop'\n" + BASE_MOCKS + mocks +
        f"\n& '{HI / script}' {args} | Format-List | Out-String -Width 400\nexit $LASTEXITCODE\n"
    )
    result = subprocess.run(
        [PWSH, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True, text=True, timeout=timeout, env={**os.environ, "HDV_MOCK_LOG": str(log)},
        stdin=subprocess.DEVNULL,
    )
    return result, [line for line in log.read_text(encoding="utf-8").splitlines() if line]


ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07]*\x07")


class Interactive:
    def __init__(self, returncode: int, stdout: str, prompted: bool) -> None:
        self.returncode, self.stdout, self.stderr, self.prompted = returncode, stdout, "", prompted


def run_interactive(script: str, args: str, mocks: str, tmp_path: Path, answer: str, timeout: int = 180) -> tuple[Interactive, list[str]]:
    """Run in a pseudo-terminal (real console, real Read-Host) and TYPE the answer at the prompt."""
    log = tmp_path / "calls.log"
    log.write_text("", encoding="utf-8")
    command = (
        "$ErrorActionPreference = 'Stop'\n" + BASE_MOCKS + mocks +
        f"\n& '{HI / script}' {args} | Format-List | Out-String -Width 400\nexit $LASTEXITCODE\n"
    )
    master, slave = pty.openpty()
    proc = subprocess.Popen([PWSH, "-NoLogo", "-NoProfile", "-Command", command], stdin=slave, stdout=slave, stderr=slave,
                            close_fds=True, env={**os.environ, "HDV_MOCK_LOG": str(log)})
    os.close(slave)
    buffer, prompted, deadline = b"", False, time.time() + timeout
    while time.time() < deadline:
        ready, _, _ = select.select([master], [], [], 0.3)
        if ready:
            try:
                data = os.read(master, 4096)
            except OSError:
                break
            if not data:
                break
            buffer += data
            if b"\x1b[6n" in data:  # cursor-position query from the console host
                os.write(master, b"\x1b[1;1R")
            if not prompted and b"Type the exact" in buffer:
                os.write(master, (answer + "\r").encode())
                prompted = True
        elif proc.poll() is not None:
            break
    else:
        proc.kill()
    proc.wait()
    os.close(master)
    text = ANSI.sub("", buffer.decode(errors="replace")).replace("\r", "")
    return Interactive(proc.returncode, text, prompted), [line for line in log.read_text(encoding="utf-8").splitlines() if line]


def out(result) -> str:
    return result.stdout + result.stderr


def journal(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
def test_example_template_is_refused(tmp_path: Path) -> None:
    example = HI / "config" / "hybrid-identity.config.example.psd1"
    result, calls = run("New-HdvHybridLabObjects.ps1", f"-ConfigPath '{example}' {APPLY}", "", tmp_path)
    assert result.returncode == 1 and "committed template" in out(result)
    assert calls == []


def test_example_config_contains_no_environment_facts() -> None:
    text = (HI / "config" / "hybrid-identity.config.example.psd1").read_text(encoding="utf-8")
    values = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#") and "Version" not in line)
    assert not re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", values), "no IP addresses"
    assert not re.search(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-", values), "no GUIDs"
    assert "DC=" not in values and "S-1-5-21" not in values.replace("S-1-5-21-...", ""), "no DNs or SIDs"
    for key in ("ExpectedDnsRoot", "ExpectedDomainSid", "DomainDN", "TenantId", "ExpectedInitialDomain"):
        assert re.search(rf"{key}\s*=\s*'<REQUIRED", text), f"{key} must be a REQUIRED placeholder"


@pytest.mark.parametrize("script", ["New-HdvHybridLabObjects.ps1", "Set-HdvConnectorAccountPermissions.ps1"])
def test_3_missing_lab_configuration_refused(tmp_path: Path, script: str) -> None:
    result, calls = run(script, f"-ConfigPath '{tmp_path / 'missing.local.psd1'}' {APPLY}", "", tmp_path)
    assert result.returncode == 1 and "REFUSED" in result.stdout and "not found" in result.stdout
    assert calls == []


@pytest.mark.parametrize("script", ["New-HdvHybridLabObjects.ps1", "Set-HdvConnectorAccountPermissions.ps1"])
@pytest.mark.parametrize("field", ["dns", "sid", "dn"])
def test_3_placeholder_identity_refused(tmp_path: Path, script: str, field: str) -> None:
    cfg = write_config(tmp_path, **{field: "<REQUIRED: value>"})
    result, calls = run(script, f"-ConfigPath '{cfg}' {APPLY}", "", tmp_path)
    assert result.returncode == 1 and "placeholder" in result.stdout
    assert calls == []


def test_layout_rejects_connector_ou_in_sync_scope(tmp_path: Path) -> None:
    cfg = write_config(tmp_path)
    cfg.write_text(cfg.read_text(encoding="utf-8").replace("OuName = 'Tier0'", "OuName = 'Users'"), encoding="utf-8")
    result, calls = run("New-HdvHybridLabObjects.ps1", f"-ConfigPath '{cfg}' -WhatIf", "", tmp_path)
    assert result.returncode == 1 and "never be synchronised" in result.stdout
    assert calls == []


# --------------------------------------------------------------------------- #
# FIX 1 / FIX 3: AD identity guard, -Apply and typed confirmation (both AD scripts)
# --------------------------------------------------------------------------- #
AD_SCRIPTS = ["New-HdvHybridLabObjects.ps1", "Set-HdvConnectorAccountPermissions.ps1"]


def ad_args(script: str, cfg: Path, extra: str) -> str:
    base = f"-ConfigPath '{cfg}'"
    if script.startswith("New-"):
        base += " -CreateCanaryObjects"
    else:
        base += " -AccountPassword $pw -AdminCredential $cred -AdSyncConfigModulePath '/nonexistent/AdSyncConfig.psm1'"
    return f"{base} {extra}"


ADSYNCCONFIG_MOCKS = r"""
function global:Set-ADSyncBasicReadPermissions { param($ADConnectorAccountDN, $ADobjectDN, [switch] $Confirm) Log-Call 'Set-ADSyncBasicReadPermissions' $PSBoundParameters }
function global:Set-ADSyncMsDsConsistencyGuidPermissions { param($ADConnectorAccountDN, $ADobjectDN, [switch] $Confirm) Log-Call 'Set-ADSyncMsDsConsistencyGuidPermissions' $PSBoundParameters }
function global:Set-ADSyncPasswordHashSyncPermissions { param($ADConnectorAccountDN, [switch] $Confirm) Log-Call 'Set-ADSyncPasswordHashSyncPermissions' $PSBoundParameters }
function global:Set-ADSyncRestrictedPermissions { param($ADConnectorAccountDN, $Credential, [switch] $Confirm) Log-Call 'Set-ADSyncRestrictedPermissions' $PSBoundParameters }
$global:Ous.AddRange([string[]]@('@ROOT@','@USERS@','@GROUPS@','@TIER0@'))
$pw = ConvertTo-SecureString '@PASSWORD@' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('LAB\admin', (ConvertTo-SecureString 'not-used-in-tests' -AsPlainText -Force))
""".replace("@ROOT@", ROOT).replace("@USERS@", USERS_OU).replace("@GROUPS@", GROUPS_OU).replace("@TIER0@", TIER0_OU).replace("@PASSWORD@", PASSWORD)

# Lab-objects tests start with no OUs; connector tests need the OUs and the ADSyncConfig mocks.
SCRIPT_MOCKS = {"New-HdvHybridLabObjects.ps1": "", "Set-HdvConnectorAccountPermissions.ps1": ADSYNCCONFIG_MOCKS}


@pytest.mark.parametrize("script", AD_SCRIPTS)
@pytest.mark.parametrize(
    ("setup", "expected"),
    [
        (PRODUCTION_DOMAIN, "LIVE DOMAIN MISMATCH"),                               # 1 incorrect DNS domain
        (PRODUCTION_SID, "LIVE DOMAIN SID MISMATCH"),                              # 2 incorrect domain SID
        ("$global:LiveDN = 'DC=other,DC=example'\n", "DOMAIN DN MISMATCH"),        # configured DN != live DN
    ],
    ids=["1-wrong-dns", "2-wrong-sid", "wrong-dn"],
)
def test_identity_guard_zero_modifications(tmp_path: Path, script: str, setup: str, expected: str) -> None:
    cfg = write_config(tmp_path)
    result, calls = run(script, ad_args(script, cfg, APPLY), SCRIPT_MOCKS[script] + setup, tmp_path)
    assert result.returncode == 1 and "REFUSED" in result.stdout and expected in result.stdout, out(result)
    assert calls == []


@pytest.mark.parametrize("script", AD_SCRIPTS)
def test_5_missing_apply_flag_zero_modifications(tmp_path: Path, script: str) -> None:
    cfg = write_config(tmp_path)
    result, calls = run_interactive(script, ad_args(script, cfg, "-Confirm:$false"), SCRIPT_MOCKS[script], tmp_path, LAB_DNS)
    assert result.returncode == 1 and "without -Apply" in result.stdout
    assert not result.prompted and calls == []


@pytest.mark.parametrize("script", AD_SCRIPTS)
@pytest.mark.parametrize("typed", ["corp.example", "lab", "lab.example.evil", ""])
def test_6_incorrect_typed_confirmation_zero_modifications(tmp_path: Path, script: str, typed: str) -> None:
    cfg = write_config(tmp_path)
    result, calls = run_interactive(script, ad_args(script, cfg, APPLY), SCRIPT_MOCKS[script], tmp_path, typed)
    assert result.prompted and result.returncode == 1 and "does not match" in result.stdout, out(result)
    assert calls == []


@pytest.mark.parametrize("script", AD_SCRIPTS)
def test_confirm_false_never_bypasses_typed_confirmation(tmp_path: Path, script: str) -> None:
    """-Apply -Confirm:$false in a non-interactive session: the typed confirmation cannot be answered -> refused."""
    cfg = write_config(tmp_path)
    result, calls = run(script, ad_args(script, cfg, APPLY), SCRIPT_MOCKS[script], tmp_path)
    assert result.returncode == 1 and "REFUSED" in result.stdout and "interactive" in result.stdout
    assert calls == []


@pytest.mark.parametrize("script", AD_SCRIPTS)
def test_confirmation_parameter_is_not_accepted(tmp_path: Path, script: str) -> None:
    """There is no -ConfirmDomain parameter any more: PowerShell rejects the call before the script runs."""
    cfg = write_config(tmp_path)
    result, calls = run(script, ad_args(script, cfg, f"{APPLY} -ConfirmDomain '{LAB_DNS}'"), SCRIPT_MOCKS[script], tmp_path)
    assert result.returncode != 0 and "ConfirmDomain" in out(result)
    assert calls == []


@pytest.mark.parametrize("script", AD_SCRIPTS)
def test_piped_answer_is_refused(tmp_path: Path, script: str) -> None:
    """Redirected input (automation, pipes) cannot answer the typed confirmation."""
    cfg = write_config(tmp_path)
    log = tmp_path / "calls.log"
    log.write_text("", encoding="utf-8")
    command = ("$ErrorActionPreference = 'Stop'\n" + BASE_MOCKS + SCRIPT_MOCKS[script] +
               f"\n& '{HI / script}' {ad_args(script, cfg, APPLY)} | Format-List | Out-String -Width 400\nexit $LASTEXITCODE\n")
    result = subprocess.run([PWSH, "-NoLogo", "-NoProfile", "-Command", command], input=f"{LAB_DNS}\n", capture_output=True,
                            text=True, timeout=120, env={**os.environ, "HDV_MOCK_LOG": str(log)})
    assert result.returncode == 1 and "input is redirected" in result.stdout, out(result)
    assert log.read_text(encoding="utf-8") == ""


@pytest.mark.parametrize("script", AD_SCRIPTS)
def test_configuration_values_cannot_bypass_confirmation(tmp_path: Path, script: str) -> None:
    cfg = write_config(tmp_path)
    cfg.write_text(cfg.read_text(encoding="utf-8").replace(
        "  SchemaVersion = 1\n", f"  SchemaVersion = 1\n  ConfirmDomain = '{LAB_DNS}'\n  Apply = $true\n  AutoApprove = $true\n"), encoding="utf-8")
    result, calls = run(script, ad_args(script, cfg, APPLY), SCRIPT_MOCKS[script], tmp_path)
    assert result.returncode == 1 and "interactive" in result.stdout
    assert calls == []


@pytest.mark.parametrize("script", AD_SCRIPTS)
def test_whatif_makes_no_changes_and_needs_no_confirmation(tmp_path: Path, script: str) -> None:
    cfg = write_config(tmp_path)
    result, calls = run(script, ad_args(script, cfg, "-WhatIf"), SCRIPT_MOCKS[script], tmp_path)
    assert result.returncode == 0, out(result)
    assert calls == [] and "WOULD" in result.stdout and "PREVIEW" in result.stdout


# --------------------------------------------------------------------------- #
# New-HdvHybridLabObjects.ps1
# --------------------------------------------------------------------------- #
def test_lab_objects_apply_creates_protected_and_journals_everything(tmp_path: Path) -> None:
    cfg = write_config(tmp_path)
    jpath = tmp_path / "journal.jsonl"
    result, calls = run_interactive("New-HdvHybridLabObjects.ps1", f"-ConfigPath '{cfg}' -CreateCanaryObjects {APPLY} -JournalPath '{jpath}'", "", tmp_path, LAB_DNS)
    assert result.prompted and result.returncode == 0, out(result)
    ou_calls = [c for c in calls if c.startswith("New-ADOrganizationalUnit")]
    assert len(ou_calls) == 4 and all("ProtectedFromAccidentalDeletion=True" in c for c in ou_calls)
    user_calls = [c for c in calls if c.startswith("New-ADUser")]
    assert len(user_calls) == 1 and "Enabled=False" in user_calls[0] and f"Path={USERS_OU}" in user_calls[0]
    assert any(c.startswith("New-ADGroup") and f"Path={GROUPS_OU}" in c for c in calls)
    entries = journal(jpath)
    assert len([e for e in entries if e["Status"] == "DONE"]) == len(calls) == 6  # every modification recorded
    assert len([e for e in entries if e["Status"] == "STARTED"]) == len(calls)


def test_lab_objects_idempotent_and_existing_left_unchanged(tmp_path: Path) -> None:
    cfg = write_config(tmp_path)
    existing = (
        f"$global:Ous.AddRange([string[]]@('{ROOT}','{USERS_OU}','{GROUPS_OU}','{TIER0_OU}'))\n"
        f"$global:Users['hdv-sync-canary'] = [pscustomobject]@{{ DistinguishedName = 'CN=HDV Sync Canary,{USERS_OU}' }}\n"
        f"$global:Groups['HDV-Sync-Canary'] = [pscustomobject]@{{ DistinguishedName = 'CN=HDV-Sync-Canary,{GROUPS_OU}' }}\n"
    )
    result, calls = run_interactive("New-HdvHybridLabObjects.ps1", f"-ConfigPath '{cfg}' -CreateCanaryObjects {APPLY}", existing, tmp_path, LAB_DNS)
    assert result.returncode == 0 and calls == [] and result.stdout.count("EXISTS") == 6, out(result)


def test_existing_production_object_is_never_modified(tmp_path: Path) -> None:
    cfg = write_config(tmp_path)
    mocks = f"$global:Users['hdv-sync-canary'] = [pscustomobject]@{{ DistinguishedName = 'CN=hdv-sync-canary,CN=Users,{DOMAIN_DN}' }}\n"
    result, calls = run("New-HdvHybridLabObjects.ps1", f"-ConfigPath '{cfg}' -CreateCanaryObjects {APPLY}", mocks, tmp_path)
    assert result.returncode == 1 and "never modified" in result.stdout
    assert calls == []  # refused in preflight: not even the OUs are created


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("canary_sam", "hdv*)(cn=*"),             # LDAP filter injection
        ("canary_sam", "Administrator"),          # outside the lab namespace
        ("canary_sam", ""),                       # empty
        ("canary_sam", "hdv-a,OU=Evil"),          # DN injection
        ("canary_sam", "hdv-x.corp.example"),     # domain reference
        ("canary_sam", "hdv-..\\..\\x"),          # path reference
        ("canary_display", "Sync Canary"),        # missing HDV namespace
        ("canary_display", "HDV Canary)(objectClass=*"),
        ("canary_group", "Domain Admins"),        # outside namespace
        ("canary_group", "HDV-Group;rm"),         # invalid character
    ],
)
def test_10_invalid_canary_names_rejected(tmp_path: Path, field: str, value: str) -> None:
    cfg = write_config(tmp_path, **{field: value.replace("'", "''")})
    result, calls = run("New-HdvHybridLabObjects.ps1", f"-ConfigPath '{cfg}' -CreateCanaryObjects {APPLY}", "", tmp_path)
    assert result.returncode == 1 and "REFUSED" in result.stdout, out(result)
    assert calls == []


def test_ldap_filter_escaping() -> None:
    result = subprocess.run(
        [PWSH, "-NoProfile", "-NonInteractive", "-Command",
         f"Import-Module '{REPO_ROOT / 'lab' / 'powershell' / 'common' / 'HdvLab.psm1'}'; ConvertTo-HdvLdapFilterValue 'a*(b)\\c'"],
        capture_output=True, text=True, timeout=60,
    )
    assert result.stdout.strip() == "a\\2a\\28b\\29\\5cc"


def test_9_partial_execution_lab_objects(tmp_path: Path) -> None:
    cfg = write_config(tmp_path)
    jpath = tmp_path / "journal.jsonl"
    mocks = (
        "function global:New-ADGroup { param($Name, $SamAccountName, $GroupScope, $GroupCategory, $Path, $Description) "
        "Log-Call 'New-ADGroup-attempt' $PSBoundParameters; throw 'Access is denied' }\n"
    )
    result, calls = run_interactive("New-HdvHybridLabObjects.ps1", f"-ConfigPath '{cfg}' -CreateCanaryObjects {APPLY} -JournalPath '{jpath}'", mocks, tmp_path, LAB_DNS)
    assert result.returncode == 3, out(result)
    assert "PARTIAL EXECUTION: 5 change(s) completed" in result.stdout
    entries = journal(jpath)
    done = [e for e in entries if e["Status"] == "DONE"]
    failed = [e for e in entries if e["Status"] == "FAILED"]
    assert len(done) == 5 and len(failed) == 1 and "Access is denied" in failed[0]["Detail"]
    assert failed[0]["Step"] == "create canary group"


# --------------------------------------------------------------------------- #
# Set-HdvConnectorAccountPermissions.ps1
# --------------------------------------------------------------------------- #
CONNECTOR_SCRIPT = "Set-HdvConnectorAccountPermissions.ps1"


def test_connector_apply_least_privilege_sequence_and_journal(tmp_path: Path) -> None:
    cfg = write_config(tmp_path)
    jpath = tmp_path / "journal.jsonl"
    result, calls = run_interactive(CONNECTOR_SCRIPT, ad_args(CONNECTOR_SCRIPT, cfg, f"{APPLY} -JournalPath '{jpath}'"), ADSYNCCONFIG_MOCKS, tmp_path, LAB_DNS)
    assert result.prompted and result.returncode == 0, out(result)
    names = [c.split(" ", 1)[0] for c in calls]
    assert names == [
        "New-ADUser",
        "Set-ADSyncBasicReadPermissions", "Set-ADSyncMsDsConsistencyGuidPermissions",
        "Set-ADSyncBasicReadPermissions", "Set-ADSyncMsDsConsistencyGuidPermissions",
        "Set-ADSyncPasswordHashSyncPermissions",
        "Set-ADSyncRestrictedPermissions",
    ]
    for flag in ("AccountNotDelegated=True", "CannotChangePassword=True", "PasswordNeverExpires=True", f"Path={TIER0_OU}", "AccountPasswordType=SecureString"):
        assert flag in calls[0]
    scoped = [c for c in calls if c.startswith(("Set-ADSyncBasicRead", "Set-ADSyncMsDs"))]
    assert all(f"ADConnectorAccountDN={CONNECTOR_DN}" in c for c in scoped)
    assert {c.split("ADobjectDN=")[1].split(";")[0] for c in scoped} == {USERS_OU, GROUPS_OU}
    assert "ADobjectDN" not in [c for c in calls if c.startswith("Set-ADSyncPasswordHashSync")][0]
    entries = journal(jpath)
    assert len([e for e in entries if e["Status"] == "DONE"]) == len(calls)  # every modification recorded
    # The SecureString password never appears in output, call log or journal.
    everything = out(result) + "\n".join(calls) + jpath.read_text(encoding="utf-8")
    assert PASSWORD not in everything
    assert "S-1-5-21-1000000000-2000000000-3000000000-1105" in result.stdout


@pytest.mark.parametrize("phs", [True, False], ids=["phs-enabled", "phs-disabled"])
@pytest.mark.parametrize("forest", [
    "$global:ForestDomains = @('lab.example','child.lab.example')\n",
    "$global:ForestDomains = @('root.example','lab.example')\n",
    "$global:ForestDomains = @('other.example')\n",
], ids=["child-domain", "lab-is-not-root", "different-domain"])
def test_4_strict_single_domain_forest_zero_modifications(tmp_path: Path, phs: bool, forest: str) -> None:
    """MVP: any forest other than exactly {lab domain} refuses the WHOLE connector operation, with or without PHS."""
    cfg = write_config(tmp_path, phs=phs)
    result, calls = run_interactive(CONNECTOR_SCRIPT, ad_args(CONNECTOR_SCRIPT, cfg, APPLY), ADSYNCCONFIG_MOCKS + forest, tmp_path, LAB_DNS)
    assert result.returncode == 1 and "MULTI-DOMAIN FOREST" in result.stdout and "EVERY domain" in result.stdout, out(result)
    assert not result.prompted  # refused in preflight, before the typed confirmation
    assert calls == []


def test_4_strict_forest_cannot_be_relaxed_by_configuration(tmp_path: Path) -> None:
    cfg = write_config(tmp_path, phs=False)
    cfg.write_text(cfg.read_text(encoding="utf-8").replace(
        "  SchemaVersion = 1\n", "  SchemaVersion = 1\n  AllowMultiDomainForest = $true\n"), encoding="utf-8")
    result, calls = run(CONNECTOR_SCRIPT, ad_args(CONNECTOR_SCRIPT, cfg, "-WhatIf"), ADSYNCCONFIG_MOCKS + MULTI_DOMAIN, tmp_path)
    assert result.returncode == 1 and "MULTI-DOMAIN FOREST" in result.stdout  # even a -WhatIf preview is refused
    assert calls == []


def test_9_partial_execution_connector(tmp_path: Path) -> None:
    cfg = write_config(tmp_path)
    jpath = tmp_path / "journal.jsonl"
    failing = (
        "function global:Set-ADSyncMsDsConsistencyGuidPermissions { param($ADConnectorAccountDN, $ADobjectDN, [switch] $Confirm) "
        f"Log-Call 'Set-ADSyncMsDsConsistencyGuidPermissions' $PSBoundParameters; if ($ADobjectDN -eq '{GROUPS_OU}') {{ throw 'Insufficient access rights' }} }}\n"
    )
    result, calls = run_interactive(CONNECTOR_SCRIPT, ad_args(CONNECTOR_SCRIPT, cfg, f"{APPLY} -JournalPath '{jpath}'"), ADSYNCCONFIG_MOCKS + failing, tmp_path, LAB_DNS)
    assert result.returncode == 3, out(result)
    assert "PARTIAL EXECUTION: 4 change(s) completed" in result.stdout
    assert "Insufficient access rights" in result.stdout
    names = [c.split(" ", 1)[0] for c in calls]
    assert "Set-ADSyncPasswordHashSyncPermissions" not in names and "Set-ADSyncRestrictedPermissions" not in names
    entries = journal(jpath)
    assert [e["Status"] for e in entries if e["Status"] in ("DONE", "FAILED")] == ["DONE", "DONE", "DONE", "DONE", "FAILED"]
    assert PASSWORD not in jpath.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("setup", "expected"),
    [
        (f"$global:Users['svc-hdv-adsync'] = [pscustomobject]@{{ DistinguishedName = '{CONNECTOR_DN}'; SID = 'S-1-5-21-1-2-3-1105'; adminCount = $null }}\n"
         f"$global:Memberships['{CONNECTOR_DN}'] = @([pscustomobject]@{{ Name = 'Domain Admins'; SID = 'S-1-5-21-1-2-3-512' }})", "privileged group"),
        (f"$global:Users['svc-hdv-adsync'] = [pscustomobject]@{{ DistinguishedName = '{CONNECTOR_DN}'; SID = 'S-1-5-21-1-2-3-1105'; adminCount = 1 }}", "adminCount=1"),
        (f"$global:Users['svc-hdv-adsync'] = [pscustomobject]@{{ DistinguishedName = 'CN=svc-hdv-adsync,CN=Users,{DOMAIN_DN}'; SID = 'S-1-5-21-1-2-3-1105'; adminCount = $null }}", "never moved or modified"),
    ],
)
def test_connector_refuses_unsafe_existing_account(tmp_path: Path, setup: str, expected: str) -> None:
    cfg = write_config(tmp_path)
    result, calls = run(CONNECTOR_SCRIPT, ad_args(CONNECTOR_SCRIPT, cfg, APPLY), ADSYNCCONFIG_MOCKS + setup, tmp_path)
    assert result.returncode == 1 and "REFUSED" in result.stdout and expected in result.stdout, out(result)
    assert calls == []


@pytest.mark.parametrize(
    ("mocks_extra", "connector", "expected"),
    [
        ("$pw = ConvertTo-SecureString 'short' -AsPlainText -Force\n", "svc-hdv-adsync", "shorter than 24"),
        ("$global:Ous.Clear()\n", "svc-hdv-adsync", "New-HdvHybridLabObjects"),
        ("", "svc-adsync", "outside the HDV lab namespace"),
    ],
)
def test_connector_preflight_refusals(tmp_path: Path, mocks_extra: str, connector: str, expected: str) -> None:
    cfg = write_config(tmp_path, connector=connector)
    result, calls = run(CONNECTOR_SCRIPT, ad_args(CONNECTOR_SCRIPT, cfg, APPLY), ADSYNCCONFIG_MOCKS + mocks_extra, tmp_path)
    assert result.returncode == 1 and expected in result.stdout, out(result)
    assert calls == []


def test_connector_refuses_without_adsyncconfig_module_before_creating_account(tmp_path: Path) -> None:
    cfg = write_config(tmp_path)
    mocks = "\n".join(line for line in ADSYNCCONFIG_MOCKS.splitlines() if not line.startswith("function global:Set-ADSync"))
    result, calls = run(CONNECTOR_SCRIPT, ad_args(CONNECTOR_SCRIPT, cfg, APPLY), mocks, tmp_path)
    assert result.returncode == 1 and "ADSyncConfig module not found" in result.stdout
    assert calls == []  # previously the account could be created before this check


def test_journal_refused_inside_git_worktree(tmp_path: Path) -> None:
    cfg = write_config(tmp_path)
    inside = REPO_ROOT / "journal.local.jsonl"
    result, calls = run(CONNECTOR_SCRIPT, ad_args(CONNECTOR_SCRIPT, cfg, f"{APPLY} -JournalPath '{inside}'"), ADSYNCCONFIG_MOCKS, tmp_path)
    assert result.returncode == 1 and "git working tree" in result.stdout
    assert calls == [] and not inside.exists()


# --------------------------------------------------------------------------- #
# Read-only AD scripts also refuse a non-lab domain
# --------------------------------------------------------------------------- #
def scope_mocks(inclusion: list[str] | None, protected: str = "") -> str:
    partitions = "@()" if inclusion is None else (
        "@([pscustomobject]@{ ConnectorPartitionScope = [pscustomobject]@{ ContainerInclusionList = @("
        + ",".join(f"'{dn}'" for dn in inclusion) + ") } })"
    )
    return (
        f"$global:Ous.AddRange([string[]]@('{ROOT}','{USERS_OU}','{GROUPS_OU}','{TIER0_OU}'))\n"
        f"$global:Users['svc-hdv-adsync'] = [pscustomobject]@{{ DistinguishedName = '{CONNECTOR_DN}' }}\n"
        f"$global:Protected = @([pscustomobject]@{{ Kind = 'user'; DistinguishedName = 'CN=Administrator,CN=Users,{DOMAIN_DN}' }}{protected})\n"
        "function global:Get-ADSyncConnector { @("
        "[pscustomobject]@{ Name = 'lab.example'; ConnectorTypeName = 'AD'; Partitions = " + partitions + " },"
        "[pscustomobject]@{ Name = 'tenant - AAD'; ConnectorTypeName = 'Extensible2' }) }\n"
    )


def test_scope_clean(tmp_path: Path) -> None:
    cfg = write_config(tmp_path)
    result, _ = run("Test-HdvSyncScope.ps1", f"-ConfigPath '{cfg}' -IncludeConnectConfiguration", scope_mocks([USERS_OU, GROUPS_OU]), tmp_path)
    assert result.returncode == 0, out(result)


def test_scope_refuses_non_lab_domain(tmp_path: Path) -> None:
    cfg = write_config(tmp_path)
    result, _ = run("Test-HdvSyncScope.ps1", f"-ConfigPath '{cfg}'", scope_mocks([USERS_OU, GROUPS_OU]) + PRODUCTION_SID, tmp_path)
    assert result.returncode == 1 and "S0 lab domain identity" in result.stdout


@pytest.mark.parametrize(
    ("inclusion", "protected", "code", "text"),
    [
        ([USERS_OU, GROUPS_OU], f",[pscustomobject]@{{ Kind = 'group'; DistinguishedName = 'CN=Lab Admins,{GROUPS_OU}' }}", 1, "adminCount=1 object inside a synced OU"),
        ([DOMAIN_DN], "", 1, "whole domain is selected"),
        ([USERS_OU], "", 1, "missing"),
        ([USERS_OU, GROUPS_OU, TIER0_OU], "", 1, "extra"),
        (None, "", 2, "Synchronization Service Manager"),
    ],
)
def test_scope_problems(tmp_path: Path, inclusion: list[str] | None, protected: str, code: int, text: str) -> None:
    cfg = write_config(tmp_path)
    result, _ = run("Test-HdvSyncScope.ps1", f"-ConfigPath '{cfg}' -IncludeConnectConfiguration", scope_mocks(inclusion, protected), tmp_path)
    assert result.returncode == code and text in result.stdout, out(result)


# --------------------------------------------------------------------------- #
# Test-HdvHybridPrerequisites.ps1 (read-only)
# --------------------------------------------------------------------------- #
def prereq_mocks(*, product_type: int = 3, caption: str = "Microsoft Windows Server 2022 Datacenter", net_release: int = 533320,
                 tls: str = "ok", services: str = "", tpm: str = "ok") -> str:
    tls_body = {
        "ok": "if ($Name -eq 'DisabledByDefault') { $v = 0 } else { $v = 1 }; [pscustomobject]@{ $Name = $v }",
        "missing": "$null",
        "wrong": "[pscustomobject]@{ $Name = 7 }",
    }[tls]
    tpm_body = {"ok": "[pscustomobject]@{ TpmPresent = $true; TpmReady = $true }",
                "absent": "[pscustomobject]@{ TpmPresent = $false; TpmReady = $false }",
                "error": "throw 'Access denied'"}[tpm]
    return f"""
function global:Get-CimInstance {{ param($ClassName)
    if ($ClassName -eq 'Win32_OperatingSystem') {{ [pscustomobject]@{{ Caption = '{caption}'; ProductType = {product_type} }} }}
    else {{ [pscustomobject]@{{ PartOfDomain = $true; Domain = 'lab.example' }} }} }}
function global:Get-ItemProperty {{ param($Path, $Name, $ErrorAction)
    if ($Path -like '*NDP*') {{ return [pscustomobject]@{{ Release = {net_release} }} }}
    {tls_body} }}
function global:Get-ExecutionPolicy {{ 'RemoteSigned' }}
function global:Get-Module {{ param([switch] $ListAvailable, $Name) [pscustomobject]@{{ Name = 'ActiveDirectory' }} }}
function global:Get-Tpm {{ {tpm_body} }}
function global:Get-Service {{ param($Name, $ErrorAction) {services} }}
function global:Get-ADDomainController {{ param([switch] $Discover, [switch] $Writable) [pscustomobject]@{{ HostName = 'dc01.lab.example' }} }}
"""


def test_prereqs_all_pass(tmp_path: Path) -> None:
    result, _ = run("Test-HdvHybridPrerequisites.ps1", "", prereq_mocks(), tmp_path)
    assert result.returncode == 0, out(result)
    assert "FAIL" not in result.stdout and "WARN" not in result.stdout


@pytest.mark.parametrize(
    ("mocks", "expected_code", "expected_text"),
    [
        (prereq_mocks(product_type=2), 1, "DOMAIN CONTROLLER"),
        (prereq_mocks(product_type=1), 1, "workstation"),
        (prereq_mocks(net_release=461808), 1, "older than 4.8"),
        (prereq_mocks(tls="wrong"), 1, "expected 1"),
        (prereq_mocks(services="[pscustomobject]@{ Name = 'AADConnectProvisioningAgent' }"), 1, "Cloud Sync"),
        (prereq_mocks(caption="Microsoft Windows Server 2019 Standard"), 2, "extended support"),
        (prereq_mocks(tls="missing"), 2, "not set"),
        (prereq_mocks(tpm="absent"), 2, "software key storage provider"),
        (prereq_mocks(tpm="error"), 2, "cannot query TPM"),
        (prereq_mocks(services="[pscustomobject]@{ Name = 'ADSync' }"), 2, "already installed"),
    ],
)
def test_prereqs_detect_problems(tmp_path: Path, mocks: str, expected_code: int, expected_text: str) -> None:
    result, _ = run("Test-HdvHybridPrerequisites.ps1", "", mocks, tmp_path)
    assert result.returncode == expected_code, out(result)
    assert expected_text in result.stdout


# --------------------------------------------------------------------------- #
# Test-HdvEntraConnectConfiguration.ps1 (read-only)
# --------------------------------------------------------------------------- #
def connect_mocks(*, version: str = "2.6.92.0", identity: str = "Application", app: str = APP, staging: bool = True,
                  phs: bool = True, events: str = "", account: str = "svc-hdv-adsync", runs: str = "'success','success'") -> str:
    return f"""
function global:Get-CimInstance {{ param($ClassName) [pscustomobject]@{{ ProductType = 3 }} }}
function global:Get-Item {{ param($LiteralPath) [pscustomobject]@{{ VersionInfo = [pscustomobject]@{{ ProductVersion = '{version}' }} }} }}
function global:Get-ADSyncScheduler {{ [pscustomobject]@{{ SyncCycleEnabled = $true; StagingModeEnabled = ${str(staging).lower()}; SchedulerSuspended = $false }} }}
function global:Get-ADSyncEntraConnectorCredential {{ [pscustomobject]@{{ ConnectorIdentityType = '{identity}'; ApplicationId = '{app}' }} }}
function global:Get-ADSyncADConnectorAccount {{ [pscustomobject]@{{ ADConnectorName = 'lab.example'; ADConnectorAccountName = '{account}'; ADConnectorAccountDomain = 'LAB' }} }}
function global:Get-ADSyncAADCompanyFeature {{ [pscustomobject]@{{ PasswordHashSync = ${str(phs).lower()} }} }}
function global:Get-WinEvent {{ param($FilterHashtable, $ErrorAction) {events} }}
function global:Get-ADSyncRunProfileResult {{ param($ErrorAction) @({runs}) | ForEach-Object {{ [pscustomobject]@{{ Result = $_; StartDate = (Get-Date) }} }} }}
function global:Get-ADSyncConnectorRunStatus {{ }}
function global:Get-Tpm {{ [pscustomobject]@{{ TpmPresent = $true; TpmReady = $true }} }}
"""


def connect_args(tmp_path: Path, cfg: Path) -> str:
    binary = tmp_path / "miiserver.exe"
    binary.write_text("fake", encoding="utf-8")
    return f"-ConfigPath '{cfg}' -MiiserverPath '{binary}' -AdSyncConfigModulePath '/nonexistent.psm1'"


def test_connect_configuration_all_pass(tmp_path: Path) -> None:
    cfg = write_config(tmp_path)
    result, _ = run("Test-HdvEntraConnectConfiguration.ps1", connect_args(tmp_path, cfg), connect_mocks(), tmp_path)
    assert result.returncode == 0, out(result)


@pytest.mark.parametrize(
    ("kwargs", "code", "text"),
    [
        ({"version": "2.6.3.0"}, 1, "synchronisation stops after 7 April 2027"),
        ({"identity": "ServiceAccount"}, 1, "ConnectorIdentityType=ServiceAccount"),
        ({"app": "33333333-3333-3333-3333-333333333333"}, 1, "not found in Get-ADSyncEntraConnectorCredential"),
        ({"staging": False}, 1, "StagingModeEnabled=False (expected True)"),
        ({"phs": False}, 1, "PasswordHashSync=False"),
        ({"account": "MSOL_0123456789ab"}, 1, "express-mode MSOL_"),
        ({"events": "[pscustomobject]@{ Id = 1012; ProviderName = 'Directory Synchronization' }"}, 1, "EXPIRED"),
        ({"events": "[pscustomobject]@{ Id = 1011; ProviderName = 'Directory Synchronization' }"}, 2, "70%"),
        ({"events": "[pscustomobject]@{ Id = 1012; ProviderName = 'Some Other App' }"}, 0, "no 1011/1012"),
        ({"runs": "'success','stopped-extension-dll-exception'"}, 2, "not 'success'"),
        ({"runs": ""}, 2, "no run history"),
    ],
)
def test_connect_configuration_problems(tmp_path: Path, kwargs: dict, code: int, text: str) -> None:
    cfg = write_config(tmp_path)
    result, _ = run("Test-HdvEntraConnectConfiguration.ps1", connect_args(tmp_path, cfg), connect_mocks(**kwargs), tmp_path)
    assert result.returncode == code and text in result.stdout, out(result)


def test_connect_configuration_unset_app_id_is_a_warning(tmp_path: Path) -> None:
    cfg = write_config(tmp_path, app_id="<REQUIRED-AFTER-INSTALL: id>")
    result, _ = run("Test-HdvEntraConnectConfiguration.ps1", connect_args(tmp_path, cfg), connect_mocks(), tmp_path)
    assert result.returncode == 2 and APP in result.stdout


# --------------------------------------------------------------------------- #
# Graph scripts (FIX 4: double tenant verification)
# --------------------------------------------------------------------------- #
def graph_mocks(*, tenant: str = TENANT, initial: str = INITIAL, blocked: bool = False, sync_enabled: bool = True, canary: bool = True,
                connector_synced: bool = False, secrets: int = 0, cert_days: int = 60, update_fails: bool = False) -> str:
    update_body = "throw 'Request_ResourceNotFound'" if update_fails else "$global:Sync.Features.BlockCloudObjectTakeoverThroughHardMatchEnabled = $true"
    return f"""
$global:Sync = [pscustomobject]@{{ Id = 'sync-1'; Features = [pscustomobject]@{{ BlockCloudObjectTakeoverThroughHardMatchEnabled = ${str(blocked).lower()} }} }}
$global:SyncCopy = {{ [pscustomobject]@{{ Id = $global:Sync.Id; Features = [pscustomobject]@{{ BlockCloudObjectTakeoverThroughHardMatchEnabled = $global:Sync.Features.BlockCloudObjectTakeoverThroughHardMatchEnabled }} }} }}
function global:Connect-MgGraph {{ param($TenantId, $Scopes) Log-Call 'Connect-MgGraph' @{{ TenantId = $TenantId; Scopes = ($Scopes -join ',') }} }}
function global:Disconnect-MgGraph {{ Log-Call 'Disconnect-MgGraph' @{{}} }}
function global:Get-MgContext {{ [pscustomobject]@{{ TenantId = '{tenant}' }} }}
function global:Get-MgDirectoryOnPremiseSynchronization {{ & $global:SyncCopy }}
function global:Update-MgDirectoryOnPremiseSynchronization {{ param($OnPremisesDirectorySynchronizationId, $Features)
    Log-Call 'Update-MgDirectoryOnPremiseSynchronization' @{{ Id = $OnPremisesDirectorySynchronizationId; Block = $Features.BlockCloudObjectTakeoverThroughHardMatchEnabled }}
    {update_body} }}
function global:Get-MgOrganization {{ [pscustomobject]@{{ OnPremisesSyncEnabled = ${str(sync_enabled).lower()}; OnPremisesLastSyncDateTime = (Get-Date).AddMinutes(-10);
    VerifiedDomains = @([pscustomobject]@{{ Name = '{initial}'; IsInitial = $true }}, [pscustomobject]@{{ Name = 'lab.example'; IsInitial = $false }}) }} }}
function global:Get-MgUser {{ param($Filter, $Property)
    if ($Filter -like '*HDV Sync Canary*' -and ${str(canary).lower()}) {{ [pscustomobject]@{{ OnPremisesSyncEnabled = $true; OnPremisesSamAccountName = 'hdv-sync-canary'; AccountEnabled = $false }} }}
    if ($Filter -like '*svc-hdv-adsync*' -and ${str(connector_synced).lower()}) {{ [pscustomobject]@{{ OnPremisesSyncEnabled = $true }} }} }}
function global:Get-MgGroup {{ param($Filter, $Property) if (${str(canary).lower()}) {{ [pscustomobject]@{{ OnPremisesSyncEnabled = $true }} }} }}
function global:Get-MgApplication {{ param($Filter, $Property)
    [pscustomobject]@{{ KeyCredentials = @([pscustomobject]@{{ EndDateTime = (Get-Date).AddDays({cert_days}) }}); PasswordCredentials = @(if ({secrets} -gt 0) {{ 1..{secrets} }}) }} }}
"""


HM = "Set-HdvHardMatchTakeoverBlock.ps1"
HM_APPLY = "-Apply -Confirm:$false"


def updates(calls: list[str]) -> list[str]:
    return [c for c in calls if c.startswith("Update-Mg")]


def test_hard_match_requires_a_mode(tmp_path: Path) -> None:
    cfg = write_config(tmp_path)
    result, calls = run(HM, f"-ConfigPath '{cfg}' -Confirm:$false", graph_mocks(), tmp_path)
    assert result.returncode == 1 and "Choose exactly one mode" in result.stdout
    assert calls == []  # refused before connecting to any tenant


def test_hard_match_verify_only_reads_and_changes_nothing(tmp_path: Path) -> None:
    cfg = write_config(tmp_path)
    result, calls = run(HM, f"-ConfigPath '{cfg}' -VerifyOnly", graph_mocks(), tmp_path)
    assert result.returncode == 1 and "= False" in result.stdout
    assert updates(calls) == []
    connect = [c for c in calls if c.startswith("Connect-MgGraph")][0]
    assert "OnPremDirectorySynchronization.Read.All" in connect and "Organization.Read.All" in connect and "ReadWrite" not in connect
    assert calls[-1].startswith("Disconnect-MgGraph")


def test_hard_match_whatif_reads_only(tmp_path: Path) -> None:
    cfg = write_config(tmp_path)
    result, calls = run(HM, f"-ConfigPath '{cfg}' -WhatIf", graph_mocks(), tmp_path)
    assert result.returncode == 2 and "would be set to True" in result.stdout
    assert updates(calls) == [] and "ReadWrite" not in [c for c in calls if c.startswith("Connect-MgGraph")][0]


def test_hard_match_apply_sets_block_and_journals(tmp_path: Path) -> None:
    cfg = write_config(tmp_path)
    jpath = tmp_path / "journal.jsonl"
    result, calls = run_interactive(HM, f"-ConfigPath '{cfg}' {HM_APPLY} -JournalPath '{jpath}'", graph_mocks(), tmp_path, INITIAL)
    assert result.prompted and result.returncode == 0, out(result)
    assert len(updates(calls)) == 1 and "Block=True" in updates(calls)[0]
    assert "OnPremDirectorySynchronization.ReadWrite.All" in [c for c in calls if c.startswith("Connect-MgGraph")][0]
    assert [e["Status"] for e in journal(jpath)] == ["STARTED", "DONE"]


def test_hard_match_already_blocked_no_change(tmp_path: Path) -> None:
    cfg = write_config(tmp_path)
    result, calls = run(HM, f"-ConfigPath '{cfg}' {HM_APPLY}", graph_mocks(blocked=True), tmp_path)
    assert result.returncode == 0 and updates(calls) == []


@pytest.mark.parametrize(
    ("kwargs", "expected"),
    [
        ({"tenant": OTHER_TENANT}, "is not the configured lab tenant"),               # 7 wrong tenant ID
        ({"initial": "contoso.onmicrosoft.com"}, "does not match the configured lab initial domain"),  # 8 wrong initial domain
    ],
    ids=["7-wrong-tenant", "8-wrong-initial-domain"],
)
def test_wrong_tenant_identity_zero_graph_modifications(tmp_path: Path, kwargs: dict, expected: str) -> None:
    cfg = write_config(tmp_path)
    result, calls = run(HM, f"-ConfigPath '{cfg}' {HM_APPLY}", graph_mocks(**kwargs), tmp_path)
    assert result.returncode == 1 and expected in result.stdout, out(result)
    assert updates(calls) == [] and calls[-1].startswith("Disconnect-MgGraph")


@pytest.mark.parametrize("typed", ["contoso.onmicrosoft.com", "hdvlab", ""])
def test_hard_match_wrong_typed_initial_domain_zero_modifications(tmp_path: Path, typed: str) -> None:
    cfg = write_config(tmp_path)
    result, calls = run_interactive(HM, f"-ConfigPath '{cfg}' {HM_APPLY}", graph_mocks(), tmp_path, typed)
    assert result.prompted and result.returncode == 1 and "does not match" in result.stdout, out(result)
    assert updates(calls) == []


def test_hard_match_non_interactive_apply_zero_modifications(tmp_path: Path) -> None:
    cfg = write_config(tmp_path)
    result, calls = run(HM, f"-ConfigPath '{cfg}' {HM_APPLY}", graph_mocks(), tmp_path)
    assert result.returncode == 1 and "interactive" in result.stdout
    assert updates(calls) == [] and calls[-1].startswith("Disconnect-MgGraph")


def test_hard_match_confirmation_parameter_is_not_accepted(tmp_path: Path) -> None:
    cfg = write_config(tmp_path)
    result, calls = run(HM, f"-ConfigPath '{cfg}' {HM_APPLY} -ConfirmInitialDomain '{INITIAL}'", graph_mocks(), tmp_path)
    assert result.returncode != 0 and "ConfirmInitialDomain" in out(result)
    assert calls == []


def test_hard_match_failed_update_is_reported(tmp_path: Path) -> None:
    cfg = write_config(tmp_path)
    jpath = tmp_path / "journal.jsonl"
    result, calls = run_interactive(HM, f"-ConfigPath '{cfg}' {HM_APPLY} -JournalPath '{jpath}'", graph_mocks(update_fails=True), tmp_path, INITIAL)
    assert result.returncode == 1 and "Request_ResourceNotFound" in result.stdout, out(result)
    assert [e["Status"] for e in journal(jpath)] == ["STARTED", "FAILED"]
    assert calls[-1].startswith("Disconnect-MgGraph")


def test_entra_sync_state_all_pass(tmp_path: Path) -> None:
    cfg = write_config(tmp_path, staging=False)
    result, calls = run("Test-HdvEntraSyncState.ps1", f"-ConfigPath '{cfg}'", graph_mocks(blocked=True), tmp_path)
    assert result.returncode == 0, out(result)
    assert "ReadWrite" not in [c for c in calls if c.startswith("Connect-MgGraph")][0]


@pytest.mark.parametrize(
    ("kwargs", "staging", "code", "text"),
    [
        ({"tenant": OTHER_TENANT}, False, 1, "not the configured lab tenant"),
        ({"initial": "contoso.onmicrosoft.com", "blocked": True}, False, 1, "is not the configured lab initial domain"),
        ({"blocked": True, "sync_enabled": False}, False, 1, "OnPremisesSyncEnabled is not True"),
        ({"blocked": True, "canary": False}, False, 1, "found 0 synchronised"),
        ({"blocked": True, "canary": False}, True, 2, "found 0 synchronised"),
        ({"blocked": True, "connector_synced": True}, False, 1, "1 synchronised user(s) with this display name"),
        ({"blocked": False}, False, 1, "run Set-HdvHardMatchTakeoverBlock"),
        ({"blocked": True, "secrets": 1}, False, 2, "1 password credential"),
        ({"blocked": True, "cert_days": 5}, False, 2, "valid for 5 more day"),
        ({"blocked": True, "cert_days": -1}, False, 1, "no valid certificate"),
    ],
)
def test_entra_sync_state_problems(tmp_path: Path, kwargs: dict, staging: bool, code: int, text: str) -> None:
    cfg = write_config(tmp_path, staging=staging)
    result, calls = run("Test-HdvEntraSyncState.ps1", f"-ConfigPath '{cfg}'", graph_mocks(**kwargs), tmp_path)
    assert result.returncode == code and text in result.stdout, out(result)
    assert calls[-1].startswith("Disconnect-MgGraph")


# --------------------------------------------------------------------------- #
# Export-HdvEntraConnectWatchlist.ps1
# --------------------------------------------------------------------------- #
WATCHLIST_MOCKS = f"""
$global:Users['svc-hdv-adsync'] = [pscustomobject]@{{ DistinguishedName = '{CONNECTOR_DN}'; SID = 'S-1-5-21-1000000000-2000000000-3000000000-1105' }}
function global:Get-NetIPAddress {{ param($AddressFamily) @('192.0.2.10','127.0.0.1','169.254.10.10','192.0.2.11') | ForEach-Object {{ [pscustomobject]@{{ IPAddress = $_ }} }} }}
"""


def test_watchlist_export(tmp_path: Path) -> None:
    cfg = write_config(tmp_path)
    target = tmp_path / "private" / "HDV_EntraConnect.local.csv"
    target.parent.mkdir()
    result, _ = run("Export-HdvEntraConnectWatchlist.ps1", f"-ConfigPath '{cfg}' -OutputPath '{target}' -Confirm:$false", WATCHLIST_MOCKS, tmp_path)
    assert result.returncode == 0, out(result)
    lines = target.read_text(encoding="utf-8-sig").splitlines()
    assert lines[0] == '"ConnectorSid","ConnectorSamAccountName","SyncServer","SyncIps","ConnectAppId","LabEgressIps"'
    assert "S-1-5-21-1000000000-2000000000-3000000000-1105" in lines[1]
    assert '[""192.0.2.10"",""192.0.2.11""]' in lines[1]
    assert APP in lines[1] and lines[1].endswith(',""')


def test_watchlist_refuses_non_lab_domain(tmp_path: Path) -> None:
    cfg = write_config(tmp_path)
    target = tmp_path / "out.csv"
    result, _ = run("Export-HdvEntraConnectWatchlist.ps1", f"-ConfigPath '{cfg}' -OutputPath '{target}' -Confirm:$false", WATCHLIST_MOCKS + PRODUCTION_DOMAIN, tmp_path)
    assert result.returncode != 0 and "LIVE DOMAIN MISMATCH" in out(result) and not target.exists()


def test_watchlist_refuses_git_worktree_and_overwrite(tmp_path: Path) -> None:
    cfg = write_config(tmp_path)
    inside_repo = REPO_ROOT / "HDV_EntraConnect.local.csv"
    result, _ = run("Export-HdvEntraConnectWatchlist.ps1", f"-ConfigPath '{cfg}' -OutputPath '{inside_repo}' -Confirm:$false", WATCHLIST_MOCKS, tmp_path)
    assert result.returncode != 0 and "git working tree" in out(result)
    assert not inside_repo.exists()
    existing = tmp_path / "existing.csv"
    existing.write_text("keep", encoding="utf-8")
    result, _ = run("Export-HdvEntraConnectWatchlist.ps1", f"-ConfigPath '{cfg}' -OutputPath '{existing}' -Confirm:$false", WATCHLIST_MOCKS, tmp_path)
    assert result.returncode != 0 and existing.read_text(encoding="utf-8") == "keep"
