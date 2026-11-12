# HDV Module 2.1 - Hybrid identity configuration TEMPLATE.
#
# Copy to 'hybrid-identity.config.local.psd1' (git-ignored) and fill in the <REQUIRED...> values.
# The scripts REFUSE this template file and any remaining <REQUIRED...> placeholder.
# This template contains NO environment facts: no domain names, SIDs, IP addresses, tenant or
# application IDs. Values marked "convention" are project naming conventions you may keep.
#
# Read-only commands to obtain the lab values (run on a lab domain member, NOT on any other network):
#   (Get-ADDomain).DNSRoot            -> ActiveDirectory.ExpectedDnsRoot
#   (Get-ADDomain).DomainSID.Value    -> ActiveDirectory.ExpectedDomainSid
#   (Get-ADDomain).DistinguishedName  -> ActiveDirectory.DomainDN
# Entra admin center > Overview: Tenant ID -> Tenant.TenantId
# Entra admin center > Domain names: the '<name>.onmicrosoft.com' domain -> Tenant.ExpectedInitialDomain
#
# WARNING: the scripts only verify that the live environment MATCHES this file. If a PRODUCTION
# domain's or tenant's real identity is entered here, every guard passes against production.
# Only ever fill in values read from inside the isolated lab and the dedicated lab tenant.
@{
    SchemaVersion    = 1

    ActiveDirectory  = @{
        # All three must match the LIVE domain or every modifying script refuses to run.
        ExpectedDnsRoot   = '<REQUIRED: DNS name of the LAB domain>'
        ExpectedDomainSid = '<REQUIRED: SID of the LAB domain (S-1-5-21-...)>'
        DomainDN          = '<REQUIRED: distinguished name of the LAB domain>'

        # Convention: lab root OU created directly under the domain root (must start with HDV).
        LabRootOuName     = 'HDV-Lab'

        # Convention: the ONLY OUs selected in Entra Connect "Domain and OU filtering".
        SyncedOuNames     = @('Users', 'Groups')

        # Convention: OUs that are never synchronised (connector account, lab administrators).
        NonSyncedOuNames  = @('Tier0')
    }

    ConnectorAccount = @{
        # Convention: dedicated AD DS connector account, 'svc-hdv-' namespace (never a Domain or Enterprise Admin).
        SamAccountName = 'svc-hdv-adsync'
        OuName         = 'Tier0'
    }

    Canary           = @{
        # Convention: disabled, permission-less objects used to prove synchronisation end to end.
        # Names must stay inside the lab namespace: 'hdv-' (sAMAccountName), 'HDV ' (display name), 'HDV-' (group).
        UserSamAccountName = 'hdv-sync-canary'
        UserDisplayName    = 'HDV Sync Canary'
        GroupName          = 'HDV-Sync-Canary'
    }

    EntraConnect     = @{
        # Microsoft: 2.6.84.0+ with application-based authentication is mandatory by 7 April 2027.
        MinimumVersion         = '2.6.84.0'
        ExpectedIdentityType   = 'Application'
        ExpectPasswordHashSync = $true
        # First installation is done in staging mode; set to $false after leaving staging mode.
        ExpectStagingMode      = $true
        # Fill in after installation from Get-ADSyncEntraConnectorCredential (application/client ID).
        ApplicationId          = '<REQUIRED-AFTER-INSTALL: application (client) ID used by Entra Connect>'
        # Maximum accepted age of the tenant's last directory sync.
        MaxSyncAgeMinutes      = 120
    }

    Tenant           = @{
        # Both must match the signed-in tenant or the Graph scripts refuse to read or change anything.
        TenantId              = '<REQUIRED: lab Entra tenant ID (GUID)>'
        ExpectedInitialDomain = '<REQUIRED: the lab tenant initial domain (name.onmicrosoft.com)>'
    }
}
