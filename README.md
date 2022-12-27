# Intro
This utility is an interactive tool for managing Azure Application Gateway certificates.  Application Gateway does not have any native cert management functionality and there are some issues that can cause outages if you don't proactively monitor things like unused certs, Key Vault cert references, and certificate expiration.  The tool can optionally return an App Gateway PowerShell object if you'd like to use this in automation rather than interactively.

# On This Page <!-- omit in toc -->
- [Intro](#intro)
- [Interactive Usage](#interactive-usage)
  - [Examples](#examples)
  - [Implement Changes](#implement-changes)
- [Programmatic Usage](#programmatic-usage)
  - [Examples](#examples-1)
- [Script Limitations](#script-limitations)
- [Certificate Management](#certificate-management)
  - [Unused Certificates](#unused-certificates)
  - [Bad Key Vault References](#bad-key-vault-references)
  - [Certificate Expiration](#certificate-expiration)

# Interactive Usage
By providing an App Gateway object, you get the interactive prompts:
```powershell
$appgw = Get-AzApplicationGateway -ResourceGroupName "my-rg" -Name "my-appgw"
.\AppGatewayCertUtilityv01.ps1 -ApplicationGateway $appgw
```
```
Application Gateway is of type: V2

Choose from the following options:
[1] Check for unused certificates
[2] Check for inaccessible Key Vault references
[3] Check certificate expiration
>:
```
## Examples
Identify unused certs:
```
>:1
=======================================
        Unused SSL Certificates
=======================================
sslpfx2022
=======================================
    Unused Trusted Root Certificates
=======================================
mycustomrootCA
mytestrootCA
=======================================
  Unused Trusted Client Certificates
=======================================
mtlsauthCA
mtlsclient1
mtlsclient2v
Remove Unused Certificates? (Y/N)
>:
```
Identify bad Key Vault references:
```
>: 2
======================================
 Bad Key Vault Certificate References
======================================
kvcert1  (Unassigned, removable)
kvcert2 (Assigned to listener, non-removable)
Remove Bad References? (Y/N)
>:
```
Check cert expiration (less than 30 days away will be marked as "Expiring Soon"):
```
>: 3
======================================
      SSL Certificate Expiration
======================================

Name    Status          Expiration
----    ------          ----------
ssl2022 Expired         10/30/2022 1:25:36 AM
sslpfx2 Expiring Soon   1/15/2023 12:25:36 PM
ssl2023 Active          10/30/2023 3:30:27 AM
```

## Implement Changes
```powershell
Set-AzApplicationGateway -ApplicationGateway $appgw
```

# Programmatic Usage
If you want to use this in automation and not interactively, you have a few options:
- Specify the option when running the script with the `Operation` flag; acceptable values are `Unused`, `KeyVault`, and `Expiration`.  These correspond to options `1`, `2`, `3` from the interactive prompts.
- By default, these options will just return the same output from the interactive prompts to the console.  With the exception of the `Expiration` operation, you can specify the `Remove` switch to return an App Gateway object that you can assign to a variable to stage a `Set` operation.

## Examples
Return a list of unused certificates:
```powershell
.\AppGatewayCertUtilityv01.ps1 -ApplicationGateway $appgw -Operation "Unused"
```
```
=======================================
        Unused SSL Certificates
=======================================
sslpfx2022
=======================================
    Unused Trusted Root Certificates
=======================================
mycustomrootCA
mytestrootCA
=======================================
  Unused Trusted Client Certificates
=======================================
mtlsauthCA
mtlsclient1
mtlsclient2v
```
Remove unused certificates and update the App Gateway:
```powershell
$appgw = .\AppGatewayCertUtilityv01.ps1 -ApplicationGateway $appgw -Operation "Unused" -Remove
Set-AzApplicationGateway -ApplicationGateway $appgw
```
Check certificate expiration:
```powershell
$appgw = .\AppGatewayCertUtilityv01.ps1 -ApplicationGateway $appgw -Operation "Expiration"
```
```
======================================
      SSL Certificate Expiration
======================================

Name    Status          Expiration
----    ------          ----------
ssl2022 Expired         10/30/2022 1:25:36 AM
sslpfx2 Expiring Soon   1/15/2023 12:25:36 PM
ssl2023 Active          10/30/2023 3:30:27 AM
```

# Script Limitations
- The Key Vault reference checker will identify bad references but will not allow you to remove them if they are assigned to a listener.  This is because HTTPS listeners *must* have a certificate assigned.  You will need to replace it.
- The Key Vault checker requires that your user (in PowerShell) has `Get` permissions for both certificates and secrets, and that the App Gateway's Managed Identity has `Get` permissions for at least secrets.
- The Key Vault checker does not account for everything in the KV Firewall.  It will check if the Firewall policy is public and if *Trusted Services can bypass this firewall* is checked, but not if you are using a service or private endpoint to allow your App Gateway to access it.

# Certificate Management

## Unused Certificates
Each certificate type, listener certs, authentication certs (V1), and trusted root certs (V2), have a 100 certificate limit.  When you replace these with a new one, only the reference by its respective resource such as a listener or HTTP setting is removed; the certificate is still in your Application Gateway's state which can lead to bloating and failed updates when the limit is reached.  Manually identifying and removing certificates is a laborous task and should be automated.

Trusted client certificates (V2) do not have a documented limit aside from a 25KB max CA certficiate size, but to reduce any bloating here it is advised to check for unused client certs as well.  These are assigned to SSL Profiles, which are either applied globally or to listeners.

## Bad Key Vault References
Application Gateway listeners can be configured to use a .pfx that is stored in Key Vault.  This can only be done with a Managed Identity, and if there is a failure in retreiving this certificate the Application Gateway can fail to start on it's next `Start` or `Set` operation.  Failures can be caused by the following:
- Certificate no longer exists in the Key Vault.
- Certificate exists but is disabled.
- Application Gateway's Managed Identity does not have `Get` permissions for secrets, which are used to retreive the certificate.
- Application Gateway is blocked by the Key Vault Firewall (*this is not checked by this script if using IP based access, or Service or Private endpoints*)

If there are bad Key Vault references, and these are unused, they can be removed like any other certificate.  However, if they are assigned to a listener, it must first be replaced by another certificate since HTTPS listeners *must* have a .pfx certificate assigned.

## Certificate Expiration
Application Gateway will not inform you of certificates that are expired or will expire.  If you are not actively monitoring them for expiration you will usually not know until your clients receive certificate warnings or your backend connectivity is broken.  For Key Vault certificates, this is simple as you can use the relevant PowerShell commands such as `Get-AzKeyVaultCertificate` to retreive a certificate object and viewing the `Expires` property.

This is different from certificates uploaded directly to the Application Gateway.  Here, you are given the Base64 encoded certificate data under the certs `PublicCertData` or `Data` property.  The best way of determining the expiration here is by importing this data into an in-memory cert store (similar to your MMC cert stores) as a `X509Certificate2Collection` object and importing the cert.  Once imported, you can view the expiration under the `NotAfter` property.  Note that if the certificate is a bundle it will import each cert independently.  If properly bundled, the leaf/server certificate will be the last one, which can be referred to in an array with the `[-1]` index.
