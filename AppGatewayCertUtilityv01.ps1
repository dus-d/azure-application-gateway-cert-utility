param(
    $ApplicationGateway,
    $Operation,
    [switch]$Remove
)

# Programmatic Operation selection via terminal
switch($Operation) {
    "Unused" {
        $Operation = "1"
    }
    "KeyVault" {
        $Operation = "2"
    }
    "Expiration" {
        $Operation = "3"
    }
    Default {
        $Operation = "0"
    }
}

# Return AppGW Object after removal of certs or return interactive output
if($Remove) {
    $RemoveOption = "Y"
} else {
    $InformationPreference = "continue"
    $RemoveOption = "N"
}

# Verify supplied object is of type PSApplicationGateway
if(!$ApplicationGateway -or $ApplicationGateway.GetType().Name -ne "PSApplicationGateway") {
    Write-Error "Please supply an Application Gateway PS Object"
    Exit
}

# Get SKU type
$sku = if($appgw.Sku.Tier -match "^Standard_v2$|^WAF_v2$") {
    "V2"
}elseif($appgw.Sku.Tier -match "^Standard$|^WAF$") {
    "V1"
}
    else {
    Write-Error "Error in retreiving Application Gateway SKU.  Ensure your object has an appropriate SKU tier."
    Exit
}
Write-Information "`nApplication Gateway is of type: ${sku}`n"

# Get Certificates
$NonKvSslCertificates = $ApplicationGateway.SslCertificates | Where-Object { !$_.KeyVaultSecretId }
$KvSslCertificates = $ApplicationGateway.SslCertificates | Where-Object { $_.KeyVaultSecretId }
$Listeners = $ApplicationGateway.HttpListeners
$ListenerCertificates = $Listeners.SslCertificate
$AuthenticationCertificates = $ApplicationGateway.AuthenticationCertificates
$TrustedRootCertificates = $ApplicationGateway.TrustedRootCertificates
$TrustedClientCertificates = $ApplicationGateway.TrustedClientCertificates

# Get MI, if any
$ApplicationGatewayManagedIdentity = $ApplicationGateway.Identity

# Get User Choice of Task to Perform
While ($Operation -notmatch "1|2|3" ) {
    Write-Information "Choose from the following options:`n[1] Check for unused certificates`n[2] Check for inaccessible Key Vault references`n[3] Check certificate expiration"
    $Operation = Read-Host -Prompt ">"
}

# Array Diff Function, probably reinventing the wheel
function GetUnusedCertificates($AllCerts, $AssignedCerts) {
    $UnusedCerts = @()
    $AllCerts | ForEach-Object {
        if($_.Id -notin $AssignedCerts.Id) {
            $UnusedCerts += $_
        }
    }
    return $UnusedCerts
}

Switch ($Operation) {
    "1" {
        # SSL (Listener) Certs
        $AllSslCertificates = @($NonKvSslCertificates)
        $AllSslCertificates += $KvSslCertificates
        $UnusedSslCerts = GetUnusedCertificates $AllSslCertificates $ListenerCertificates
        Write-Information "=======================================`n`tUnused SSL Certificates`t`n======================================="
        if($UnusedSslCerts.count -gt 0) {
            $UnusedSslCerts | ForEach-Object {
                Write-Information "$($_.Id.split('/')[10])`t"
            }
        } else {
            Write-Information "`nNo unused SSL Certificates found"
        }
        if($sku -eq "V1") {
            # Auth Certs
            $BackendSettingsCertificates = $ApplicationGateway.BackendHttpSettingsCollection.AuthenticationCertificates
            $UnusedBackendCerts = GetUnusedCertificates $AuthenticationCertificates $AssignedAuthenticationCertificates
            if($UnusedBackendCerts.count -gt 0) {
                Write-Information "=======================================`n`tUnused Auth Certificates`t`n======================================="
                $UnusedBackendCerts | ForEach-Object {
                    Write-Information "$($_.Id.split('/')[10])`t(Unused Auth Certificate)"
                }
            }
        } else {
            # Trusted Root Certs
            $BackendSettingsCertificates = $ApplicationGateway.BackendHttpSettingsCollection.TrustedRootCertificates
            $UnusedBackendCerts = getUnusedCertificates $TrustedRootCertificates $BackendSettingsCertificates
            if($UnusedBackendCerts.count -gt 0) {
                Write-Information "=======================================`n    Unused Trusted Root Certificates`t`n======================================="
                $UnusedBackendCerts | ForEach-Object {
                    Write-Information "$($_.Id.split('/')[10])`t"
                }
            }
            # Trusted Client Certs
            $SSLProfileTrustedClientCerts = $ApplicationGateway.SslProfiles.TrustedClientCertificates
            $UnusedClientCerts = getUnusedCertificates $TrustedClientCertificates $SSLProfileTrustedClientCerts
            if($UnusedClientCerts.count -gt 0) {
                Write-Information "=======================================`n  Unused Trusted Client Certificates`t`n======================================="
                $UnusedClientCerts | ForEach-Object {
                    Write-Information "$($_.Id.split('/')[10])`t"
                }
            }
        }
        
        $UnusedCerts = @()
        $UnusedCerts += if($UnusedSslCerts) { $UnusedSslCerts }
        $UnusedCerts += if($UnusedBackendCerts) { $UnusedBackendCerts }
        $UnusedCerts += if($UnusedClientCerts) { $UnusedClientCerts }
        # Ask User to Remove Certificates
        if($UnusedCerts.count -gt 0) {
            While ($RemoveOption -notmatch "Y|N" ) {
                Write-Information "Remove Unused Certificates? (Y/N)"
                $RemoveOption = Read-Host -Prompt ">"
            } 
            if($RemoveOption -eq "Y") {
                $UnusedCerts | ForEach-Object {
                    $name = $_.Name
                    Switch($_.Type.split('/')[2]) {
                        "sslCertificates" {
                            $ApplicationGateway = Remove-AzApplicationGatewaySslCertificate -ApplicationGateway $ApplicationGateway -Name $name
                        }
                        "authenticationCertificates" {
                            $ApplicationGateway = Remove-AzApplicationGatewayAuthenticationCertificate -ApplicationGateway $ApplicationGateway -Name $name
                        }
                        "trustedRootCertificates" {
                            $ApplicationGateway = Remove-AzApplicationGatewayTrustedRootCertificate -ApplicationGateway $ApplicationGateway -Name $name
                        }
                        "trustedClientCertificates" {
                            $ApplicationGateway = Remove-AzApplicationGatewayTrustedClientCertificate -ApplicationGateway $ApplicationGateway -Name $name
                        }
                    }
                }
            }
        } else {
            Write-Information "No unused certificates found"
        }
    }
    "2" {
        # Bad KV references can't be removed if attached to listener
        $BadKvCertificateReference = @()
        $BadKvCertificateReferenceNonRemovable = @()
        if($KvSslCertificates.Count -gt 0) {
            $KvSslCertificates | ForEach-Object {

                # Check that user can access KV and Cert, and then check that MI has permissions to check as well.
                $KeyVaultName = $_.KeyVaultSecretId -replace '(https*\:\/\/)(.*)(\.vault.*$)','$2'
                $KeyVaultSecret = $_.KeyVaultSecretId -replace '(.*\/secrets\/)(\w*)(\/*\w*)','$2'
                $Kv = Get-AzKeyVault -VaultName $KeyVaultName -ErrorAction 'silentlycontinue'
                $KvCert = Get-AzKeyVaultCertificate -VaultName $KeyVaultName -Name $KeyVaultSecret -ErrorAction 'silentlycontinue'
                if($ApplicationGatewayManagedIdentity) {
                    $PrincipalId = $ApplicationGatewayManagedIdentity.UserAssignedIdentities.Values.PrincipalId
                }

                # Check MI Permissions to Secrets and Network Perms
                if($Kv -and $PrincipalId) {
                    $AccessPolicy = $Kv.AccessPolicies | Where-Object {
                        $_.ObjectId -eq $PrincipalId
                    }
                    if($AccessPolicy -and ("get" -in $AccessPolicy.PermissionstoSecrets) -and $Kv.NetworkAcls.Bypass -eq "AzureServices") {
                        $MIPerms = $true
                    }
                } else {
                    $MIPerms = $false
                }
                
                if(!$Kv -or !$KvCert -or !$KvCert.Enabled -or !$MIPerms) {
                    # Check if Assigned to Listener
                    $IsAssignedToListener = ($_.Id -in $Listeners.SslCertificate.Id)
                    if($IsAssignedToListener) {
                        $BadKvCertificateReferenceNonRemovable += $_
                    } else {
                        $BadKvCertificateReference += $_
                    }
                }
                
            }
        } else {
            Write-Information "No listener certificates are referencing Key Vault"
        }
        Write-Information "======================================`n Bad Key Vault Certificate References`t`n======================================"
        if($BadKvCertificateReference.count -gt 0) {
            $BadKvCertificateReference | ForEach-Object {
                Write-Information "$($_.Id.split('/')[10])`t(Unassigned, removable)"
            }
        }
        if($BadKvCertificateReferenceNonRemovable.count -gt 0) {            
            $BadKvCertificateReferenceNonRemovable | ForEach-Object {
                Write-Information "$($_.Id.split('/')[10])`t(Assigned to listener, non-removable)"
            }
            Write-Information ""
            Write-Information "For bad Key Vault references, see the README on how to resolve these as there are limitations to what this script checks."
        } else {
            Write-Information "`nNo bad Key Vault certificate references found."
        }

        if($BadKvCertificateReference.length -gt 0) {
            While ($RemoveOption -notmatch "Y|N" ) {
                Write-Information "Remove Bad References? (Y/N)"
                $RemoveOption = Read-Host -Prompt ">"
            } 
            if($RemoveOption -eq "Y") {
                $BadKvCertificateReference | ForEach-Object {
                    $ApplicationGateway = Remove-AzApplicationGatewaySslCertificate -ApplicationGateway $ApplicationGateway -Name $_.Name
                }
            }
        }
    }
    "3" {
        # Get SSL Leaf Cert Expiration as long as PFX bundled properly (Non-KV)
        if($NonKvSslCertificates.count -gt 0 -or $KvSslCertificates.count -gt 0) {
            Write-Output "======================================`n      SSL Certificate Expiration `t`n======================================"
            $CertsHashTableArray = @()
            if($NonKvSslCertificates.count -gt 0) {
                $NonKvSslCertificates | ForEach-Object {
                    $certData = $_.PublicCertData
                    $certChain = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
                    $certChain.Import([System.Convert]::FromBase64String($certData),$null,[System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
    
                    $Now = Get-Date
                    $Expiration = $certChain[-1].NotAfter
                    $TimeToExpiration = ($Expiration - $Now).Days
                    $IsExpired = ($Expiration -lt $Now)
                    if($IsExpired) {
                        $CertsHashTableArray += @{ Name = $_.Name; Status = "Expired"; Expiration = $Expiration }
                    } elseif($TimeToExpiration -gt 0 -and $TimeToExpiration -lt 30) {
                        $CertsHashTableArray += @{ Name = $_.Name; Status = "Expiring Soon (<30 Days)"; Expiration = $Expiration }
                    } else {
                        $CertsHashTableArray += @{ Name = $_.Name; Status = "Active"; Expiration = $Expiration }
                    }
                }
            }
            # Get SSL Leaf Cert Expiration for KV Certificates
            if($KvSslCertificates.count -gt 0) {
                $KvSslCertificates | ForEach-Object {
                    $KeyVaultName = $_.KeyVaultSecretId -replace '(https*\:\/\/)(.*)(\.vault.*$)','$2'
                    $KeyVaultSecret = $_.KeyVaultSecretId -replace '(.*\/secrets\/)(\w*)(\/*\w*)','$2'
                    $Kv = Get-AzKeyVault -VaultName $KeyVaultName -ErrorAction 'silentlycontinue'
                    $KvCert = Get-AzKeyVaultCertificate -VaultName $KeyVaultName -Name $KeyVaultSecret -ErrorAction 'silentlycontinue'
                    
                    if($Kv) {
                        $Now = Get-Date
                        $Expiration = $KvCert.Expires
                        $TimeToExpiration = ($Expiration - $Now).Days
                        $IsExpired = ($Expiration -lt $Now)
                        if($IsExpired) {
                            $CertsHashTableArray += @{ Name = $_.Name; Status = "Expired"; Expiration = $Expiration }
                        } elseif($TimeToExpiration -gt 0 -and $TimeToExpiration -lt 30) {
                            $CertsHashTableArray += @{ Name = $_.Name; Status = "Expiring Soon (<30 Days)"; Expiration = $Expiration }
                        } else {
                            $CertsHashTableArray += @{ Name = $_.Name; Status = "Active"; Expiration = $Expiration }
                        }
                    } else {
                        Write-Output "$($_.Name) (KV)`t(Couldn't access Key Vault, check that certificate permissions, that it exists, and is enabled)"
                    }
                }
            }
            Write-Output ($CertsHashTableArray | ForEach-Object {[PSCustomObject]$_} | Format-Table Name, Status, Expiration -AutoSize)
        }
        
        # Get Trusted Root Cert Expiration
        if($TrustedRootCertificates.count -gt 0 -or $AuthenticationCertificates.count -gt 0) {
            Write-Output "======================================`n    Backend Certificate Expiration `t`n======================================"
        }
        if($TrustedRootCertificates.count -gt 0) {
            $CertsHashTableArray = @()
            $TrustedRootCertificates | ForEach-Object {
                $certData = $_.Data
                $certChain = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
                $certChain.Import([System.Convert]::FromBase64String($certData),$null,[System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)

                $Now = Get-Date
                $Expiration = $certChain[-1].NotAfter
                $TimeToExpiration = ($Expiration - $Now).Days
                $IsExpired = ($Expiration -lt $Now)
                if($IsExpired) {
                    $CertsHashTableArray += @{ Name = $_.Name; Status = "Expired"; Expiration = $Expiration }
                } elseif($TimeToExpiration -gt 0 -and $TimeToExpiration -lt 30) {
                    $CertsHashTableArray += @{ Name = $_.Name; Status = "Expiring Soon (<30 Days)"; Expiration = $Expiration }
                } else {
                    $CertsHashTableArray += @{ Name = $_.Name; Status = "Active"; Expiration = $Expiration }
                }
            }
            Write-Output ($CertsHashTableArray | ForEach-Object {[PSCustomObject]$_} | Format-Table Name, Status, Expiration -AutoSize)
        }

        # Get Auth Cert Expiration
        if($AuthenticationCertificates.count -gt 0) {
            $CertsHashTableArray = @()
            $AuthenticationCertificates | ForEach-Object {
                $certData = $_.Data
                $certChain = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
                $certChain.Import([System.Convert]::FromBase64String($certData),$null,[System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)

                $Now = Get-Date
                $Expiration = $certChain[-1].NotAfter
                $TimeToExpiration = ($Expiration - $Now).Days
                $IsExpired = ($Expiration -lt $Now)
                if($IsExpired) {
                    $CertsHashTableArray += @{ Name = $_.Name; Status = "Expired"; Expiration = $Expiration }
                } elseif($TimeToExpiration -gt 0 -and $TimeToExpiration -lt 30) {
                    $CertsHashTableArray += @{ Name = $_.Name; Status = "Expiring Soon (<30 Days)"; Expiration = $Expiration }
                } else {
                    $CertsHashTableArray += @{ Name = $_.Name; Status = "Active"; Expiration = $Expiration }
                }
            }
            Write-Output ($CertsHashTableArray | ForEach-Object {[PSCustomObject]$_} | Format-Table Name, Status, Expiration -AutoSize)
        }
    } Default {
        Write-Information "Valid input not detected, exiting..."
        Exit
    }
}
if($Operation -ne "3" -and $Remove) {
    return $ApplicationGateway
}
