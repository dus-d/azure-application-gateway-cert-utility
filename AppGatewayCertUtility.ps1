#################################
#  App Gateway Cert Util V0.2   #
#################################

param(
    $ApplicationGateway,
    $Operation,
    [switch]$Remove
)

# Programmatic Operation selection via terminal
switch($Operation) {
    "Unused" {
        $InteractiveOption = "1"
    }
    "KeyVault" {
        $InteractiveOption = "2"
    }
    "Expiration" {
        $InteractiveOption = "3"
    }
    $null {
        $InteractiveOption = "0"
    }
    Default {
        Write-Host "Invalid Operation chosen.  Your options are `"Unused`", `"KeyVault`", `"Expiration`", or omitting the `"-Operation`" flag."
        Exit
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
    Write-Error "Please supply an Application Gateway PS Object from Get-AzApplicationGateway"
    Exit
}

# Get SKU type
$sku = if($appgw.Sku.Tier -match "^Standard_v2$|^WAF_v2$") {
    "V2"
} elseif($appgw.Sku.Tier -match "^Standard$|^WAF$") {
    "V1"
} else {
    Write-Error "Error in retreiving Application Gateway SKU.  Ensure your object has an appropriate SKU tier."
    Exit
}

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
While ($InteractiveOption -notmatch "1|2|3" ) {
    Write-Information "Choose from the following options:`n[1] Check for unused certificates`n[2] Check for inaccessible Key Vault references`n[3] Check certificate expiration"
    $InteractiveOption = Read-Host -Prompt ">"
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

Switch ($InteractiveOption) {
    "1" {
        # SSL (Listener) Certs
        $AllSslCertificates = @($NonKvSslCertificates)
        $AllSslCertificates += $KvSslCertificates
        $UnusedSslCerts = GetUnusedCertificates $AllSslCertificates $ListenerCertificates
        if($sku -eq "V1") {
            # Auth Certs
            $BackendSettingsCertificates = $ApplicationGateway.BackendHttpSettingsCollection.AuthenticationCertificates
            $UnusedBackendCerts = GetUnusedCertificates $AuthenticationCertificates $AssignedAuthenticationCertificates
        } else {
            # Trusted Root Certs
            $BackendSettingsCertificates = $ApplicationGateway.BackendHttpSettingsCollection.TrustedRootCertificates
            $UnusedBackendCerts = getUnusedCertificates $TrustedRootCertificates $BackendSettingsCertificates
            
            # Trusted Client Certs
            $SSLProfileTrustedClientCerts = $ApplicationGateway.SslProfiles.TrustedClientCertificates
            $UnusedClientCerts = getUnusedCertificates $TrustedClientCertificates $SSLProfileTrustedClientCerts
        }
        
        # Generate and print hash tables for each cert type
        $UnusedCerts = @()
        $UnusedCerts += if($UnusedSslCerts.count -gt 0) { $UnusedSslCerts }
        $UnusedCerts += if($UnusedBackendCerts.count -gt 0) { $UnusedBackendCerts }
        $UnusedCerts += if($UnusedClientCerts.count -gt 0) { $UnusedClientCerts }
        if($UnusedSslCerts.count -gt 0) {
            Write-Output "=======================================`n`tUnused SSL Certificates`t`n======================================="
            Write-Output ($UnusedSslCerts | ForEach-Object {[PSCustomObject]$_} | Format-Table Name -AutoSize)
        }
        if($sku -eq "V1") {
            if($UnusedBackendCerts.count -gt 0) {
                Write-Information "=======================================`n`tUnused Auth Certificates`t`n======================================="
                Write-Output ($UnusedBackendCerts | ForEach-Object {[PSCustomObject]$_} | Format-Table Name -AutoSize)
            }
        } else {
            if($UnusedBackendCerts.count -gt 0) {
                Write-Output "=======================================`n    Unused Trusted Root Certificates`t`n======================================="
                Write-Output ($UnusedBackendCerts | ForEach-Object {[PSCustomObject]$_} | Format-Table Name -AutoSize)
            }
            if($UnusedClientCerts.count -gt 0) {
                Write-Output "=======================================`n  Unused Trusted Client Certificates`t`n======================================="
                Write-Output ($UnusedClientCerts | ForEach-Object {[PSCustomObject]$_} | Format-Table Name -AutoSize)
            }
        }
        # Ask User to Remove Certificates
        if($UnusedCerts.count -gt 0) {
            While ($RemoveOption -notmatch "Y|N" ) {
                Write-Information "Removed Unused Certificates? (Y/N)"
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
        $BadKvRefsHashTable = @()
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
        }

        # Print bad KV references to console and whether they are removable
        Write-Information "======================================`n Bad Key Vault Certificate References`t`n======================================"
        if($BadKvCertificateReference.count -gt 0) {
            $BadKvCertificateReference | ForEach-Object {
                $BadKvRefsHashTable += @{ Name = $_.Name; Removable = "True" }
            }
        }
        if($BadKvCertificateReferenceNonRemovable.count -gt 0) {            
            $BadKvCertificateReferenceNonRemovable | ForEach-Object {
                $BadKvRefsHashTable += @{ Name = $_.Name; Removable = "False" }
            }
        }
        Write-Output ($BadKvRefsHashTable | ForEach-Object {[PSCustomObject]$_} | Format-Table Name, Removable -AutoSize)
        Write-Output "For bad Key Vault references, see the README on how to resolve these as there are limitations to what this script checks."

        # Ask user to remove bad references (only those not assigned to listeners)
        if($BadKvCertificateReference.length -gt 0) {
            While ($RemoveOption -notmatch "Y|N" ) {
                Write-Information "Removed Bad References? (Y/N)"
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
        $SSLCertsHashTableArray = @()
        $TrustedRootHashTableArray = @()
        $AuthCertHashTableArray = @()

        if($NonKvSslCertificates.count -gt 0 -or $KvSslCertificates.count -gt 0) {
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
                        $SSLCertsHashTableArray += @{ Name = $_.Name; Status = "Expired"; Expiration = $Expiration }
                    } elseif($TimeToExpiration -gt 0 -and $TimeToExpiration -lt 30) {
                        $SSLCertsHashTableArray += @{ Name = $_.Name; Status = "Expiring Soon (<30 Days)"; Expiration = $Expiration }
                    } else {
                        $SSLCertsHashTableArray += @{ Name = $_.Name; Status = "Active"; Expiration = $Expiration }
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
                            $SSLCertsHashTableArray += @{ Name = $_.Name; Status = "Expired"; Expiration = $Expiration }
                        } elseif($TimeToExpiration -gt 0 -and $TimeToExpiration -lt 30) {
                            $SSLCertsHashTableArray += @{ Name = $_.Name; Status = "Expiring Soon (<30 Days)"; Expiration = $Expiration }
                        } else {
                            $SSLCertsHashTableArray += @{ Name = $_.Name; Status = "Active"; Expiration = $Expiration }
                        }
                    } else {
                        Write-Information "$($_.Name) (KV)`t(Couldn't access Key Vault, check that certificate permissions, that it exists, and is enabled)"
                    }
                }
            }
        }
        
        # Get Trusted Root Cert Expiration
        if($TrustedRootCertificates.count -gt 0 -or $AuthenticationCertificates.count -gt 0) {
        }
        if($TrustedRootCertificates.count -gt 0) {
            $TrustedRootCertificates | ForEach-Object {
                $certData = $_.Data
                $certChain = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
                $certChain.Import([System.Convert]::FromBase64String($certData),$null,[System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)

                $Now = Get-Date
                $Expiration = $certChain[-1].NotAfter
                $TimeToExpiration = ($Expiration - $Now).Days
                $IsExpired = ($Expiration -lt $Now)
                if($IsExpired) {
                    $TrustedRootHashTableArray += @{ Name = $_.Name; Status = "Expired"; Expiration = $Expiration }
                } elseif($TimeToExpiration -gt 0 -and $TimeToExpiration -lt 30) {
                    $TrustedRootHashTableArray += @{ Name = $_.Name; Status = "Expiring Soon (<30 Days)"; Expiration = $Expiration }
                } else {
                    $TrustedRootHashTableArray += @{ Name = $_.Name; Status = "Active"; Expiration = $Expiration }
                }
            }
        }

        # Get Auth Cert Expiration
        if($AuthenticationCertificates.count -gt 0) {
            $AuthenticationCertificates | ForEach-Object {
                $certData = $_.Data
                $certChain = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
                $certChain.Import([System.Convert]::FromBase64String($certData),$null,[System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)

                $Now = Get-Date
                $Expiration = $certChain[-1].NotAfter
                $TimeToExpiration = ($Expiration - $Now).Days
                $IsExpired = ($Expiration -lt $Now)
                if($IsExpired) {
                    $AuthCertHashTableArray += @{ Name = $_.Name; Status = "Expired"; Expiration = $Expiration }
                } elseif($TimeToExpiration -gt 0 -and $TimeToExpiration -lt 30) {
                    $AuthCertHashTableArray += @{ Name = $_.Name; Status = "Expiring Soon (<30 Days)"; Expiration = $Expiration }
                } else {
                    $AuthCertHashTableArray += @{ Name = $_.Name; Status = "Active"; Expiration = $Expiration }
                }
            }
        }

        # Print Expirations to console
        if($SSLCertsHashTableArray.count -gt 0) {
            Write-Output "======================================`n      SSL Certificate Expiration `t`n======================================"
            Write-Output ($SSLCertsHashTableArray | ForEach-Object {[PSCustomObject]$_} | Format-Table Name, Status, Expiration -AutoSize)
        }
        if($TrustedRootHashTableArray.count -gt 0) {
            Write-Information "======================================`n    Backend Certificate Expiration `t`n======================================"
            Write-Output ($TrustedRootHashTableArray | ForEach-Object {[PSCustomObject]$_} | Format-Table Name, Status, Expiration -AutoSize)
        }
        if($AuthCertHashTableArray) {
            Write-Information "======================================`n    Backend Certificate Expiration `t`n======================================"
            Write-Output ($AuthCertHashTableArray | ForEach-Object {[PSCustomObject]$_} | Format-Table Name, Status, Expiration -AutoSize)
        }
    }
}
if($InteractiveOption -ne "3" -and $Remove) {
    return $ApplicationGateway
}
