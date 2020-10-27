    #region Error Messages
    $DNSResolutionFailed = ' Please make sure the server name FQDN is correct and that your machine can resolve it.
Failure to resolve domain name for your logical server is almost always the result of specifying an invalid/misspelled server name,
or a client-side networking issue that you will need to pursue with your local network administrator.'

    $DNSResolutionFailedSQLMIPublicEndpoint = ' Please make sure the server name FQDN is correct and that your machine can resolve it.
You seem to be trying to connect using Public Endpoint, this error can be caused if the Public Endpoint is Disabled.
See how to enable public endpoint for your managed instance at https://aka.ms/mimanage-publicendpoint
If public endpoint is enabled, failure to resolve domain name for your logical server is almost always the result of specifying an invalid/misspelled server name,
or a client-side networking issue that you will need to pursue with your local network administrator.'

    $SQLDB_InvalidGatewayIPAddress = ' Please make sure the server name FQDN is correct and that your machine can resolve it to a valid gateway IP address (DNS configuration).
Failure to resolve domain name for your logical server is almost always the result of specifying an invalid/misspelled server name,
or a client-side networking issue that you will need to pursue with your local network administrator.
See the valid gateway addresses at https://docs.microsoft.com/azure/azure-sql/database/connectivity-architecture#gateway-ip-addresses'

    $SQLDB_GatewayTestFailed = ' Failure to reach the Gateway is usually a client-side networking issue that you will need to pursue with your local network administrator.
See more about connectivity architecture at https://docs.microsoft.com/azure/azure-sql/database/connectivity-architecture'

    $SQLDB_Redirect = " Servers in SQL Database and Azure Synapse support Redirect, Proxy or Default for the server's connection policy setting:

Default: This is the connection policy in effect on all servers after creation unless you explicitly alter the connection policy to either Proxy or Redirect.
 The default policy is Redirect for all client connections originating inside of Azure (for example, from an Azure Virtual Machine)
 and Proxy for all client connections originating outside (for example, connections from your local workstation).

Redirect (recommended): Clients establish connections directly to the node hosting the database, leading to reduced latency and improved throughput.
 For connections to use this mode, clients need to:
 - Allow outbound communication from the client to all Azure SQL IP addresses in the region on ports in the range of 11000-11999.
 - Allow outbound communication from the client to Azure SQL Database gateway IP addresses on port 1433.

Proxy: In this mode, all connections are proxied via the Azure SQL Database gateways, leading to increased latency and reduced throughput.
 For connections to use this mode, clients need to allow outbound communication from the client to Azure SQL Database gateway IP addresses on port 1433.

If you are using Proxy, the Redirect Policy related tests would not be a problem.
If you are using Redirect, failure to reach ports in the range of 11000-11999 is usually a client-side networking issue that you will need to pursue with your local network administrator.
Please check more about connection policies at https://docs.microsoft.com/en-us/azure/azure-sql/database/connectivity-architecture#connection-policy"

    $SQLMI_GatewayTestFailed = ' Failure to reach the Gateway is usually a client-side networking issue that you will need to pursue with your local network administrator.
See more about connectivity architecture at https://docs.microsoft.com/azure/azure-sql/managed-instance/connectivity-architecture-overview'

    $SQLMI_PublicEndPoint_GatewayTestFailed = ' This usually indicates a client-side networking issue that you will need to pursue with your local network administrator.
See more about connectivity using Public Endpoint at https://docs.microsoft.com/en-us/azure/azure-sql/managed-instance/public-endpoint-configure'

    $AAD_login_windows_net = ' If you are using AAD Password or AAD Integrated Authentication please make sure you fix the connectivity from this machine to login.windows.net:443
This usually indicates a client-side networking issue that you will need to pursue with your local network administrator.'

    $AAD_login_microsoftonline_com = ' If you are using AAD Universal with MFA authentication please make sure you fix the connectivity from this machine to login.microsoftonline.com:443
This usually indicates a client-side networking issue that you will need to pursue with your local network administrator.'

    $AAD_secure_aadcdn_microsoftonline_p_com = ' If you are using AAD Universal with MFA authentication please make sure you fix the connectivity from this machine to secure.aadcdn.microsoftonline-p.com:443
This usually indicates a client-side networking issue that you will need to pursue with your local network administrator.'

    $error18456RecommendedSolution = ' This error indicates that the login request was rejected, the most common reasons are:
- Incorrect or empty password: Please ensure that you have provided the correct password.
- Database does not exist: Please ensure that the connection string has the correct database name.
- Insufficient permissions: The user does not have CONNECT permissions to the database. Please ensure that the user is granted the necessary permissions to login.
- Connections rejected due to DoSGuard protection: DoSGuard actively tracks failed logins from IP addresses. If there are multiple failed logins from a specific IP address within a period of time, the IP address is blocked from accessing any resources in the service for a pre-defined time period even if the password and other permissions are correct.'
    #endregion

    $SQLDBGateways = @(
    New-Object PSObject -Property @{Region = "Australia Central"; Gateways = ("20.36.105.0"); Affected20191014 = $false; TRs = ('tr1', 'tr2', 'tr3'); Cluster = 'australiacentral1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "Australia Central2"; Gateways = ("20.36.113.0"); Affected20191014 = $false; TRs = ('tr1', 'tr2', 'tr3'); Cluster = 'australiacentral2-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "Australia East"; Gateways = ("13.75.149.87", "40.79.161.1", "13.70.112.9"); Affected20191014 = $false; TRs = ('tr2', 'tr3', 'tr4'); Cluster = 'australiaeast1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "Australia South East"; Gateways = ("13.73.109.251", "13.77.48.10", "191.239.192.109"); Affected20191014 = $false; TRs = ('tr2', 'tr3', 'tr4'); Cluster = 'australiasoutheast1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "Brazil South"; Gateways = ("104.41.11.5", "191.233.200.14"); Affected20191014 = $true; TRs = ('tr11', 'tr12', 'tr15'); Cluster = 'brazilsouth1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "Canada Central"; Gateways = ("40.85.224.249", "52.246.152.0", "20.38.144.1"); Affected20191014 = $false; TRs = ('tr1', 'tr2', 'tr3'); Cluster = 'canadacentral1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "Canada East"; Gateways = ("40.86.226.166", "52.242.30.154"); Affected20191014 = $false; TRs = ('tr1', 'tr2', 'tr3'); Cluster = 'canadaeast1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "Central US"; Gateways = ("23.99.160.139", "13.67.215.62", "52.182.137.15", "104.208.21.1", "104.208.16.96"); Affected20191014 = $true; TRs = ('tr4', 'tr8', 'tr9'); Cluster = 'centralus1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "China East"; Gateways = ("139.219.130.35"); Affected20191014 = $false; TRs = ('tr2', 'tr3'); Cluster = 'chinaeast1-a.worker.database.chinacloudapi.cn'; }
    New-Object PSObject -Property @{Region = "China East 2"; Gateways = ("40.73.82.1"); Affected20191014 = $false; TRs = ('tr1', 'tr5', 'tr11'); Cluster = 'chinaeast2-a.worker.database.chinacloudapi.cn'; }
    New-Object PSObject -Property @{Region = "China North"; Gateways = ("139.219.15.17"); Affected20191014 = $false; TRs = ('tr2', 'tr3'); Cluster = 'chinanorth1-a.worker.database.chinacloudapi.cn'; }
    New-Object PSObject -Property @{Region = "China North 2"; Gateways = ("40.73.50.0"); Affected20191014 = $false; TRs = ('tr1', 'tr67', 'tr119'); Cluster = 'chinanorth2-a.worker.database.chinacloudapi.cn'; }
    New-Object PSObject -Property @{Region = "East Asia"; Gateways = ("191.234.2.139", "52.175.33.150", "13.75.32.4"); Affected20191014 = $true; TRs = ('tr4', 'tr8', 'tr9'); Cluster = 'eastasia1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "East US"; Gateways = ("191.238.6.43", "40.121.158.30", "40.79.153.12", "40.78.225.32"); Affected20191014 = $true; TRs = ('tr7', 'tr8', 'tr9'); Cluster = 'eastus1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "East US 2"; Gateways = ("191.239.224.107", "40.79.84.180", "52.177.185.181", "52.167.104.0", "104.208.150.3"); Affected20191014 = $true; TRs = ('tr10', 'tr8', 'tr9'); Cluster = 'eastus2-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "France Central"; Gateways = ("40.79.137.0", "40.79.129.1"); Affected20191014 = $false; TRs = ('tr1', 'tr7', 'tr8'); Cluster = 'francecentral1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "Germany Central"; Gateways = ("51.4.144.100"); Affected20191014 = $false; TRs = ('tr1', 'tr2', 'tr3'); Cluster = 'germanycentral1-a.worker.database.cloudapi.de'; }
    New-Object PSObject -Property @{Region = "Germany North East"; Gateways = ("51.5.144.179"); Affected20191014 = $false; TRs = ('tr1', 'tr2', 'tr3'); Cluster = 'germanynortheast1-a.worker.database.cloudapi.de'; }
    New-Object PSObject -Property @{Region = "Germany North"; Gateways = ("51.116.56.0"); Affected20191014 = $false; TRs = ('tr1', 'tr3', 'tr4'); Cluster = 'germanynorth1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "Germany West Central"; Gateways = ("51.116.152.0", "51.116.240.0", "51.116.248.0"); Affected20191014 = $false; TRs = ('tr1', 'tr3', 'tr4'); Cluster = 'germanywestcentral1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "India Central"; Gateways = ("104.211.96.159"); Affected20191014 = $false; TRs = ('tr1', 'tr3', 'tr16'); Cluster = 'indiacentral1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "India South"; Gateways = ("104.211.224.146"); Affected20191014 = $false; TRs = ('tr1', 'tr2', 'tr5'); Cluster = 'indiasouth1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "India West"; Gateways = ("104.211.160.80"); Affected20191014 = $false; TRs = ('tr41', 'tr42', 'tr54'); Cluster = 'indiawest1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "Japan East"; Gateways = ("191.237.240.43", "13.78.61.196", "40.79.184.8", "40.79.192.5", "13.78.106.224"); Affected20191014 = $true; TRs = ('tr4', 'tr5', 'tr9'); Cluster = 'japaneast1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "Japan West"; Gateways = ("191.238.68.11", "104.214.148.156", "40.74.97.10", "40.74.100.192"); Affected20191014 = $true; TRs = ('tr11', 'tr12', 'tr13'); Cluster = 'japanwest1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "Korea Central"; Gateways = ("52.231.32.42"); Affected20191014 = $false; TRs = ('tr1', 'tr10', 'tr118'); Cluster = 'koreacentral1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "Korea South"; Gateways = ("52.231.200.86"); Affected20191014 = $false; TRs = ('tr1', 'tr3', 'tr75'); Cluster = 'koreasouth1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "North Central US"; Gateways = ("23.98.55.75", "23.96.178.199", "52.162.104.33"); Affected20191014 = $true; TRs = ('tr7', 'tr8', 'tr9'); Cluster = 'northcentralus1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "North Europe"; Gateways = ("191.235.193.75", "40.113.93.91", "52.138.224.1", "13.74.104.113"); Affected20191014 = $true; TRs = ('tr7', 'tr8', 'tr9'); Cluster = 'northeurope1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "Norway East"; Gateways = ("51.120.96.0"); Affected20191014 = $false; TRs = ('tr1', 'tr45', 'tr14'); Cluster = 'norwayeast1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "Norway West"; Gateways = ("51.120.216.0"); Affected20191014 = $false; TRs = ('tr1', 'tr17', 'tr14'); Cluster = 'norwaywest1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "South Africa North"; Gateways = ("102.133.152.0", "102.133.120.2"); Affected20191014 = $false; TRs = ('tr1', 'tr2', 'tr4'); Cluster = 'southafricanorth1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "South Africa West"; Gateways = ("102.133.24.0"); Affected20191014 = $false; TRs = ('tr1', 'tr2', 'tr3'); Cluster = 'southafricawest1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "South Central US"; Gateways = ("23.98.162.75", "13.66.62.124", "104.214.16.32", "20.45.121.1", "20.49.88.1"); Affected20191014 = $true; TRs = ('tr10', 'tr8', 'tr9'); Cluster = 'southcentralus1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "South East Asia"; Gateways = ("23.100.117.95", "104.43.15.0", "40.78.232.3"); Affected20191014 = $true; TRs = ('tr7', 'tr8', 'tr4'); Cluster = 'southeastasia1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "Switzerland North"; Gateways = ("51.107.56.0", "51.107.57.0"); Affected20191014 = $false; TRs = ('tr1', 'tr2', 'tr54'); Cluster = 'switzerlandnorth1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "Switzerland West"; Gateways = ("51.107.152.0", "51.107.153.0"); Affected20191014 = $false; TRs = ('tr1', 'tr2', 'tr52'); Cluster = 'switzerlandwest1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "UAE Central"; Gateways = ("20.37.72.64"); Affected20191014 = $false; TRs = ('tr1', 'tr4'); Cluster = 'uaecentral1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "UAE North"; Gateways = ("65.52.248.0"); Affected20191014 = $false; TRs = ('tr1', 'tr4', 'tr9'); Cluster = 'uaenorth1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "UK South"; Gateways = ("51.140.184.11", "51.105.64.0"); Affected20191014 = $false; TRs = ('tr1', 'tr2', 'tr3'); Cluster = 'uksouth1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "UK West"; Gateways = ("51.141.8.11"); Affected20191014 = $false; TRs = ('tr1', 'tr2', 'tr4'); Cluster = 'ukwest1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "West Central US"; Gateways = ("13.78.145.25", "13.78.248.43"); Affected20191014 = $false; TRs = ('tr1', 'tr2', 'tr3'); Cluster = 'westcentralus1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "West Europe"; Gateways = ("191.237.232.75", "40.68.37.158", "104.40.168.105", "52.236.184.163"); Affected20191014 = $true; TRs = ('tr7', 'tr8', 'tr9'); Cluster = 'westeurope1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "West US"; Gateways = ("23.99.34.75", "104.42.238.205", "13.86.216.196"); Affected20191014 = $true; TRs = ('tr1', 'tr2', 'tr3'); Cluster = 'westus1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "West US 2"; Gateways = ("13.66.226.202", "40.78.240.8", "40.78.248.10"); Affected20191014 = $false; TRs = ('tr1', 'tr2', 'tr3'); Cluster = 'westus2-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "US DoD East"; Gateways = ("52.181.160.27"); TRs = ('tr3', 'tr4', 'tr5'); Cluster = 'usdodeast1-a.worker.database.usgovcloudapi.net'; }
    New-Object PSObject -Property @{Region = "US DoD Central"; Gateways = ("52.182.88.34"); TRs = ('tr1', 'tr4', 'tr7'); Cluster = 'usdodcentral1-a.worker.database.usgovcloudapi.net'; }
    New-Object PSObject -Property @{Region = "US Gov Iowa"; Gateways = ("13.72.189.52"); TRs = ('tr1'); Cluster = 'usgovcentral1-a.worker.database.usgovcloudapi.net'; }
    New-Object PSObject -Property @{Region = "US Gov Texas"; Gateways = ("52.238.116.32"); TRs = ('tr1', 'tr2', 'tr29'); Cluster = 'usgovsouthcentral1-a.worker.database.usgovcloudapi.net'; }
    New-Object PSObject -Property @{Region = "US Gov Arizona"; Gateways = ("52.244.48.33"); TRs = ('tr1', 'tr4', 'tr13'); Cluster = 'usgovsouthwest1-a.worker.database.usgovcloudapi.net'; }
    New-Object PSObject -Property @{Region = "US Gov Virginia"; Gateways = ("13.72.48.140"); TRs = ('tr1', 'tr3', 'tr5'); Cluster = 'usgoveast1-a.worker.database.usgovcloudapi.net'; }
)
function Write-AzSqlConnectivityResults {
    ($dnsResult, 
        [string] $dnsSource)
    Try {
        if ($dnsResult) {
            $msg = ' Found DNS record in ' + $dnsSource + ' (IP Address:' + $dnsResult.IPAddress + ')'
            Write-Verbose $msg
            #   [void]$summaryLog.AppendLine($msg)
        }
        else {
            Write-Verbose ' Could not find DNS record in' $dnsSource
        }
    }
    Catch {
        $msg = "Error at PrintDNSResults for " + $dnsSource + '(' + $_.Exception.Message + ')'
        TrackWarningAnonymously $msg
    }
}

function Add-AzSqlConnectivityRequiredFunction {
    # PowerShell Container Image Support Start

    if (!$(Get-Command 'Test-NetConnection' -errorAction SilentlyContinue)) {
        function Test-NetConnection {
            param(
                [Parameter(Position = 0, Mandatory = $true)] $HostName,
                [Parameter(Mandatory = $true)] $Port
            );
            process {
                $client = [TcpClient]::new()

                try {
                    $client.Connect($HostName, $Port)
                    $result = @{TcpTestSucceeded = $true; InterfaceAlias = 'Unsupported' }
                }
                catch {
                    $result = @{TcpTestSucceeded = $false; InterfaceAlias = 'Unsupported' }
                }

                $client.Dispose()

                return $result
            }
        }
    }

    if (!$(Get-Command 'Resolve-DnsName' -errorAction SilentlyContinue)) {
        function Resolve-DnsName {
            param(
                [Parameter(Position = 0)] $Name,
                [Parameter()] $Server,
                [switch] $CacheOnly,
                [switch] $DnsOnly,
                [switch] $NoHostsFile
            );
            process {
                # ToDo: Add support
                Write-Host "WARNING: Current environment doesn't support multiple DNS sources."
                return @{ IPAddress = [Dns]::GetHostAddresses($Name).IPAddressToString };
            }
        }
    }

    if (!$(Get-Command 'Get-NetAdapter' -errorAction SilentlyContinue)) {
        function Get-NetAdapter {
            param(
                [Parameter(Position = 0, Mandatory = $true)] $HostName,
                [Parameter(Mandatory = $true)] $Port
            );
            process {
                Write-Host 'Unsupported'
            }
        }
    }

    if (!$(Get-Command 'netsh' -errorAction SilentlyContinue) -and $CollectNetworkTrace) {
        Write-Host "WARNING: Current environment doesn't support network trace capture. This option is now disabled!"
        $CollectNetworkTrace = $false
    }

    # PowerShell Container Image Support End
}

function Test-AzSqlConnectivityRunningAsAdmin {
    if ($PSVersionTable.Platform -eq 'Unix') {
        if ((id -u) -eq 0) {
            $CustomerRunningInElevatedMode = $true
        }
    }
    else {
        $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            $CustomerRunningInElevatedMode = $true
        }
    }
}

function Test-AzSQlConnectivityDNS {
    #ValidateDNS 
    [cmdletbinding()]
    Param(
        [String] $Instance
    ) 

    Write-Verbose "Validating DNS record for $Instance"

    $DnsResults = [PSCustomObject]@{
        Hosts     = $null
        Cache     = $null
        DNSServer = $null
        OpenDNS   = $null
    }
    Try {
        Write-Verbose "Validating DNS record for $Instance from Hosts File"
        $DNSfromHosts = Resolve-DnsName -Name $Instance -CacheOnly -ErrorAction SilentlyContinue
        $DnsResults.Hosts = $DNSfromHosts
    }
    Catch {
        $_.Exception.Message 
        #  TrackWarningAnonymously 'Error at ValidateDNS from hosts file'
    }

    Try {
        Write-Verbose "Validating DNS record for $Instance from cache"
        $DNSfromCache = Resolve-DnsName -Name $Instance -NoHostsFile -CacheOnly -ErrorAction SilentlyContinue
        $DnsResults.Cache = $DNSfromCache
    }
    Catch {
        $_.Exception.Message 
        # TrackWarningAnonymously 'Error at ValidateDNS from cache'
    }

    Try {
        Write-Verbose "Validating DNS record for $Instance from dnsserver"
        $DNSfromCustomerServer = Resolve-DnsName -Name $Instance -DnsOnly -ErrorAction SilentlyContinue
        $DnsResults.DNSServer = $DNSfromCustomerServer
    }
    Catch {
        $_.Exception.Message 
        #  TrackWarningAnonymously 'Error at ValidateDNS from DNS server'
    }

    Try {
        Write-Verbose "Validating DNS record for $Instance from Open DNS"
        $DNSfromAzureDNS = Resolve-DnsName -Name $Instance -DnsOnly -Server 208.67.222.222 -ErrorAction SilentlyContinue
        $DnsResults.OpenDNS = $DNSfromAzureDNS
    }
    Catch {
        $_.Exception.Message 
        # TrackWarningAnonymously 'Error at ValidateDNS from Open DNS'
    }
    Write-Verbose "Found the following DNS results"
    Write-Verbose ($DnsResults | ConvertTo-Json | Out-String)
    $DnsResults
}

function Test-AzSQlConnectivityManagedInstance {
    #IsManagedInstance
    [OutputType('bool')]
    [cmdletbinding()]
    Param    
    ([String] $Server)
    
    [bool]((($Server.ToCharArray() | Where-Object { $_ -eq '.' } | Measure-Object).Count) -ge 4)
}

function Test-AzSQlConnectivitySqlOnDemand {
    #IsSqlOnDemand
    [OutputType('bool')]
    [cmdletbinding()]
    Param    
    ([String] $Server)
    [bool]($Server -match '-ondemand.')
}

function Test-AzSQlConnectivityPrivateLink {
    #HasPrivateLink
    [OutputType('bool')]
    [cmdletbinding()]
    Param ([String] $Server)

    [bool]((((Resolve-DnsName $Server) | Where-Object { $_.Name -Match ".privatelink." } | Measure-Object).Count) -gt 0)
}

function Set-AzSQlConnectivitySanitizeString {
    #SanitizeString
    ([String] $string) 
    ($string.Replace('\', '_').Replace('/', '_').Replace("[", "").Replace("]", "").Replace('.', '_').Replace(':', '_').Replace(',', '_'))
}

function Add-AzSqlConnectivitySummaryRecommendedAction {
    Param($key, $value)
    if ($global:summaryRecommendedAction) {
        $global:summaryRecommendedAction.Add($key,$value)
    }else{
        $global:summaryRecommendedAction = @{}
        $global:summaryRecommendedAction.Add($key,$value)
    }
}

function Add-AzSqlConnectivityResults {
    Param($key, $value)
    if ($global:AzSqlConnectivityResults) {
        $AzSqlConnectivityResults.Add($key,$value)
    }else{
        $global:AzSqlConnectivityResults = @{}
        $AzSqlConnectivityResults.Add($key,$value)
    }
}


function Test-AzSQlConnectivityToDatabase {
    #TestConnectionToDatabase
    [cmdletbinding()]
    Param(
        $Server, 
        $gatewayPort, 
        $Database, 
        $User, 
        $Password
    ) 

    Write-Verbose "Testing connecting to $Database database"
    Try {
        $masterDbConnection = [System.Data.SqlClient.SQLConnection]::new()
        $masterDbConnection.ConnectionString = [string]::Format("Server=tcp:{0},{1};Initial Catalog={2};Persist Security Info=False;User ID='{3}';Password='{4}';MultipleActiveResultSets=False;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;Application Name=Azure-SQL-Connectivity-Checker;",
            $Server, $gatewayPort, $Database, $User, $Password)
        $masterDbConnection.Open()
        Write-Verbose " The connection attempt succeeded $Database"
        Add-AzSqlConnectivityResults -key 'DatabaseConnection' -value $true
    }
    catch [System.Data.SqlClient.SqlException] {
        $ex = $_.Exception
        Switch ($_.Exception.Number) {
            18456 {
                if ($User -eq 'AzSQLConnCheckerUser') {
                    if ($Database -eq 'master') {
                        $msg = [string]::Format(" Dummy login attempt reached '{0}' database, login failed as expected.", $Database)
        Add-AzSqlConnectivityResults -key 'DatabaseConnection' -value $false
        Add-AzSqlConnectivityResults -key 'DatabaseConnectionMessage' -value $msg

                    }
                    else {
                        $msg = [string]::Format(" Dummy login attempt on '{0}' database resulted in login failure. This was either expected due to dummy credentials being used, or database does not exist, which also results in login failed.", $Database)
                        Add-AzSqlConnectivityResults -key 'DatabaseConnection' -value $false
                        Add-AzSqlConnectivityResults -key 'DatabaseConnectionMessage' -value $msg
                
                    }
                }
                else {

                    $msg = [string]::Format(" Login against database {0} failed for user '{1}'", $Database, $User)
                    Add-AzSqlConnectivityResults -key 'DatabaseConnection' -value $false
                    Add-AzSqlConnectivityResults -key 'DatabaseConnectionMessage' -value $msg
                    Add-AzSqlConnectivitySummaryRecommendedAction -key 18456 -value $error18456RecommendedSolution
                    
                   # TrackWarningAnonymously 'FailedLogin18456UserCreds'
                }
            }
            40532 {
                if ($_.Exception.Number -eq 40532 -and $gatewayPort -eq 3342) {
                    $msg = ' You seem to be trying to connect to MI using Public Endpoint but Public Endpoint may be disabled'
                    Add-AzSqlConnectivityResults -key 'DatabaseConnection' -value $false
                    Add-AzSqlConnectivityResults -key 'DatabaseConnectionMessage' -value $msg            
                    $msg = ' Learn how to configure public endpoint at https://docs.microsoft.com/en-us/azure/sql-database/sql-database-managed-instance-public-endpoint-configure'
                    Add-AzSqlConnectivitySummaryRecommendedAction -key 40532 -value $msg 
                   # TrackWarningAnonymously 'SQLMI|PublicEndpoint|Error40532'
                }
                else {
                    $msg = ' Connection to database ' + $Database + ' failed (error ' + $ex.Number + ', state ' + $ex.State + '): ' + $ex.Message
                    Add-AzSqlConnectivityResults -key 'DatabaseConnection' -value $false
                    Add-AzSqlConnectivityResults -key 'DatabaseConnectionMessage' -value $msg            
                   # TrackWarningAnonymously ('TestConnectionToDatabase|Error:' + $ex.Number + 'State:' + $ex.State)
                }
            }
            40615 {
                $msg = ' Connection to database ' + $Database + ' failed (error ' + $ex.Number + ', state ' + $ex.State + '): ' + $ex.Message
                Add-AzSqlConnectivityResults -key 'DatabaseConnection' -value $false
                Add-AzSqlConnectivityResults -key 'DatabaseConnectionMessage' -value $msg        
                Add-AzSqlConnectivitySummaryRecommendedAction -key 40615 -value $msg
                # TrackWarningAnonymously ('TestConnectionToDatabase|Error:' + $ex.Number + 'State:' + $ex.State)
            }
            default {
                $msg = ' Connection to database ' + $Database + ' failed (error ' + $ex.Number + ', state ' + $ex.State + '): ' + $ex.Message
                Add-AzSqlConnectivityResults -key 'DatabaseConnection' -value $false
                Add-AzSqlConnectivityResults -key 'DatabaseConnectionMessage' -value $msg        
               # TrackWarningAnonymously ('TestConnectionToDatabase|Error:' + $ex.Number + 'State:' + $ex.State)
            }
        }
    }
    Catch {
         
        # TrackWarningAnonymously 'TestConnectionToDatabase|Exception'
        Add-AzSqlConnectivityResults -key 'DatabaseConnection' -value $false
        Add-AzSqlConnectivityResults -key 'DatabaseConnectionMessage' -value $_.Exception.Message
    }
}

function Get-AzSqlConnectivityLocalNetworkConfiguration {
    if (![System.Net.NetworkInformation.NetworkInterface]::GetIsNetworkAvailable()) {
        throw "There's no network connection available!" 
        
    }

    $computerProperties = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
    $networkInterfaces = [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()

    Add-AzSqlConnectivityResults -key 'Network' -value 'Interface information for '$computerProperties.HostName'.'$networkInterfaces.DomainName

    foreach ($networkInterface in $networkInterfaces) {
        if ($networkInterface.NetworkInterfaceType -eq 'Loopback') {
            continue
        }

        $properties = $networkInterface.GetIPProperties()
        Add-AzSqlConnectivityResults -key "$($networkInterface.Name) Interface name" -value $networkInterface.Name
        Add-AzSqlConnectivityResults -key "$($networkInterface.Name) Interface description" -value $networkInterface.Description
        Add-AzSqlConnectivityResults -key "$($networkInterface.Name) Interface type" -value $networkInterface.NetworkInterfaceType
        Add-AzSqlConnectivityResults -key "$($networkInterface.Name) Operational status" -value $networkInterface.OperationalStatus
        Add-AzSqlConnectivityResults -key "$($networkInterface.Name) Unicast address list" -value  $([String]::Join([Environment]::NewLine + '  ', [System.Linq.Enumerable]::Select($properties.UnicastAddresses, [Func[System.Net.NetworkInformation.UnicastIPAddressInformation, IPAddress]] { $args[0].Address })))
        Add-AzSqlConnectivityResults -key "$($networkInterface.Name) DNS server address list" -value $([String]::Join([Environment]::NewLine + '  ', $properties.DnsAddresses))
    }
}

function Get-AzSqlConnectivityResults {
    $global:AzSqlConnectivityResults
    $global:AzSqlConnectivityResults = $null
}
function Get-AzSqlConnectivitySummaryRecommendedAction  {
    $global:summaryRecommendedAction
    $global:summaryRecommendedAction = $null
}

function Test-AzSqlConnectivityAffected20191014{
    #CheckAffected20191014
    Param ($gateway) 
    $isCR1 = $CRaddress -eq $gateway.Gateways[0]
    if ($gateway.Affected20191014) {
        Write-Host 'This region WILL be affected by the Gateway migration starting at Oct 14 2019!' -ForegroundColor Yellow
        if ($isCR1) {
            Write-Host 'and this server is running on one of the affected Gateways' -ForegroundColor Red
        }
        else {
            Write-Host 'but this server is NOT running on one of the affected Gateways (never was or already migrated)' -ForegroundColor Green
            Write-Host 'Please check other servers you may have in the region' -ForegroundColor Yellow
        }
    }
    else {
        Write-Host 'This region will NOT be affected by the Oct 14 2019 Gateway migration!' -ForegroundColor Green
    }
    Write-Host
}

function Test-AzSqlConnectivityMIPublicEndpoint {
    #RunSqlMIPublicEndpointConnectivityTests
    [cmdletbinding()]
    Param
($resolvedIPAddress) 
    Try {
        $msg = 'Detected as Managed Instance using Public Endpoint'
        Write-Verbose $msg 

       # TrackWarningAnonymously 'SQLMI|PublicEndpoint'

        Write-Verbose "Public Endpoint connectivity test $resolvedIPAddress"
        $testResult = Test-NetConnection $resolvedIPAddress -Port 3342 -WarningAction SilentlyContinue

        if ($testResult.TcpTestSucceeded) {
            Write-verbose 'TCP test succeed'
            PrintAverageConnectionTime $resolvedIPAddress 3342
            $msg = ' Gateway connectivity to ' + $resolvedIPAddress + ':3342 succeed'
            Add-AzSqlConnectivityResults -key 'MIPublicEndpoint' -value $true
            Add-AzSqlConnectivityResults -key 'MIPublicEndpointMessage' -value $msg
        }
        else {
            Write-Verbose 'TCP test FAILED'
            $msg = 'Gateway connectivity to ' + $resolvedIPAddress + ':3342 FAILED'
            Add-AzSqlConnectivityResults -key 'MIPublicEndpoint' -value $false
            Add-AzSqlConnectivityResults -key 'MIPublicEndpointMessage' -value $msg
            $msg = ' Please make sure you fix the connectivity from this machine to ' + $resolvedIPAddress + ':3342 (SQL MI Public Endpoint)'
            Add-AzSqlConnectivitySummaryRecommendedAction -key 'MiPublicEndpointConnection' -value $msg

            $msg = $SQLMI_PublicEndPoint_GatewayTestFailed
            Add-AzSqlConnectivitySummaryRecommendedAction -key 'MiPublicEndpointConnectionMessage' -value $msg

            #TrackWarningAnonymously 'SQLMI|PublicEndPoint|GatewayTestFailed'
        }
    }
    Catch {
        Add-AzSqlConnectivityResults -key 'MIPublicEndpoint' -value $false
        Add-AzSqlConnectivityResults -key 'MIPublicEndpointMessage' -value "Error at RunSqlMIPublicEndpointConnectivityTests - $($_.Exception.Message)" 
        #TrackWarningAnonymously 'RunSqlMIPublicEndpointConnectivityTests|Exception'
    }
}

function Test-AzSqlConnectivityMIVNet{
    #RunSqlMIVNetConnectivityTests
    [cmdletbinding()]
    Param($resolvedIpAddress) 
    Try {
        Write-Verbose 'Detected as Managed Instance' 
        #TrackWarningAnonymously 'SQLMI|PrivateEndpoint'
        Write-Verbose 'Running Gateway connectivity tests'
        $testResult = Test-NetConnection $resolvedIpAddress -Port 1433 -WarningAction SilentlyContinue

        if ($testResult.TcpTestSucceeded) {
            Write-Verbose 'TCP test succeed'
            PrintAverageConnectionTime $resolvedIpAddress 1433
            $msg =  'Gateway connectivity to ' + $resolvedIpAddress + ':1433 Succeeded'
            Add-AzSqlConnectivityResults -key 'MIPublicVNet' -value $true
            Add-AzSqlConnectivityResults -key 'MIPublicVNetMessage' -value $msg
        }
        else {
            Write-Verbose 'TCP test FAILED'
            Write-Verbose ' Trying to get IP routes for interface:' $testResult.InterfaceAlias
            Get-NetAdapter $testResult.InterfaceAlias -ErrorAction SilentlyContinue -ErrorVariable ProcessError | Get-NetRoute
            If ($ProcessError) {
                Write-Verbose 'Could not to get IP routes for this interface'
            }

            $msg = ' Gateway connectivity to ' + $resolvedIpAddress + ':1433 FAILED'

            Add-AzSqlConnectivityResults -key 'MIPublicVNet' -value $false
            Add-AzSqlConnectivityResults -key 'MIPublicVNetMessage' -value $msg
            Add-AzSqlConnectivitySummaryRecommendedAction -key 'MIPublicVNet' -value $msg


            $msg = ' Please fix the connectivity from this machine to ' + $resolvedIpAddress + ':1433'
            Add-AzSqlConnectivitySummaryRecommendedAction -key 'MIPublicVNetMessage' -value $msg
            Add-AzSqlConnectivitySummaryRecommendedAction -key 'MIPublicVNetMessageDetail' -value $SQLMI_GatewayTestFailed
            
            #TrackWarningAnonymously 'SQLMI|GatewayTestFailed'

        }
    }
    Catch {
        Add-AzSqlConnectivityResults -key 'MIPublicVNet' -value $false
        Add-AzSqlConnectivityResults -key 'MIPublicVNetMessage' -value "Error at RunSqlMIVNetConnectivityTests $($_.Exception.Message)"
        #TrackWarningAnonymously 'RunSqlMIVNetConnectivityTests|Exception'
    }
}