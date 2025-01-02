
<# Docs for API

 https://github.com/ssllabs/ssllabs-scan/blob/master/ssllabs-api-docs-v4.md

#>

[System.Uri] $Urlbase = "https://api.ssllabs.com/api/v4"

Function Invoke-SSLLabsRegister {

param (
        [Parameter(Mandatory = $true)] [string] $Email
	  , [Parameter(Mandatory = $true)] [string] $FirstName
	  , [Parameter(Mandatory = $true)] [string] $LastName
	  , [Parameter(Mandatory = $true)] [string] $Organization	  
)

$body = @{
    firstName = $FirstName
    lastName = $LastName
    email = $Email
    organization = $Organization
    } | ConvertTo-Json

Invoke-RestMethod -Uri "$urlbase/register" -Method Post -ContentType 'application/json' -Body $body
}

Function Invoke-SSLLabsAnalyzeHost {

param (
      [Parameter(Mandatory = $true)] [string] $email 
    , [Parameter(Mandatory = $true)] [string[]] $Fqdns
)

$pending_states = ("IN_PROGRESS","DNS")

foreach($fqdn in $fqdns) {

    $fqdnClean = $fqdn.ToString().Trim().Trim('.')
    $urlAnalyze =  "$Urlbase/analyze?host={0}&publish=off&fromCache=on&all=done" -f $fqdnClean
    $output_complete = $false

    do {	
        try {            
            $ret = Invoke-WebRequest -Uri $urlAnalyze -Method  Get -Headers @{email = $email} -UseBasicParsing

            $result = ConvertFrom-Json  $ret.Content 
		
            if($pending_states -contains $result.status) {
                Write-Host "Pausing for $($result.status) of $fqdnClean"
                Start-Sleep -Seconds 30
            } else {                
		        # Use an array here so that we can make sure the endpoint enumeration has at least one record to loop through, even for failed scans
		        $endpoints = @()
		        $endpoints += $result.endpoints
		
                foreach($endpoint in $endpoints) {

                    $output = New-Object pscustomobject

                    # parent props
                    foreach($p in ("host","testTime","port","status","statusMessage")) {
                        $output | Add-Member -NotePropertyName $p -NotePropertyValue $result."$p"
                    }

                    if($endpoint.grade -eq "T") {
                        Write-Verbose $result
                    }

                    # endpoint props
                    foreach($p in ("grade","ipAddress","serverName")) {
                        $output | Add-Member -NotePropertyName $p -NotePropertyValue $endpoint."$p"
                    }

                    # cert props
                    # peculiar way of having to get the leaf cert presented by this endpoint
                    if($cert = $result.certs | ?{$_.id -eq $endpoint.details.certChains[0].certIds[0]}) {
                        foreach($p in ("subject","issuerSubject","notBefore","notAfter")) {
                            $output | Add-Member -NotePropertyName $p -NotePropertyValue $cert."$p"
                        }
                    }
                    $output_complete = $true

                    Write-Output $output
                }
                Start-Sleep -Seconds 10
            }

        } catch [System.Net.WebException] {
            if($_.Exception.Response) {
                $s = $_.Exception.Response.GetResponseStream()
                $s.Position = 0;
                $sr = New-Object System.IO.StreamReader($s)
                $err = $sr.ReadToEnd()
                $sr.Close()
                $s.Close()
            }

            if($err) {
                Write-Warning ("[{2}] HTTP: {0} - {1}" -f $_.Exception.Response.StatusCode,$err,$fqdn)
            }

            if((429,529) -contains $_.Exception.Response.StatusCode) {
                Write-Warning "Sleeping for a bit ...."
                Start-Sleep -Seconds 60
            }
        }
    
    } until ($result.host -eq $fqdnClean -and $pending_states -notcontains $result.status)

    if(-not $output_complete) {
        Write-Verbose $fqdn
    }
}
}
