Function Convert-BytesToSize
    {[CmdletBinding()]
    Param([parameter(Mandatory=$False,Position=0)]$Size)
    if ($Size -gt 1){
        [int64]$Size = $Size
        Switch ($Size){
            {$_ -gt 1TB}{
                $NewSize = “$([math]::Round(($_ / 1TB),2))TB”
                Break}
            {$_ -gt 1GB}{
                $NewSize = “$([math]::Round(($_ / 1GB),2))GB”
                Break}
            {$_ -gt 1MB}{
                $NewSize = “$([math]::Round(($_ / 1MB),2))MB”
                Break}
                Default{
                $NewSize = “$([math]::Round(($_ / 1KB),2))KB”
                Break}}}
    else{
        $NewSize = $Size}
    Return $NewSize}

#region config
$ReportedItems = Get-Content "C:\gidi\ReportedTopics.json" | ConvertFrom-Json #this file contain easy to read descriptions for each issue that can be found in the report.
$UNCLastRunReport = "C:\gidi\LastReports\LastRunReport.xml" #use to store the last report, and compare to see if there's new items in the current run
$MaximumExpectedCnameTTL = (New-TimeSpan -Minutes 5)
$DiskLimitShouldBeLowerThenDiskUsageTimesX = 6
$CdotClusters = 'Cluster1FQDN','Cluster2FQDN','Cluster3FQDN' # change to your cluster names
$FileServersToCheckSPNsFor = "FileServer1" #this created for a legacy file server we had. that we wanted SPN related best practices to be enforced on
$FileServersDomainToCheckSPNsFor = "contoso.local" # for the above server again
$EmailtoIR = "incdent@contoso.local" #where to send email when a new breach is found
$Emailto = "SuperAdmin@contoso.local" # where to send a report every time the script has run
$MailFROM = "postmaster@contoso.local"
$SmtpServer = "smtp.contoso.local" #need to be allowed to send anonymous emails via this sever 
$DnsServer = "contoso.local" #whatever account running this script need to have DNS read only access - we used the domain name as all of them are also DNS servers 
$Cdotcred = Import-Clixml -Path  "C:\gidi\shh_thats_a_secret\Credentials\Cdot_Cred_$($env:USERNAME).xml" -ErrorVariable myerror -ErrorAction SilentlyContinue #see bellow
<#
use the following command running PS as the same service account that going to run this script
in order to save to an encrypted file the credentials that will be used to connect to the NetApp Cluster (this account need read zapi access on the clusters)
I also run it with my own user.  So I have two files - one for the service account and one for myself for when i troubleshoot

Get-Credential | Export-Clixml -Path "C:\gidi\shh_thats_a_secret\Credentials\Cdot_Cred_$($env:USERNAME).xml"
#>


#Exclusion - these done as some best practiced been breached for a reason
$UsersThatAllowedToBeUsingOldCIFSProtocols = "NT AUTHORITY\ANONYMOUS LOGON","Contoso\Administrator" #Exemples only. i had some known smb1 users...
$QtreesIntendToBeWithoutQuota = "HF_" #we didn't enforce quota only on some Home folder qtrees
$EnableQuotaBreachesReport = $true
#endregion config

#import module, connect to clusters and initialize report variable
Import-Module DataONTAP
$clustersSessions = Connect-NcController ($CdotClusters) -HTTPS -Credential $CdotCred -ErrorVariable gidiout
$Report = @{}

#region Check that CIFS shares matched between Prod and DR
$Report.CifsSharesThatDontHaveExactMatchInDR = Get-NcCifsShare -Controller $clustersSessions | select Vserver,ShareName,
        @{Name='ShareProperties';Expression={$($_.ShareProperties | sort) -join ';'}}, 
        @{Name='Acl';Expression={$_.Acl -join ';'}} | Group-Object path,sharename,ACL,ShareProperties | ? count -lt 2 | select -ExpandProperty Group | sort ShareName   # Will only output issues 
#endregion Check that CIFS shares matched between Prod and DR

#region check if there’s SMB1 connections
$Report.SessionsUsingOldCIFSProtocols = Get-NcCifsSession -Controller $clustersSessions | ? {$_.ProtocolVersion -eq "smb1" -or $_.AuthMechanism -match "ntlm"} | select vserver,WindowsUser,Address,AuthMechanism,ProtocolVersion -Unique
$Report.SessionsUsingOldCIFSProtocols = $Report.SessionsUsingOldCIFSProtocols | ? WindowsUser -NotIn $UsersThatAllowedToBeUsingOldCIFSProtocols
#endregion check if there’s SMB1 connections

#region check that Cname has delegation set and low TTL
$SVMsCifsServer = Get-NcCifsServer -Controller $clustersSessions
$cnameInDomains = $(Get-ADForest).domains |% {Get-DnsServerResourceRecord  -ZoneName $_ -ComputerName $DnsServer -RRType CName | select -ExpandProperty RecordData HostName,TimeToLive} #You need DNS read only access to do this
$cnamePointingToSVMs = $SVMsCifsServer.CifsServer + $FileServersToCheckSPNsFor | % {$cnameInDomains | ? HostNameAlias -like "$($_)*" }
$SPNrefferals = $SVMsCifsServer | % {setspn -Q */$($_.CifsServer) -T $_.domain}  # Searching SPN's delegated to that storage object
$SPNrefferals += setspn -Q */$FileServersToCheckSPNsFor -T $FileServersDomainToCheckSPNsFor #this created for a legacy file server we had. that we wanted SPN related best practices to be enforced on

$Report.CNAMEsWithMissingValidSPNs = $cnamePointingToSVMs | ? {-not ($SPNrefferals  | Select-String $_.HostName)} | select HostName,HostNameAlias
$Report.CNAMEsWithMissingValidSPNs | % {$_ | ? HostName|  add-member -type NoteProperty -Name "Add the SPN manually with the following command" -Value "SETSPN -S ""HOST/$($_.HostName)"" $(($_.HostNameAlias -split '\.')[0])"}
$Report.CNAMEsPointingToSVMsWithHighTTL = $cnamePointingToSVMs | ? TimeToLive -gt $MaximumExpectedCnameTTL | select HostName,TimeToLive
#endregion check that Cname has delegation set and low TTL

#region check Qtree and Quota settings
$LiveQtrees = Get-NcQtree  -Controller $clustersSessions | ? status -eq "normal" | ? Qtree 
$LiveQtrees | % {$_ | Add-Member -Type NoteProperty -Name "QtreePath" -Value "/vol/$($_.volume)/$($_.Qtree)"}
$Quota = Get-NcQuota -Controller $clustersSessions
$QuotaReport = Get-NcQuotaReport -Controller $clustersSessions
$QuotaStatusForVolumesWithQuotaSetOnQtrees = $Quota | select -Unique Vserver,Volume | Get-NcQuotaStatus -Controller $clustersSessions
$Report.LiveQtreesWithoutQuota = $LiveQtrees | ? Qtreepath -NotIn $Quota.QuotaTarget | ? Qtree -NotMatch $QtreesIntendToBeWithoutQuota | select vserver,Volume,Qtree
$Report.VolumesWithQuotaSetOnQtreeButOffOnVolume = $QuotaStatusForVolumesWithQuotaSetOnQtrees | ? Status -eq "off"  | select vserver,Volume,Status
$Report.QuotaErrors = $QuotaStatusForVolumesWithQuotaSetOnQtrees | select -ExpandProperty QuotaErrorMsgs | ConvertFrom-Csv -Header "Errors"
if($EnableQuotaBreachesReport)
{ 
    $Report.BreachedQuotas = $QuotaReport | ? {[int64]$_.DiskUsed -gt [int64]$_.SoftDiskLimit} | select Vserver,QuotaTarget
}
#Calculate if Quota set correctly. in our config - check that it's almost 90% for SoftDiskLimit and 80% for Threshold 
$Quota |  ` 
% {
    $ErrorActionPreference = 'SilentlyContinue'  #ignore errors from here
    $QuotaThresholdAreWitihinStd = $false
    if  ( `
        ([int64]($_.SoftDiskLimit) -lt [int64]($_.DiskLimit)*0.93) -and `
        ([int64]($_.SoftDiskLimit) -gt [int64]($_.DiskLimit)*0.87) -and `
        ([int64]($_.Threshold)     -lt [int64]($_.DiskLimit)*0.83) -and `
        ([int64]($_.Threshold)     -gt [int64]($_.DiskLimit)*0.77) `  
        ) 
    {
            $QuotaThresholdAreWitihinStd = $true
    }
    $ErrorActionPreference = 'Continue'  #stop ignoring errors from here
    $_ | `
    add-member -MemberType NoteProperty -PassThru -Name "The90PercentFromDiskLimit" -value $([int64]([int64]($_.DiskLimit) * 0.90)) | `
    add-member -MemberType NoteProperty -PassThru -Name "The80PercentFromDiskLimit" -value $([int64]([int64]($_.DiskLimit) * 0.80)) | `
    Add-Member -MemberType NoteProperty -PassThru -Name "QuotaThresholdAreWitihinStd" -Value $QuotaThresholdAreWitihinStd | `
    Add-Member -MemberType NoteProperty -Name "DiskUsed" -Value $($QuotaReport | ? QuotaTarget -eq $_.QuotaTarget).DiskUsed
}
$Report.QuotaSoftLimitAndThresholdNeedAlignment = $Quota | ? QuotaThresholdAreWitihinStd -eq $false | sort QuotaTarget | select QuotaTarget,`
@{ Label="Current DiskLimit" ; Expression = {Convert-BytesToSize (($_.DiskLimit)*1024)}},`
@{ Label="Current SoftDiskLimit" ; Expression = {Convert-BytesToSize (($_.SoftDiskLimit)*1024)}},`
@{ Label="Suggested SoftDiskLimit" ; Expression = {Convert-BytesToSize (($_.The90PercentFromDiskLimit)*1024)}},`
@{ Label="Current Threshold" ; Expression = {Convert-BytesToSize (($_.Threshold)*1024)}},`
@{ Label="Suggested Threshold" ; Expression = {Convert-BytesToSize (($_.The80PercentFromDiskLimit)*1024)}},`
@{ Label="Current DiskUsed" ; Expression = {Convert-BytesToSize (($_.DiskUsed)*1024)}}


$Report.QuotaLimitIsTooHigh = $QuotaReport | ? {(([int64]$_.DiskUsed + 1GB) * $DiskLimitShouldBeLowerThenDiskUsageTimesX ) -lt [int64]$_.DiskLimit} | sort QuotaTarget | select QuotaTarget,`
@{ Label="Current DiskLimit" ; Expression = {Convert-BytesToSize (($_.DiskLimit)*1024)}},`
@{ Label="Current SoftDiskLimit" ; Expression = {Convert-BytesToSize (($_.SoftDiskLimit)*1024)}},`
@{ Label="Current Threshold" ; Expression = {Convert-BytesToSize (($_.Threshold)*1024)}},`
@{ Label="Current DiskUsed" ; Expression = {Convert-BytesToSize (($_.DiskUsed)*1024)}}


$Report.QuotaNotYetCalculated = $Quota | ? QuotaTarget -NotIn $QuotaReport.QuotaTarget | select nccontroller,QuotaTarget,`
@{ Label="Current DiskLimit" ; Expression = {Convert-BytesToSize (($_.DiskLimit)*1024)}}

#endregion check Qtree and Quota settings

#region check fpolicy
$Report.FpolicyIsSetButNotConnected = Get-NcFpolicyServerStatus -Controller $clustersSessions | ? status -ne "connected" | select nccontroller,vserver,node,FpolicyServer,DisconnectedSinceDT,DisconnectReason
$Report.FpolicyPolicyIsNotEnabled = Get-NcFpolicyStatus -Controller $clustersSessions | ? Enabled -ne $true
#endregion check fpolicy

#region check volume and AGGR settings
$Volumes = Get-NcVol -Controller $clustersSessions
$Aggr = Get-NcAggr -Controller $clustersSessions
$SnapMirrors = Get-NcSnapmirror -Controller $clustersSessions
$Report.SnapshotReserveIsNotSetOnAllTheCopiesEqually =  ($SnapMirrors | ? { ($_.DestinationVserver -match "DR|RB|BK") } | group SourceVolume | ? {($_.group.DestinationVserver | select -Unique).count -ne 3 -or $_.group.IsHealthy -contains $false} | ? name -NotMatch "_Root")
$Report.TheVolumeSnapshotReserveIsSetToTooHigherThanTheCurrentSnapshotUsage = $Volumes | select name,vserver -ExpandProperty VolumeSpaceAttributes | ? {$_.PercentageSnapshotReserve  -gt 5 -and $_.PercentageSnapshotReserveUsed -lt 30} | select name,vserver,nccontroller,PercentageSnapshotReserve,PercentageSnapshotReserveUsed


$Report.SVMRootVolumeDontHaveCopiesOnAllNodes = #$Volumes | select *
$Report.SnapMirroredVolumesThatDontHaveHealthyCopiesOnDRBKAndRBSVMs = ($SnapMirrors | ? { ($_.DestinationVserver -match "DR|RB|BK") } | group SourceVolume | ? {($_.group.DestinationVserver | select -Unique).count -ne 3 -or $_.group.IsHealthy -contains $false} | ? name -NotMatch "_Root")
#endregion check volume and AGGR settings

#region check error counters
<# Under DEV Gidi May 2019
$NetPorts = Get-NcNetPort -Controller $clustersSessions 
$NetPorts = invoke-nc -Controller $clustersSessions 
Invoke-NcSsh -Controller $clustersSessions -Command "version"
#>
#endregion check error ocunters

#region check ems messages
<# Under DEV Gidi May 2019
Get-NcEmsMessage -Controller $clustersSessions
Get-NcEmsStatus -Controller $clustersSessions | ? severity -ne "info" |  ? severity -ne "debug" |  ? severity -ne "notice" | ? Indications -gt 0 | ? LastTimeOccurredDT -GT ((get-date).adddays(-1)) | sort Indications | select StatStartingTimeDT,LastTimeOccurredDT,MessageName,Node,Indications,Severity | ft
#>
#endregion check ems messages

#region email 

#load descriptions from file for items with errors
$RpoertedItemsWithErrors = $ReportedItems | ? {$Report.($_.name)}

#initalize vars
$Html = @()
$EmailSubject = "Cdot standard enforcment script found " 
$EmailSubject += Switch($($RpoertedItemsWithErrors.count))
{
     0{"no errors - GREEN"}
     1{"an error - AMBER"}
     2{"an error - AMBER"}
     default{"$_ errors - RED"}
}
$resultsHeader = @"
		<style>
		TABLE {border-width: 1px;border-style: solid;border-color: black;border-collapse: collapse;}
		TH {border-width: 1px;padding: 3px;border-style: solid;border-color: black;background-color: #6495ED;}
		TD {border-width: 1px;padding: 3px;border-style: solid;border-color: black;}
		</style> 
"@

#prepare summery
$Html += $ReportedItems | select description | ConvertTo-Html -as Table -Fragment -PreContent ‘<h2>Report Summery</h2>’ | Out-String
$RpoertedItemsWithErrors.description | %{$Html[0]= $Html[0] -replace "<td>$_</td>","<td style=""background-color:red"">$_</td>"}

#append tables with errors
$Report.keys | ?{$Report.$_} | %{$Html += $Report.$_ | ConvertTo-Html -AS Table -Fragment -PreContent $("<br><br><br><h3>$(($ReportedItems | ? Name -eq $_).LongDescription)</h3>") | Out-String}

#send email as report
$Html = ConvertTo-Html -Body $Html  -Head $resultsHeader
Send-MailMessage -SmtpServer $smtpserver -FROM $MailFROM -to $Emailto -Subject $EmailSubject -BodyAsHtml  $([string]$Html) -ErrorVariable myerror  -ErrorAction SilentlyContinue 

#Import last report to XML
$LastRunReport = import-Clixml $UNCLastRunReport 
#Export current report to XML
$Report | Export-Clixml $UNCLastRunReport 

#Run on all types of monitored issues
foreach ($ReportKey in ($Report.keys | ?{$Report.$_})) {
    # compare if ther's addition from last report
    $IRinfo = (Compare-Object -ReferenceObject @($Report.$ReportKey| Select-Object) -DifferenceObject @($LastRunReport.$ReportKey | Select-Object) | ?  SideIndicator -eq "<=").InputObject
    if($IRinfo)
    {
        #Prepare and send an IR email for each found issue
        $IRinfo = @"
Hello
The Cdot standard enforcement script running on Server_Name found $(($ReportedItems | ? Name -eq $ReportKey).LongDescription):
                        
$($IRinfo | out-string) 
                        
If you require any assistance, please consult the product manual, incident management doc. or a member of the server team.
Regards,
The storage admin
"@
        $ITSubject = "The Cdot standard enforcement script found $(($ReportedItems | ? Name -eq $ReportKey).Description)"
        Send-MailMessage -SmtpServer $smtpserver -FROM $MailFROM  -to $EmailtoIR -Subject $ITSubject -Body $([string]$IRinfo) -ErrorVariable myerror  -ErrorAction SilentlyContinue 
    }
}
#endregion email 