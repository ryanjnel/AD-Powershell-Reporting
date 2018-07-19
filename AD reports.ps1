# Compiled by Nel.Ryan@microsoft.com. Some scripts were already created and simply added to this. 
# Special Thanks to Jimmy.Fitzsimmons@microsoft.com; doduval@microsoft.com and jeremy@jhouseconsulting.com for contributing to this up to this point. 

<# The script outputs the following reports, to modify the code, press CTRL + F and lookup the report number you would like to modify EG: if you want to view or modify code for script 19 using below index, perform a search for "report 19"
 
1.  Windows Server Computer Objects left in the default Computers OU. Script output file: ComputersleftinDefaultOU.csv
2.  Computer objects Password last set older than x days. Script output file: ComputersPasswordNotSet180Days.csv
3.  Computer Objects with password never expires configured. Script output file: ComputersPasswordNeverExpires.csv
4.  Computer objects with Kerberos Preauthentication disabled Script output file: ComputersKerberosPreauthdisabled.csv
5.  Computer objects found with SID history. Script output file: ComputersWithSIDhistory.csv
6.  Computer Objects in a Disabled State. Script output file: DisabledComputerObjects.csv
7.  Computer objects last logon to domain older than x days. Script output file: ComputersLastLoggedOn180Days.csv
8.  Computer Objects with DES encryption Only. Script output file: Computersusedeskeyonly.csv
9.  User Objects in a Disabled State. Script output file: UsersDisabled.csv 
10. User Objects with the PasswordNotRequired Flag set to True. Script output file: UserObjectsPasswordNotRequired.csv
11. User Objects with the PasswordNeverExpires Flag set to True. Script output file: UsersPasswordNeverExpires.csv
12. User objects last logon to domain older than x days. Script output file: UsersNotloggedon180Days.csv
13. User objects Password last set older than x days. Script output file: UsersPasswordolder180Days.csv
14. User objects with Kerberos Preauthentication disable. Script output file: UsersKerberosPreauthdisabled.csv
15. User Objects Found with SIDHistory. Script output file: usersWithSIDhistory.csv
16. User Objects with DES encryption Only. Script output file: UsersusedesEncryptionTypesOnly.csv
17. Group Objects Found with SIDHistory. Script output file: GroupswithSIDHistory.csv
18. AD Site Count Per AD SITE Link. Script output file: Sitecountpersitelink.csv
19. AD Site Links that contain only 1 or 0 ADsites. Script output file: Sitelinkswithoutsites.csv
20. Displays the AD sites inside the AD sitelinks. Script output file: Sitesinsitelinks.csv
21. Displays all AD sites that are not contained within a site link. Script output file: UnlinkedSites.csv
22. AD Sites with No AD subnets linked. Script output file: Siteswithnosubnets.csv
23. AD Subnets that are not linked to any AD site. Script output file: unlinkedsubnets.csv
24. Client IP addresses that are not associated to an AD subnet (missing AD subnets). Script output file: MissingADSubnets.csv
25. Displays all Unlinked Group Policy Objects. Script output file: UnLinkedGPOS.csv
26. Displays Status of all GPO's (DIsabled GPO's). Script output file: GPOSTATUS.CSV
27. Displays Built-in privileged AD GROUPS Membersof. Script output file: PrivilegedUsers.csv

#>
 


#Creates Directory that will contain all the AD Reports#
New-Item -Path "$env:USERPROFILE\Desktop" -ItemType "Directory" -Name "AD REPORTS" -ErrorAction SilentlyContinue
  
#Global Variables that is used by the PS commands below# 

$ReportFolder = "$env:USERPROFILE\Desktop\AD REPORTS" # Path of CSV Report Output  #
$OlderthanDays = "-180" # Today - x days is seen as a dormant account (user and computer objects) #

#Removes Previous versions of CSV files#
Remove-Item "$ReportFolder\*" -Include *.CSV  -Recurse 


#########################################
#										#
#		AD OBJECTS REPORTING			#
#										#
#########################################

#S Report 1 
# Windows Server Computer Objects left in the default Computers OU. This ensures that new objects that are joined to the domain have been moved to the correct OU's to have the appropriate group policies applied#
$S1 = $DefaultcomputersOU = (Get-ADdomain).computerscontainer 
Get-ADComputer -Filter * -Properties Operatingsystem,created,enabled -SearchBase $DefaultcomputersOU | select Name,Operatingsystem,created,enabled | Export-Csv "$reportfolder\ComputersleftinDefaultOU.csv" -NoTypeInformation

# Report 2 
# Computer objects Password last set older than x days. This report can assist with identifying computer objects that are dormant, can can be disabled or deleted #
$d = [DateTime]::Today.AddDays($OlderthanDays)
Get-ADComputer -Filter 'PasswordLastSet -lt $d' -Properties PasswordLastSet | Export-Csv "$reportfolder\ComputersPasswordNotSet180Days.csv" -delimiter ";" -NoTypeInformation

# report 3 
# Computer Objects with password never expires configured. This report can assist with identifying computer objects that are dormant, can can be disabled or deleted # #
Get-ADComputer -Filter 'useraccountcontrol -band 65536' -Properties useraccountcontrol,PasswordlastSet,PasswordNeverExpires,enabled | Select Name,enabled,PasswordNeverExpires,PasswordlastSet,Useraccountcontrol| Export-csv "$ReportFolder\ComputersPasswordNeverExpires.csv" -NoTypeInformation

# report 4
# Computer objects with Kerberos Preauthentication disabled. This report will highlight the risk of computer objects that does not require Kerberos Preauthentication#
get-adcomputer -filter * -properties DoesNotRequirePreAuth |where {$_.DoesNotRequirePreAuth -eq "TRUE"}| select SamAccountName,Doesnotrequirepreauth,Enabled | Export-Csv "$reportfolder\ComputersKerberosPreauthdisabled.csv" -NoTypeInformation

# report 5
# Computer objects found with SID History. This report will highlight computer objects found with SID history. Sid history can contribute to Kerberos Token Bloat, which can cause authentication errors against IIS #
Get-adcomputer -Properties * -Filter{Sidhistory -ne "**"} | select SamaccountName,Enabled | Export-Csv "$reportfolder\computersWithSIDhistory.csv" -notypeinformation

# report 6 
# All Computer Objects in a Disabled State. This report will show all computer objects in a disabled state, computers that are disabled in the domain should be considered for deletion #
Get-ADComputer –LDAPFilter '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=2))' | Select -Property Name,Enabled,DistinguishedName| Export-CSV "$ReportFolder\DisabledComputerObjects.csv" -NoTypeInformation -Encoding UTF8 

# report 7
# Computer objects last logon to domain older than x days. This report can assist with identifying Dormant computer objects that can be disabled, based on the lastlogon againt the domain #
$d = [DateTime]::Today.AddDays($OlderthanDays)
Get-ADComputer -filter 'LastLogonTimeStamp -lt $d' -Properties LastLogonTimeStamp,Enabled | Select-Object Name,@{n='LastLogonTimeStamp';e={[DateTime]::FromFileTime($_.LastLogonTimeStamp)}},Enabled | export-csv "$ReportFolder\ComputersLastLoggedOn180Days.csv"  -notypeinformation

# report 8
# Computer Objects with DES encryption Only. This report can assist with highlighting computers that use Des encryption only, which is a legacy encryption type that carries risk#
get-adcomputer -filter * -properties usedeskeyonly |where {$_.usedeskeyonly -eq "TRUE"}| select SamAccountName,Usedeskeyonly,Enabled | export-csv "$reportfolder\computersusedeskeyonly.csv" -Notypeinformation 

# report 9
# User Objects in a Disabled State. This report will highlight all user objects in a disabled state. Disabled users should be moved to a isolated OU where access is delegated more strictly#
Search-ADAccount –AccountDisabled -UsersOnly | Select -Property Name,Samaccountname,enabled,DistinguishedName | Export-CSV "$ReportFolder\UsersDisabled.csv" -notypeinformation -Encoding UTF8 

# report 10
# User Objects with the PasswordNotRequired Flag set to True. This report will highlight all user objects that is set to not require a password. This is a risk to any organization and should be remediated in order for the account to confirm with a password policy.  #
Get-ADUser -Properties Name,Enabled,distinguishedname,useraccountcontrol,objectClass -LDAPFilter "(&(userAccountControl:1.2.840.113556.1.4.803:=32)(!(IsCriticalSystemObject=TRUE)))" | select Name,Enabled,SamAccountName,useraccountcontrol,distinguishedname | export-csv "$ReportFolder\UserObjectsPasswordNotRequired.csv" -notypeinformation 

# report 11
# User Objects with the PasswordNeverExpires Flag set to True This report will highlight all user objects that have their passwords set to never expire. Passwords set to never expire are prone to bruteforce attacks and poses a risk #
Get-ADUser -filter * -properties Name,SamaccountName,Passwordneverexpires,Enabled,Description,Title,physicalDeliveryOfficeName,employeeType,CanonicalName | where { $_.passwordNeverExpires -eq "true" -and $_.Name -ne "krbtgt" }| select Name,SamaccountName,Passwordneverexpires,Enabled,Description,Title,physicalDeliveryOfficeName,employeeType,CanonicalName | Export-csv -path "$ReportFolder\UsersPasswordNeverExpires.csv" -notypeinformation 

# report 12
# User objects last logon to domain older than x days. This report can assist to identify dormant user objects based on the last logon timestamp against the domain #
Get-ADUser -filter 'LastLogonTimeStamp -lt $d' -Properties LastLogonTimeStamp,Enabled | Select-Object Name,@{n='LastLogonTimeStamp';e={[DateTime]::FromFileTime($_.LastLogonTimeStamp)}},Enabled | Export-Csv "$ReportFolder\UsersNotloggedon180Days.csv" -NoTypeInformation

# report 13
# User objects Password last set older than x days This report can assist to identify dormant user objects based on the password last set date against the domain #
Get-ADUser -Filter 'PasswordLastSet -lt $d' -Properties PasswordLastSet | export-csv "$ReportFolder\UsersPasswordolder180Days.csv" -NoTypeInformation

# report 14
# User objects with Kerberos Preauthentication disabled This report will highlight the risk of computer objects that does not require Kerberos Preauthentication #
get-aduser -filter * -properties DoesNotRequirePreAuth |where {$_.DoesNotRequirePreAuth -eq "TRUE"}| select SamAccountName,Doesnotrequirepreauth,Enabled | Export-Csv "$reportfolder\UsersKerberosPreauthdisabled.csv" -NoTypeInformation

# report 15
# User objects found with SID history. This report will highlight user objects found with SID history. Sid history can contribute to Kerberos Token Bloat, which can cause authentication errors against IIS #
Get-aduser -Properties * -Filter{Sidhistory -ne "**"} | select SamaccountName,Enabled | Export-Csv "$reportfolder\usersWithSIDhistory.csv" -notypeinformation

# report 16
# User objects found to use Legacy Kerberos Encryption Types, that is less secure than more up to date encryption types. 
get-aduser -filter * -properties usedeskeyonly |where {$_.usedeskeyonly -eq "TRUE"}| select SamAccountName,Usedeskeyonly,Enabled | export-csv "$reportfolder\UsersusedesEncryptionTypesOnly.csv" -Notypeinformation 

# report 17
# Groups Found with SIDHistory # This report will highlight group objects found with SID history. Sid history can contribute to Kerberos Token Bloat, which can cause authentication errors against IIS #
Get-ADgroup -Properties * -Filter{Sidhistory -ne "**"} | select SamaccountName,SIDHISTORY | export-csv "$reportfolder\GroupswithSIDHistory.csv" -NoTypeInformation

###################################################
#						 						  #
#			AD SITES and Subnet reports 	      #
#						  						  #
###################################################

# Report 18
# AD Site Count Per AD SITE Link # THIS REPORT highlights Site links that are missing AD sites. A site link requires at least 2 or more sites to build a replication link between two sites
Get-ADObject -Filter {(objectClass -eq "sitelink")} -Searchbase (Get-ADRootDSE).ConfigurationNamingContext -Property Options, Cost, ReplInterval, SiteList, Schedule | Select-Object Name, @{Name="sitecount";Expression={$_.sitelist.count}} | Where {$_.sitecount -le "1"} | Export-Csv "$ReportFolder\Sitecountpersitelink.csv" -notypeinformation

# Report 19
# AD Site Links that contain only 1 or 0 ADsites # THIS REPORT highlights Site links that are missing AD sites. A site link requires at least 2 or more sites to build a replication link between two sites
Get-ADObject -Filter {(objectClass -eq "sitelink")} -Searchbase (Get-ADRootDSE).ConfigurationNamingContext -Property Options, Cost, ReplInterval, SiteList, Schedule | Select-Object Name, @{Name="sitecount";Expression={$_.sitelist.count}} | Where {$_.sitecount -le "1"} | Export-Csv "$ReportFolder\Sitelinkswithoutsites.csv" -notypeinformation

# Report 20
#Displays the AD sites inside the AD sitelinks# NOTE!: Increase the hashtable to include more sites if required Hashtable is configured to handle two sites per site link only!. This report will list all sites and their associated site links.
#Compare this report (AD SITES that are linked) to AD ALL AD SITES(Get-adreplicationsite -filter * | export-csv .\ALLADSITES.csv) to find AD sites that are not linked to an AD site link
Get-ADObject -Filter {(objectClass -eq "sitelink")} -Searchbase (Get-ADRootDSE).ConfigurationNamingContext -Property Options, Cost, ReplInterval, SiteList, Schedule | Select-Object Name, @{L='Sitelist_1'; E={$_.Sitelist[0]}},
@{L='Sitelist_2';E={$_.Sitelist[1]}} | Export-Csv -Path "$reportfolder\Sitesinsitelinks.csv" -NoTypeInformation 

# Report 21
#Displays all AD sites that are not contained within a site link# 
$UnlinkedSites = @()
$sites = Get-ADObject -Filter {(objectClass -eq "site")} -SearchBase (Get-ADRootDSE).ConfigurationNamingContext -Properties DistinguishedName | select name,DistinguishedName
foreach ($site in $sites)
{
    $siteDN = $site.DistinguishedName
    $siteName = $site.name
    $sitelinks = Get-ADReplicationSiteLink -Filter *| select -ExpandProperty sitesincluded
    if ($sitelinks -notcontains $siteDN)
    {
        $UnlinkedSite = New-Object PSObject  
        $UnlinkedSite | Add-Member NoteProperty -Name "SiteName" -Value $siteName -Force
        $UnlinkedSite | Add-Member NoteProperty -Name "SiteDN" -Value $siteDN -Force
        $UnlinkedSites += $UnlinkedSite
    }
}
$UnlinkedSites | Export-Csv "$reportfolder\UnlinkedSites.csv" -NoTypeInformation

# Report 22
#AD Sites with No AD subnets linked. This report will highlight sites that does not have any AD subnets associated with them. AD subnets are a crucial component for AD Sites as this is used to establish the neareast DC for a endpoint within a subnet #
Get-ADObject -Filter {(objectClass -eq "site")} -SearchBase (Get-ADRootDSE).ConfigurationNamingContext -Properties SiteobjectBL,created | select Name,@{Name="Subnetcount";Expression={$_.SiteObjectbl.Count}},created | Where-Object {$_.Subnetcount -EQ "0"} | Export-Csv "$ReportFolder\Siteswithnosubnets.csv" -NoTypeInformation

# Report 23
#AD Subnets that are not linked to any AD site. This report will highlight all AD subnets that have not been linked to AD sites.#
Get-ADObject -Filter {(objectClass -eq "Subnet")} -SearchBase (Get-ADRootDSE).ConfigurationNamingContext -Properties Siteobject,whencreated,location,Description | select Name,@{Name="Sitecount";Expression={$_.SiteObject.Count}},whencreated,location,Description | Where-Object {$_.sitecount -eq "0"} | Export-Csv "$ReportFolder\unlinkedsubnets.csv" -NoTypeInformation

# Report 24
#Locate all NO_CLIENT_SITE events in last 2 weeks from all DCs

$Result = ""
$NetLogonLog = @{}

$NetlogonLog = Get-ADDomainController -filter * | Select-Object -ExpandProperty HostName | % { @{$_=(Invoke-Command -Computer $_ -ScriptBlock { Get-Content ($env:SystemRoot + "\Debug\Netlogon.log") -last 1000})}}
$Now = Get-Date

$MissingIPs = $NetLogonLog.Keys | % { 
    $EventServer = $_ 
    $NetLogonLog.($EventServer) | % {
        if($_ -like "*NO_CLIENT_SITE*") {
            $EventTokens = $_ -split " "
            $EventYear = $Now.Year
            $MonthDay = $EventTokens[0]
            $Month = ($MonthDay -split "/")[0]
            $EventDay = ($MonthDay -split "/")[1]
            $EventTime = $EventTokens[1]
            $EventHour = ($EventTime -split ":")[0]
            $EventMinute = ($EventTime -split ":")[1]
            $EventSecond = ($EventTime -split ":")[2]
            $EventIP = $EventTokens[6]
            $EventClient = $EventTokens[5]

        
            #Adjust likely event year down by one if today is new years day
            if ((($Now.Month -eq 1) -and ($Now.Day -lt 15)) -and (($Month -eq 12) -and ($EventDay -eq 31))) { $EventYear -= 1}

            $EventDateTime = Get-Date -Year $EventYear -Month $Month -Day $EventDay -Hour $EventHour -Minute $EventMinute -Second $EventSecond
    
            if ((New-TimeSpan -Start $EventDateTime -End $Now).TotalDays -lt 14) {
                $Object = New-Object PsObject
                $Object | Add-Member -MemberType NoteProperty -Name Server $EventServer
                $Object | Add-Member -MemberType NoteProperty -Name Client $EventClient
                $Object | Add-Member -MemberType NoteProperty -Name ClientIP $EventIP
                $Object | Add-Member -MemberType NoteProperty -Name DateTime $EventDateTime
                $Object
            }
        } 
    }
}

$MissingIPs | Export-Csv "$reportfolder\MissingADSubnets.csv" -NoTypeInformation

###################################################
#						  						  #
#			Group Policy Object reports 		  #		  
#						  						  #
###################################################

# Report 25
# This Script will display all unlinked Group Policy Objects #
$DomainLinkedGPOs = Get-ADDomain | Select-Object -ExpandProperty LinkedGroupPolicyObjects
$OULinkedGPOs = Get-ADOrganizationalUnit -Filter * | Select-Object -ExpandProperty LinkedGroupPolicyObjects
$SiteLinkedGPOs = Get-ADReplicationSite -Properties GpLink | Select-Object -ExpandProperty GpLink | % {($_ -split ";")[0]} | %{($_ -split "//")[1]}
$unlinkedGPOS = Get-GPO -All | ? Path -notin $DomainLinkedGPOs | ? Path -notin $OULinkedGPOs | ? Path -notin $SiteLinkedGPOs | select Displayname,ID,GPOstatus
$unlinkedGPOS | Export-csv $reportfolder\UnLinkedGPOS.csv -NoTypeInformation 


# Report 26
#This script will retrieve the status of group policies in the domain. That can be used to identify Disabled Group Policies. 
(get-ADForest).domains | foreach { get-GPO -all -Domain $_ } | Select Displayname,GPOstatus | export-csv $reportfolder\GPOSTATUS.CSV -notypeinformation


###################################################
#						  						  #
#		Builtin Priviledged AD Groups Auditor 	  #		  
#						  						  #
###################################################

# Report 27
<#
  This script will create a report of users that are members of the following
  privileged groups:
  - Enterprise Admins
  - Schema Admins
  - Domain Admins
  - Cert Publishers
  - Administrators
  - Account Operators
  - Server Operators
  - Backup Operators
  - Print Operators

  A summary report is output to the console, whilst a full report is exported
  to a CSV file.

  The original script was written by Doug Symalla from Microsoft:
  - http://blogs.technet.com/b/askpfeplat/archive/2013/04/08/audit-membership-in-privileged-active-directory-groups-a-second-look.aspx
  - http://gallery.technet.microsoft.com/scriptcenter/List-Membership-In-bff89703

  The script was okay, but needed some updates to be more accurate and
  bug free. As Doug had not updated it since 26th April 2013, I though
  that I would. The changes I made are:

  1. Addressed a bug with the member count in the main section.
     Changed...
       $numberofUnique = $uniqueMembers.count
     To...
       $numberofUnique = ($uniqueMembers | measure-object).count
  2. Addressed a bug with the $colOfMembersExpanded variable in the
     getMemberExpanded function 
     Added...
       $colOfMembersExpanded=@()
  3. Enhanced the main section
  4. Enhanced the getForestPrivGroups function
  5. Enhanced the getUserAccountAttribs function
  6. Added script variables
  7. Added the accountExpires and info attributes
  8. Enhanced description of object members (AKA csv headers) so that
     it's easier to read.

  Script Name: Get-PrivilegedUsersReport.ps1
  Release 1.2
  Modified by Jeremy@jhouseconsulting.com 13/06/2014

#>
#-------------------------------------------------------------
# Set this to maximum number of unique members threshold
$MaxUniqueMembers = 25

# Set this to maximum password age threshold
$MaxPasswordAge = 365

# Set this to true to privide a detailed output to the console
$DetailedConsoleOutput = $False
#-------------------------------------------------------------

##################   Function to Expand Group Membership ################
function getMemberExpanded
{
        param ($dn)

        $colOfMembersExpanded=@()
        $adobject = [adsi]"LDAP://$dn"
        $colMembers = $adobject.properties.item("member")
        Foreach ($objMember in $colMembers)
        {
                $objMembermod = $objMember.replace("/","\/")
                $objAD = [adsi]"LDAP://$objmembermod"
                $attObjClass = $objAD.properties.item("objectClass")
                if ($attObjClass -eq "group")
                {
			  getmemberexpanded $objMember           
                }   
                else
                {
			$colOfMembersExpanded += $objMember
		}
        }    
$colOfMembersExpanded 
}    

########################### Function to Calculate Password Age ##############
Function getUserAccountAttribs
{
                param($objADUser,$parentGroup)
		$objADUser = $objADUser.replace("/","\/")
                $adsientry=new-object directoryservices.directoryentry("LDAP://$objADUser")
                $adsisearcher=new-object directoryservices.directorysearcher($adsientry)
                $adsisearcher.pagesize=1000
                $adsisearcher.searchscope="base"
                $colUsers=$adsisearcher.findall()
                foreach($objuser in $colUsers)
                {
                	$dn = $objuser.properties.item("distinguishedname")
	                $sam = $objuser.properties.item("samaccountname")
        	        $attObjClass = $objuser.properties.item("objectClass")
			If ($attObjClass -eq "user")
			{
				$description = $objuser.properties.item("description")[0]
				$notes = $objuser.properties.item("info")[0]
				$notes = $notes -replace "`r`n", "|"
                		If (($objuser.properties.item("lastlogontimestamp") | Measure-Object).Count -gt 0) {
                		  $lastlogontimestamp = $objuser.properties.item("lastlogontimestamp")[0]
                		  $lastLogon = [System.DateTime]::FromFileTime($lastlogontimestamp)
                		  $lastLogonInDays = ((Get-Date) - $lastLogon).Days
                		  if ($lastLogon -match "1/01/1601") {
                                    $lastLogon = "Never logged on before"
                		    $lastLogonInDays = "N/A"
                                  }
                		} else {
                		  $lastLogon = "Never logged on before"
                		  $lastLogonInDays = "N/A"
                		}
                		$accountexpiration = $objuser.properties.item("accountexpires")[0]
                		If (($accountexpiration -eq 0) -OR ($accountexpiration -gt [DateTime]::MaxValue.Ticks)) {
                		  $accountexpires = "<Never>"
                		} else {
                		  $accountexpires = [datetime]::fromfiletime([int64]::parse($accountexpiration))
                		}

        	        	$pwdLastSet=$objuser.properties.item("pwdLastSet")
                		if ($pwdLastSet -gt 0)
                        	{
                        		$pwdLastSet = [datetime]::fromfiletime([int64]::parse($pwdLastSet))
                                	$PasswordAge = ((get-date) - $pwdLastSet).days
                        	}
                        	Else {$PasswordAge = "<Not Set>"}                                                                        
                		$uac = $objuser.properties.item("useraccountcontrol")
                        	$uac = $uac.item(0)
                		if (($uac -bor 0x0002) -eq $uac) {$disabled="TRUE"}
                        	else {$disabled = "FALSE"}
                        	if (($uac -bor 0x10000) -eq $uac) {$passwordneverexpires="TRUE"}
                        	else {$passwordNeverExpires = "FALSE"}
                        }                                                        
                        $record = "" | select-object SamAccountName,DistinguishedName,MemberOf,PasswordAge,LastLogon,LastLogonInDays,Disabled,PasswordNeverExpires,AccountExpires,Description,Notes
                        $record.SamAccountName = [string]$sam
                        $record.DistinguishedName = [string]$dn
                        $record.MemberOf = [string]$parentGroup
                        $record.PasswordAge = $PasswordAge
                        $record.LastLogon = $lastLogon
                        $record.LastLogonInDays = $lastLogonInDays
                        $record.Disabled = $disabled
                        $record.PasswordNeverExpires = $passwordNeverExpires
                        $record.AccountExpires = $accountexpires
                        $record.Description = $description
                        $record.Notes = $notes

                } 
$record
}
####### Function to find all Privileged Groups in the Forest ##########
Function getForestPrivGroups
{
  # Privileged Group Membership for the following groups:
  # - Enterprise Admins - SID: S-1-5-21root domain-519
  # - Schema Admins - SID: S-1-5-21root domain-518
  # - Domain Admins - SID: S-1-5-21domain-512
  # - Cert Publishers - SID: S-1-5-21domain-517
  # - Administrators - SID: S-1-5-32-544
  # - Account Operators - SID: S-1-5-32-548
  # - Server Operators - SID: S-1-5-32-549
  # - Backup Operators - SID: S-1-5-32-551
  # - Print Operators - SID: S-1-5-32-550
  # Reference: http://support.microsoft.com/kb/243330

                $colOfDNs = @()
                $Forest = [System.DirectoryServices.ActiveDirectory.forest]::getcurrentforest()
		$RootDomain = [string]($forest.rootdomain.name)
		$forestDomains = $forest.domains
		$colDomainNames = @()
		ForEach ($domain in $forestDomains)
		{
			$domainname = [string]($domain.name)
			$colDomainNames += $domainname
		}
		
                $ForestRootDN = FQDN2DN $RootDomain
		$colDomainDNs = @()
		ForEach ($domainname in $colDomainNames)
		{
			$domainDN = FQDN2DN $domainname
			$colDomainDNs += $domainDN	
		}

		$GC = $forest.FindGlobalCatalog()
                $adobject = [adsi]"GC://$ForestRootDN"
        	$RootDomainSid = New-Object System.Security.Principal.SecurityIdentifier($AdObject.objectSid[0], 0)
		$RootDomainSid = $RootDomainSid.toString()
		$colDASids = @()
		ForEach ($domainDN in $colDomainDNs)
		{
			$adobject = [adsi]"GC://$domainDN"
        		$DomainSid = New-Object System.Security.Principal.SecurityIdentifier($AdObject.objectSid[0], 0)
			$DomainSid = $DomainSid.toString()
			$daSid = "$DomainSID-512"
			$colDASids += $daSid
			$cpSid = "$DomainSID-517"
			$colDASids += $cpSid
		}


		$colPrivGroups = @("S-1-5-32-544";"S-1-5-32-548";"S-1-5-32-549";"S-1-5-32-551";"S-1-5-32-550";"$rootDomainSid-519";"$rootDomainSid-518")
		$colPrivGroups += $colDASids
                
		$searcher = $gc.GetDirectorySearcher()
		ForEach($privGroup in $colPrivGroups)
                {
                                $searcher.filter = "(objectSID=$privGroup)"
                                $Results = $Searcher.FindAll()
                                ForEach ($result in $Results)
                                {
                                                $dn = $result.properties.distinguishedname
                                                $colOfDNs += $dn
                                }
                }
$colofDNs
}

########################## Function to Generate Domain DN from FQDN ########
Function FQDN2DN
{
	Param ($domainFQDN)
	$colSplit = $domainFQDN.Split(".")
	$FQDNdepth = $colSplit.length
	$DomainDN = ""
	For ($i=0;$i -lt ($FQDNdepth);$i++)
	{
		If ($i -eq ($FQDNdepth - 1)) {$Separator=""}
		else {$Separator=","}
		[string]$DomainDN += "DC=" + $colSplit[$i] + $Separator
	}
	$DomainDN
}

########################## MAIN ###########################
# Get the script path
$ScriptPath = {Split-Path $MyInvocation.ScriptName}
$ReferenceFile = "$Reportfolder\PrivilegedUsers.csv"

$forestPrivGroups = GetForestPrivGroups
$colAllPrivUsers = @()

$rootdse=new-object directoryservices.directoryentry("LDAP://rootdse")

Foreach ($privGroup in $forestPrivGroups)
{
                #write-host ""
		#write-host "Enumerating $privGroup.." -foregroundColor yellow
                $uniqueMembers = @()
                $colOfMembersExpanded = @()
		$colofUniqueMembers = @()
                $members = getmemberexpanded $privGroup
                If ($members)
                {
                                $uniqueMembers = $members | sort-object -unique
				$numberofUnique = ($uniqueMembers | measure-object).count
				Foreach ($uniqueMember in $uniqueMembers)
				{
					 $objAttribs = getUserAccountAttribs $uniqueMember $privGroup
                                         $colOfuniqueMembers += $objAttribs      
				}
                                $colAllPrivUsers += $colOfUniqueMembers
                }
                Else {$numberofUnique = 0}
                
                If ($numberofUnique -gt $MaxUniqueMembers)
                {
                                #write-host "...$privGroup has $numberofUnique unique members" -foregroundColor Red
                }
		Else { #write-host "...$privGroup has $numberofUnique unique members" -foregroundColor White 
}

                $pwdneverExpiresCount = 0
                $pwdAgeCount = 0

                ForEach($user in $colOfuniquemembers)
                {
                                $i = 0
                                $userpwdAge = $user.pwdAge
                                $userpwdneverExpires = $user.pWDneverExpires
                                $userSAM = $user.SAM
                                IF ($userpwdneverExpires -eq $True)
                                {
                                  $pwdneverExpiresCount ++
                                  $i ++
                                  If ($DetailedConsoleOutput) {#write-host "......$userSAM has a password age of $userpwdage and the password is set to never expire" -foregroundColor Green
                                  }
                                }
                                If ($userpwdAge -gt $MaxPasswordAge)
                                {
                                  $pwdAgeCount ++
                                  If ($i -gt 0)
                                  {
                                    If ($DetailedConsoleOutput) {#write-host "......$userSAM has a password age of $userpwdage days" -foregroundColor Green
                                    }
                                  }
                                }
                }

                If ($numberofUnique -gt 0)
                {
                                #write-host "......There are $pwdneverExpiresCount accounts that have the password is set to never expire." -foregroundColor Green
                                #write-host "......There are $pwdAgeCount accounts that have a password age greater than $MaxPasswordAge days." -foregroundColor Green
                }
}

#write-host "`nComments:" -foregroundColor Yellow
#write-host " - If a privileged group contains more than $MaxUniqueMembers unique members, it's highlighted in red." -foregroundColor Yellow
If ($DetailedConsoleOutput) {
  #write-host " - The privileged user is listed if their password is set to never expire." -foregroundColor Yellow
  #write-host " - The privileged user is listed if their password age is greater than $MaxPasswordAge days." -foregroundColor Yellow
  #write-host " - Service accounts should not be privileged users in the domain." -foregroundColor Yellow
}

$colAllPrivUsers | Export-CSV -notype -path "$Reportfolder\PrivilegedUsers.csv" -Delimiter ';'

# Remove the quotes
(get-content "$ReferenceFile") |% {$_ -replace '"',""} | out-file "$ReferenceFile" -Fo -En ascii



Invoke-Item "C:\Users\Install\Desktop\AD REPORTS"

