#Powershell script for nessus scans
#Nessus Scans are hard to investigate. Also, csv export can't be imported directly to excel.
#This tool is used for manipulating csv scan files. Excel can directly import new csv scan file.
#
#2016 anilyuk


[CmdletBinding(DefaultParameterSetName="ShowHelp")]
param(
	[Parameter(Mandatory=$True,ParameterSetName="WriteToSameDirectory",Position=0)]
	[Parameter(Mandatory=$True,ParameterSetName="WriteToDifferentDirectory",Position=0)]
	[string]
	$i,

	##CSV delimeter
	[string]
	$d = "#",
	
	[Parameter(Mandatory=$True,ParameterSetName="WriteToDifferentDirectory",Position=1)]
	[string]
	$o,

	[Parameter(Mandatory=$True,ParameterSetName="WriteToSameDirectory",Position=1)]
	[switch]
	$s,
	
	[Parameter(Mandatory=$True,ParameterSetName="ShowHelp")]
	[switch]
	$h,

	#host based listing
	[switch]
	$ho
	
)

function showHelp{

	echo ""
	echo "Parse Nessus exported csv file and convert to Excel friendly CSV."
	echo "Usage: .\NessusCSVScanParser.ps1 -i C:\ScanResult\Scan1.csv -s"
	echo ""
	echo "   -i		Full path of scan file(Only .csv file, Full path must be stated!)"
	echo "   -s		Write Output .csv to same directory"
	echo "   -o		Write output to differenf directory (Full path must be stated!)"
	echo "   -d		Csv file delimeter (Default is #)"
	echo "   -ho	Change listing to host based (Default is Plugin Based)"
	echo "   -Verbose	Enable verbose logging"
	echo ""
	echo ""

}

$global:scanFile = ""
$global:outputFile = ""

function setFiles{
	
	$global:scanFile = $i
	
	$inputFileName = ($scanFile -split "\\")[-1]
	$inputFileDir = $scanFile -split "$(($scanFile -split "\\")[-1])"

	if($ho){
	
		$outPutFileName = ($inputFileName -split "\.csv")[0] + "_HostBased_Output.csv"
	
	}else{
	
		$outPutFileName = ($inputFileName -split "\.csv")[0] + "_PluginBased_Output.csv"
	
	}
	

	if($s){
		
		$global:outputFile = $inputFileDir[0].Trim("\\") + "\" + $outPutFileName
		
	}else{

		$outFileDir = $o
		$global:outputFile = $outFileDir.Trim("\\") + "\" + $outPutFileName

	}


	Write-Verbose "Input File: $scanFile"
	Write-Verbose "Output Dir: $outputFile"
	
}

function pluginBasedListing{

	echo "Plugin based listing selected"

	Write-Verbose "Reading plugins (this may take long time...)"
	$pluginInformations = $importedCSV | select "Plugin ID", "CVEText", "CVSS", "Risk", "Name", "Synopsis", "Description", "Solution", "HostText" -Unique
	echo "$($pluginInformations.length) plugins found."
	Write-Verbose "Reading hosts."
	$hostCsvList = $importedCSV | select "Plugin ID", "Host", "Port" ,"Protocol" -Unique
	Write-Verbose "Reading CVEs."
	$cveCsvList = $importedCSV | select "Plugin ID", "CVE" -Unique
	
	echo "Processing vulnerabilities..."
	
	foreach($plugin in $pluginInformations){

		$hostList = $hostCsvList | where {$_."Plugin ID" -eq $plugin."Plugin ID"} | select "Host", "Port" ,"Protocol" -Unique
		
		$plugin."Solution" = $plugin."Solution" -replace "`n"," "
		$plugin."Synopsis" = $plugin."Synopsis" -replace "`n"," "
		$plugin."Name" = $plugin."Name" -replace "`n"," "
		$plugin."Description" = $plugin."Description" -replace "`n"," "
		
		
		Write-Verbose "Processed $current/$($pluginInformations.length) plugins"
		Write-Verbose "------------------------------------------------------------------"
		
		Write-Verbose "Processing Plugin ID: $($plugin."Plugin ID")"
		Write-Verbose "Plugin ID: $($plugin."Plugin ID") affects $($hostList.length) hosts and services"
		$hostsText = ""
		if(($hostList) -is [system.array]){
		
			for($i = 0; $i -lt ($hostList).length; $i++){
				
				if($i -lt ($hostList).length -1){
				
					$hostsText += "$(($hostList)[$i]."Host") ($(($hostList)[$i]."Protocol")/$(($hostList)[$i]."Port")), "
					$plugin."HostText" = $hostsText
				
				}else{
				
					$hostsText += "$(($hostList)[$i]."Host") ($(($hostList)[$i]."Protocol")/$(($hostList)[$i]."Port"))"
					$plugin."HostText" = $hostsText
					
				}
				
			}
		
		}else {
		
			$hostsText += "$(($hostList)."Host") ($(($hostList)."Protocol")/$(($hostList)."Port"))"
			$plugin."HostText" = $hostsText
		
		}
		
		$cveList = $cveCsvList | where {$_."Plugin ID" -eq $plugin."Plugin ID"} | select "CVE" -Unique
		
		$cveText = ""
		
		if(($cveList) -is [system.array]){
		
			for($i = 0; $i -lt ($cveList).length; $i++){
				
				if($i -lt ($cveList).length -1){
				
					$cveText += "$(($cveList)[$i]."CVE"), "
					$plugin."CVEText" = $cveText
				
				}else{
				
					$cveText += "$(($cveList)[$i]."CVE")"
					$plugin."CVEText" = $cveText
					
				}
				
			}
		
		}else{
		
			$cveText = "$($cveList."CVE")"
			$plugin."CVEText" = $cveText
		
		}
				
		Write-Verbose "------------------------------------------------------------------"
		
		$current++
		
		$text = "$($plugin."Plugin ID")$d $($plugin."CVEText")$d $($plugin."CVSS") $d $($plugin."Risk")$d $($plugin."Name")$d $($plugin."Synopsis")$d $($plugin."Description")$d $($plugin."Solution")$d $($plugin."HostText")"
		echo $text >> $outputFile

	}

}

function hostBasedListing{

	echo "Host based listing selected"
	
	Write-Verbose "Reading plugins (this may take long time...)"
	$pluginInformations = $importedCSV | select "Plugin ID", "CVEText", "CVSS", "Risk", "Name", "Synopsis", "Description", "Solution", "Host", "Port", "Protocol" -Unique
	echo "$($pluginInformations.length) plugins found."
	Write-Verbose "Reading CVEs."
	$cveCsvList = $importedCSV | select "Plugin ID", "CVE" -Unique
	
	echo "Processing vulnerabilities..."
	
	foreach($plugin in $pluginInformations){

		$plugin."Solution" = $plugin."Solution" -replace "`n"," "
		$plugin."Synopsis" = $plugin."Synopsis" -replace "`n"," "
		$plugin."Name" = $plugin."Name" -replace "`n"," "
		$plugin."Description" = $plugin."Description" -replace "`n"," "
		
		Write-Verbose "Processed $current/$($pluginInformations.length) plugins"
		Write-Verbose "------------------------------------------------------------------"
		
		Write-Verbose "Processing Plugin ID: $($plugin."Plugin ID")"

		$hostsText = "$($plugin."Host") ($($plugin."protocol")/$($plugin."port"))"

		$plugin."Host" = $hostsText
		
		$cveList = $cveCsvList | where {$_."Plugin ID" -eq $plugin."Plugin ID"} | select "CVE" -Unique
		
		$cveText = ""
		
		if(($cveList) -is [system.array]){
		
			for($i = 0; $i -lt ($cveList).length; $i++){
				
				if($i -lt ($cveList).length -1){
				
					$cveText += "$(($cveList)[$i]."CVE"), "
					$plugin."CVEText" = $cveText
				
				}else{
				
					$cveText += "$(($cveList)[$i]."CVE")"
					$plugin."CVEText" = $cveText
					
				}
				
			}
		
		}else{
		
			$cveText = "$($cveList."CVE")"
			$plugin."CVEText" = $cveText
		

		}
				
		Write-Verbose "------------------------------------------------------------------"
		
		$current++
		
		$text = "$($plugin."Plugin ID")$d $($plugin."CVEText")$d $($plugin."CVSS") $d $($plugin."Risk")$d $($plugin."Name")$d $($plugin."Synopsis")$d $($plugin."Description")$d $($plugin."Solution")$d $($plugin."Host")"
		echo $text >> $outputFile
	
	}
}

$global:current = 0
$global:importedCSV = ""

function ProcessVulnerabilities{

	Try{
	
		$importedCSV = Import-Csv $scanFile -ErrorAction Stop
	
	}
	Catch{
	
		Write-Verbose "ERROR: Problem with csv file."
	
	}
	Finally{
	
		Write-Verbose -Message "Scan file imported."
	
	}
		
	echo "Plugin ID$d CVE$d CVSS$d Risk$d Name$d Synopsis$d Description$d Solution$d Hosts" > $outputFile

	if($ho){
	
		hostBasedListing
	
	}else{
	
		pluginBasedListing
		
	}

}



if($h){

	showHelp
	
}else{

	setFiles
	ProcessVulnerabilities
	
}
