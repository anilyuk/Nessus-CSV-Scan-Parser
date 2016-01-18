#Powershell script for nessus scans
#Nessus Scans are hard to investigate. Also, csv export can't be imported directly to excel.
#This tool is used for manipulating csv scan files. Excel can directly import new csv scan file.
#
#2016 AnilYUKSEL


[CmdletBinding(DefaultParameterSetName="None")]
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
	$h

)

function showHelp{

	echo ""
	echo "Parse exported CSV file and create Excel friendly CSV."
	echo "Usage: nessusCSVScanParser.ps1 d:\ScanResults\Scan1.csv -s"
	echo ""
	echo "	-i	[File]			Full path of scan file(Only .csv file, Full path)"
	echo "	-s					Write Output .csv to same directory"
	echo "	-o	[Directory]		Write output to differenf directory (Full path)"
	echo "	-d	[Delimeter]		Csv file delimeter (Default is #)"
	echo ""
	echo ""

}

$global:scanFile = ""
$global:outputFile = ""

function setFiles{
	
	$global:scanFile = $i
	
	$inputFileName = ($scanFile -split "\\")[-1]
	$inputFileDir = $scanFile -split "$(($scanFile -split "\\")[-1])"

	$outPutFileName = ($inputFileName -split "\.csv")[0] + "_Output.csv"

	if($s){
		
		$global:outputFile = $inputFileDir[0].Trim("\\") + "\" + $outPutFileName
		
	}else{

		$outFileDir = $o
		$global:outputFile = $outFileDir.Trim("\\") + "\" + $outPutFileName

	}


	echo "Input File: $scanFile"
	echo "Output Dir: $outputFile"
	
}


function ProcessVulnerabilities{

	$importedCSV = Import-Csv $scanFile

	echo "Plugin ID$d CVE$d CVSS$d Risk$d Name$d Synopsis$d Description$d Solution$d Hosts" > $outputFile

	$pluginInformations = $importedCSV | select "Plugin ID", "CVEText", "CVSS", "Risk", "Name", "Synopsis", "Description", "Solution", "HostText" -Unique

	echo "$($pluginInformations.length) plugins found."

	foreach($plugin in $pluginInformations){

		$hostList = $importedCSV | where {$_."Plugin ID" -eq $plugin."Plugin ID"} | select "Host", "Port" ,"Protocol" -Unique
		
		$plugin."Solution" = $plugin."Solution" -replace "`n"," "
		$plugin."Synopsis" = $plugin."Synopsis" -replace "`n"," "
		$plugin."Name" = $plugin."Name" -replace "`n"," "
		$plugin."Description" = $plugin."Description" -replace "`n"," "
		
		echo "Processing Plugin ID: $($plugin."Plugin ID")"
		echo "Plugin ID: $($plugin."Plugin ID") affects $($hostList.length) hosts and services"
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
		
		$cveList = $importedCSV | where {$_."Plugin ID" -eq $plugin."Plugin ID"} | select "CVE" -Unique
		
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
		echo $cveText
		
		echo "------------------------------------------------------------------"
		
		$text = "$($plugin."Plugin ID")$d $($plugin."CVEText")$d $($plugin."CVSS") $d $($plugin."Risk")$d $($plugin."Name")$d $($plugin."Synopsis")$d $($plugin."Description")$d $($plugin."Solution")$d $($plugin."HostText")"
		echo $text >> $outputFile

	}

}


if($h){

	showHelp
	
}else{

	setFiles
	ProcessVulnerabilities
	
}
