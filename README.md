# Nessus-CSV-Scan-Parser

Parse exported CSV file and create Excel friendly CSV.

Usage: nessusCSVScanParser.ps1 d:\ScanResults\Scan1.csv -s

	-i	[File]		Full path of scan file(Only .csv file, Full path)
	-s				Write Output .csv to same directory
	-o	[Directory]	Write output to differenf directory (Full path)"
	-d	[Delimeter]	Csv file delimeter (Default is #)
	-ho	Change listing to host based (Default is Plugin Based)
	-Verbose	Enable verbose
