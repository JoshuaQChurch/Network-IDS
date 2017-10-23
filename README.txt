If providing a Blacklisted IP file, the following format MUST be followed:
	- There can only be (1) IP on each line
	- There can only be (1) IP file provided
	- The file extension must be .txt 

If providing a Blacklisted Domain file, the follwing format MUST be followed:
	- There can only be (1) domain on each line
	- There can only be (1) domain file provided
	- The file extension must be .txt

If providing a PCAP file, the following format MUST be followed:
	- There can only be (1) .pcap file 
	- The file extension must be .pcap

If providing a Blacklisted Signatures file, the following format MUST be followed:
	- There can only be (1) signature on each line
	- There can only be (1) signature file provided
	- The file extension must be .txt

If providing a Blacklisted String file, the following for MUST be followed:
	- There can only be (1) string on each line
	- There can only be (1) string file provided
	- The file extension must be .txt 

A Network Interface MUST be provided. 
	- Must only provided (1) interface

If providing custom log file, the following format MUST be followed:
	- There can only be (1) log file provided
	- The file extension must be .txt

If no custom log file is provided, one will be provided:
	- It will create in current directory
	- It will be called logfile.txt

WARNING: If any of these rules are broken, the program will crash. 


