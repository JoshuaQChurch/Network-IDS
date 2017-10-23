###################################################################
## ASSIGNMENT: Homework 3 - Network Intrusion Detection System	 
## NAME: 	   Joshua Church									 
## NETID: 	   JQC10											 
###################################################################

## REFERENCES:
## [1] http://www.secdev.org/projects/scapy/doc/usage.html 
## 	 - Official scapy documentation to help with functionality 
## 	 - All Scapy functionality learned from here
## [2] https://perishablepress.com/blacklist/ip.txt
##	 - This is an official list of blacklisted IP Addresses from 2010
##	 - Using as my .txt file for testing purposes. 

# Using Python 2.7.10
# I have not tested with 3+ version of Python
#	- If using 3+, there may be errors. Unsure at the moment, however. 

import sys
import os
import time
import datetime
import math

from scapy.all import *

################### CUSTOM HELP MENU #######################################


# Defaulted custom help menu for ids.py
def help_menu(): 
	print("\n\nNAME")
	print("\tids.py - Simple Network Intrusion Detection System")
	print("\n\nSYNOPSIS")
	print("\tids.py [FILE]... [OPTION]...")
	print("\n\nDESCRIPTION\n")
	print("\tThis system will monitor live or pre-existing (PCAP) network traffic.\n")
	
	# Blacklisted IP Help Entry
	print("\t -i")
	print("\t\tAdded after custom Blacklisted IP text file for parsing.")
	print("\t\tEXAMPLE: python ids.py ip.txt -ip") 

	# Blacklisted DNS Help Entry
	print("\t -d")
	print("\t\tAdded after custom Blacklisted DNS text file for parsing.")
	print("\t\tEXAMPLE: python ids.py dns.txt -dns")	
	
	# Network Interface Help Entry
	print("\t -n")
	print("\t\tAdded after specific network interface.")
	print("\t\tEXAMPLE: python ids.py eth0 -n") 

	# Logfile Output Help Entry
	print("\t -o")
	print("\t\tAdded after specified output file")
	print("\t\tEXAMPLE: python ids.py logfile.txt -o")

	# PCAP Help Entry
	print("\t -p")
	print("\t\tAdded after specifed PCAP file")
	print("\t\tEXAMPLE: python ids.py pcap_file.pcap -p")

	# Blacklisted Signature List Help Entry
	print("\t -sg")
	print("\t\tAdded after custom Blacklisted Payload Signatures text file for parsing.")
	print("\t\tEXAMPLE: python ids.py signatures.txt -sg")

	# Blacklisted URL String List Help Entry
	print("\t -st")
	print("\t\tAdded after custom Blacklisted URL Strings text file for parsing.")
	print("\t\tEXAMPLE: python ids.py strings.txt -st")

	# Config File Referral Entry
	print("\n\nARGUMENT REQUIREMENTS\n")
	print("\tFor requirements to run this program, refer to the README.txt file")

	# Additional spacing and program exit
	print("\n\n")
	sys.exit(1)

######################## END HELP MENU #######################################	


	
################## CLASSES FOR LOGGING AND ALERTING PURPOSES #################

# This class helps keep up with the different Blacklisted IPs
class blacklisted_ip():
	def __init__(self):
		self.ip = ""
		self.log_count = 0
		self.min_diff = 0

	def setIP(self, ip):
		self.ip = ip

	def incrementCount(self):
		self.log_count += 1

	def setMinute(self, minutes):
		self.min_diff = minutes 

	def getIP(self):
		return self.ip

	def getCount(self):
		return self.log_count

	def getDiff(self):
		return self.min_diff

# This class helps keep up with the different Blacklisted Domains
class blacklisted_dns():
	def __init__(self):
		self.dns = ""
		self.log_count = 0
		self.min_diff = 0

	def setDNS(self, dns):
		self.dns = dns

	def incrementCount(self):
		self.log_count += 1

	def setMinute(self, minutes):
		self.min_diff = minutes 

	def getDNS(self):
		return self.dns

	def getCount(self):
		return self.log_count

	def getDiff(self):
		return self.min_diff

# This class helps keep up with the different Blacklisted Strings
class blacklisted_strings():
	def __init__(self):
		self.string = ""
		self.log_count = 0
		self.min_diff = 0

	def setString(self, string):
		self.string = string

	def incrementCount(self):
		self.log_count += 1

	def setMinute(self, minutes):
		self.min_diff = minutes

	def getString(self):
		return self.string

	def getCount(self):
		return self.log_count

	def getDiff(self):
		return self.min_diff


# This class helps keep up with the different Blacklisted Signatures
class blacklisted_signatures():
	def __init__(self):
		self.signature = ""
		self.log_count = 0
		self.min_diff = 0

	def setSignature(self, signature):
		self.signature = signature

	def incrementCount(self):
		self.log_count += 1

	def setMinute(self, minutes):
		self.min_diff = minutes

	def getSignature(self):
		return self.signature

	def getCount(self):
		return self.log_count

	def getDiff(self):
		return self.min_diff

################### END CLASS CREATION #######################################



################### PARSING COMMAND LINE ARGUMENTS ###########################

# Function to parse values passed into the command line. 
def parse():

	global ip_read 				# Blacklisted IP File defined by user
	global dns_read				# Blacklisted Domain Names List defined by the user
	global pcap					# PCAP File defined by user
	global net_int				# Network Interface defined by user
	global output 				# Output file for logging
	global online				# If .pcap file is passed in argument, don't monitor live traffic.
	global dns_provided			# Check to see if Blacklisted domain list was provided by user
	global ip_provided			# Check to see if Blacklisted ip list was provided by user
	global net_int_provided		# Check to see if Network Interface provided by the user
	global str_provided			# Check to see if Blacklisted string list was provided
	global sig_provided 		# Check to see if Payload signatures were provided
	global count 				# Keeps up with counting in the log file. 
	global pkt_dict				# Keeps up with packet keys 
	global time_dict			# Keeps up with packet times
	global dport_dict			# Keeps up with packet dports

	output = "logfile.txt" 		# Setting Default logfile if one isn't provided. 
	online = True				# Defaulted to sniffing live traffic
	dns_provided = False		# Defaulted to no Domain file provided
	ip_provided = False			# Defaulted to no IP file provided
	str_provided = False		# Defaulted to no String file provided
	net_int_provided = False	# Defaulted to no network interface being provided 
	sig_provided = False		# Defaulted to no payload signatures being provided 
	count = 0					# Defaulted to 0 until log happens
	pkt_dict = {}				# Defaulted to 0 packet keys
	time_dict = {}				# Defaulted to 0 time keys
	dport_dict = {}				# Defaulted to 0 dport keys
	argv = sys.argv				# Quicker way to parse command line args


	# Help menu command line argument
	if (len(argv) == 2 and argv[1] == '-h'):
		help_menu()
	
	else: 

		# Check each argument passed in via commandline
		for i in range(len(argv)):
			
			# Checks for Blacklisted IP address text file
			if (argv[i] == '-i' and argv[i - 1].lower().endswith(".txt")):
				bip = argv[i - 1]

				# Set provided flag to true
				ip_provided = True

				# Check to see if file passed is valid. 
				try:
					blacklisted_ip_file = open(bip, "r")
					ip_read = blacklisted_ip_file.read().splitlines()
				
				# If not valid, throw error and exit. 
				except IOError:
					print("#############################################")
					print("Error: " + bip + " is not a valid file.")
					print("#############################################")
					sys.exit(-1)

				# Create array of Blacklisted IP Objects
				# This will be used to keep up with alerting and logging
				global alert_ip
				alert_ip = [blacklisted_ip() for i in range(len(ip_read))]
	
				for i in range(len(ip_read)):
					alert_ip[i].setIP(ip_read[i])

			# Check for Blacklisted Domain Addresses in text file.
			elif(argv[i] == '-d' and argv[i - 1].lower().endswith(".txt")):
				dns = argv[i - 1] 

				# Set provided flag to true
				dns_provided = True

				# Check to see if file passed is valid. 
				try:
					blacklisted_dns_file = open(dns, "r")
					dns_read = blacklisted_dns_file.read().splitlines()

				# If not valid, throw error and exit.
				except IOError:
					print("#############################################")
					print("Error: " + dns + " is not a valid file.")
					print("#############################################")
					sys.exit(-1)

				# Create array of Blacklisted Domain Names Objects
				# This will be used to keep up with alerting and logging
				global alert_dns
				alert_dns = [blacklisted_dns() for i in range(len(dns_read))]

				for i in range(len(dns_read)):
					alert_dns[i].setDNS(dns_read[i])

			# Check for Blacklisted Strings in text file.
			elif(argv[i] == '-st' and argv[i - 1].lower().endswith(".txt")):
				str_file = argv[i - 1] 

				# Set provided flag to true
				str_provided = True

				# Check to see if file passed is valid. 
				try:
					blacklisted_str_file = open(str_file, "r")
					str_read = blacklisted_str_file.read().splitlines()

				# If not valid, throw error and exit.
				except IOError:
					print("#############################################")
					print("Error: " + str_file + " is not a valid file.")
					print("#############################################")
					sys.exit(-1)

				# Create array of Blacklisted String Names Objects
				# This will be used to keep up with alerting and logging
				global alert_string
				alert_string = [blacklisted_strings() for i in range(len(str_read))]

				for i in range(len(str_read)):
					alert_string[i].setString(str_read[i])


			# Check for Blacklisted Signatures in text file.
			elif(argv[i] == '-sg' and argv[i - 1].lower().endswith(".txt")):
				sig_file = argv[i - 1] 

				# Set provided flag to true
				sig_provided = True

				# Check to see if file passed is valid. 
				try:
					blacklisted_sig_file = open(sig_file, "r")
					sig_read = blacklisted_sig_file.read().splitlines()

				# If not valid, throw error and exit.
				except IOError:
					print("#############################################")
					print("Error: " + sig_file + " is not a valid file.")
					print("#############################################")
					sys.exit(-1)

				# Create array of Blacklisted Signature Name Objects
				# This will be used to keep up with alerting and logging
				global alert_signature
				alert_signature = [blacklisted_signatures() for i in range(len(sig_read))]

				for i in range(len(sig_read)):
					alert_signature[i].setSignature(sig_read[i])

			# Sets the output log file
			elif(argv[i] == '-o' and argv[i - 1].lower().endswith(".txt")):
				output = argv[i - 1] 

			# Checks for .pcap files
			elif (argv[i] == '-p' and argv[i - 1].lower().endswith(".pcap")):
				pcap = argv[i - 1]
				online = False
			
			# Checks for appropriate network interface
			elif (argv[i] == '-n'):
				net_int = argv[i - 1]

				# Set the provided flag to true
				net_int_provided = True
	
####################### END PARSING COMMAND LINE ARGUMENTS ####################################


####################### PACKET DETECTION AND HANDLING #####################################

# Function to utilize Scapy's sniffing functionality
def sniffPackets():

	# Check to see if user provided a network interface
	if net_int_provided:
		print("Listening...")

		# Scapy's built in packet sniffer
		# Assistance from [1] 
		# Try to sniff on provided network interface

		try:
			sniff(iface=str(net_int), prn=checkPacket)

		# If error arises, display error and exit program. 
		except socket.error:
			print("ERROR: " + net_int + " is an invalid network interface")
			print("Exiting...")
			sys.exit(-1)

	# If Network Interface is not provided, display error and exit the program. 
	else:
		print("ERROR: A Network Interface MUST be provided.")
		print("Exiting...")
		sys.exit(-1)

# This function checks the packets that have been sniffed. 
def checkPacket(pkt): # Assistance found at [1] 

	# Checks for port scanning	
	#portScanning(pkt)

	# Check each packet for a blacklisted string
	if str_provided:
		checkString(pkt)

	# Check each packet for a blacklisted payload signature
	if sig_provided:
		checkSignature(pkt)

	# Check if IP Layer Found
	if pkt[0].haslayer(IP):

		# If DNS request, check the packet
		if pkt[0].haslayer(DNS) and dns_provided:
			checkDNS(pkt)
		
		# If TCP, check the packet
		if ip_provided:
			checkIP(pkt)

	# If unable to propery process packet, throw error. 
	else:
		print("ERROR: Unable to process packet properly.")
		return 




def checkString(pkt):

	# Using Scapy's built in sprintf functionality,
	# store Raw Packet results in variable for easier parsing
	# Assistance found at [1]
	raw = pkt.sprintf("{Raw:%Raw.load%}")

	# Loop through the imported 
	for s in alert_string:

		# If GET request found in URL, do the following:
		if raw.find("GET"):
			if "GET" in raw.partition("HTTP/1.1")[0] and s.getString() in raw.partition("HTTP/1.1")[0]:
				
				# Log the instance every time
				logString(s.getString(), raw.partition("HTTP/1.1")[0], pkt[IP].dst)

				# Only alert to screen after 5+ minutes of instance occuring
				if s.getCount() == 0 and s.getDiff() == 0:
					s.incrementCount()
					s.setMinute(datetime.datetime.now().minute)
					print("BLACKLISTED STRING: [" + s.getString() + "] in GET request to [" + pkt[IP].dst + "]")
					print(" \ Located in: " + raw.partition("HTTP/1.1")[0])

				# After 5+ Minutes, reset values to be able to alert to screen
				elif (s.getCount() > 0 and abs(s.getDiff() - datetime.datetime.now().minute) >= 6):
					s.log_count = 0
					s.setMinute(0)

				# Otherwise, increment count value
				else:
					s.incrementCount()


# Function to check specified packet for Blacklisted Payload signatures
def checkSignature(pkt):

	# Using Scapy's built in sprintf functionality,
	# store Raw Packet results in variable for easier parsing
	# Assistance found at [1]

	# If DNS, set appropriate payload 
	if pkt[0].haslayer(DNS):
		payload = pkt.sprintf("%UDP.payload%")


	# If TCP, set appropriate payload
	else:
		payload = pkt.sprintf("%TCP.payload%")

	# Loop through the imported signature list
	for s in alert_signature:

		# If an imported signature was found in payload, do the following:
		if s.getSignature() in payload:

			# Log the instance every time
			logSignature(s.getSignature(), pkt[IP].dst)

			# Only alert to screen after 5+ minutes of instance occuring
			if s.getCount() == 0 and s.getDiff() == 0:
				s.incrementCount()
				s.setMinute(datetime.datetime.now().minute)
				print("BLACKLISTED SIGNATURE: [" + s.getSignature() + "] packet to [" + pkt[IP].dst + "]")

			# After 5+ Minutes, reset values to be able to alert to screen
			elif (s.getCount() > 0 and abs(s.getDiff() - datetime.datetime.now().minute) >= 6):
				s.log_count = 0
				s.setMinute(0)

			# Otherwise, increment count value
			else:
				s.incrementCount()

			


# Check IP Addressed within the packet passed
def checkIP(pkt):

	# Loop through the imported Blacklisted IP array
	for ip in alert_ip:

		# If Blacklisted IP Address found, do the following:
		if ip.getIP() == pkt[IP].src or ip.getIP() == pkt[IP].dst:
			
			# Log every instance
			logIP(ip)

			# Only alert to screen after 5+ minutes of instance occuring
			if ip.getCount() == 0 and ip.getDiff() == 0:
				ip.incrementCount()
				ip.setMinute(datetime.datetime.now().minute)
				if ip.getIP() == pkt[IP].src:
					print("BLACKLIST WARNING: [" +  ip.getIP() + "] sending data to [" + pkt[IP].dst + "]")
				else:	
					print("BLACKLIST WARNING: [" + ip.getIP() + "] receiving data from [" + pkt[IP].src + "]")
			
			# After 5+ Minutes, reset values to be able to alert to screen
			elif (ip.getCount() > 0 and abs(ip.getDiff() - datetime.datetime.now().minute) >= 6):
				ip.log_count = 0
				ip.setMinute(0)
	
			# Increment count
			else:
				ip.incrementCount()

# Check Domain Addressed with the packet passed
def checkDNS(pkt):

	# Loop through the imported Blacklisted DNS array
	for dns in alert_dns:

		# If Blacklisted Domain found, do the following:
		if dns.getDNS() in pkt[DNSQR].qname:
			
			# Log every instance
			logDNS(dns)

			# Only alert to screen after 5+ minutes of instance occuring
			if dns.getCount() == 0 and dns.getDiff() ==  0:
				dns.incrementCount()
				dns.setMinute(datetime.datetime.now().minute)
				print("BLACKLIST WARNING: [" + dns.getDNS() + "] was requested!")

			# After 5+ minutes, reset values to be able to alert to screen
			elif (dns.getCount() > 0 and abs(dns.getDiff() - datetime.datetime.now().minute) >= 6):
				dns.log_count = 0
				dns.setMinute(0)

			# Increment Count
			else:
				dns.incrementCount()

##################### END PACKET DETECTION AND HANDLING ###############################


# ATTEMPTS TO DO PORT SCANNING
# Unfortunately I'm missing something 

def portScanning(pkt):

	# Bool for incrementing packet
	incValue = True

	# Checks the specified layers
	if pkt[0].haslayer(TCP) or pkt[0].haslayer(UDP):

		# Setting values according to protocol
		if pkt[0].haslayer(TCP):
			packet = pkt[IP].src
			dport = pkt[TCP].dport

		elif pkt[0].haslayer(UDP):
			packet = pkt[IP].src
			dport = pkt[UDP].dport

		# If dport value value
		if dport:

			# If Packet Dictonary empty, add objects.
			if packet in pkt_dict.keys():

				# If the value has been logged before, skip count
				if dport in dport_dict[packet]:
					incValue = False

				# Otherwise, append to dictionary
				else:
					dport_dict[packet].append(dport)

				# Arbitrary value chosen for scanning
				if pkt_dict[packet] >= 20:
					if (time.time() - time_dict[packet]) < 0.500:
						pck_dict[packet] = 0
						time_dict[packet] = time.time()
						dport_dict[packet] = []
						print("Port Scanning Intrusion by: " + packet)

				# Otherwise, increment value 
				elif incValue:
					pkt_dict[packet] += 1

			# If packet not in dictionary, add it.
			else: 
				pkt_dict[packet] = 1
				time_dict[packet] = time.time()
				dport_dict[packet] = [dport]


####################### LOGGING FUNCTIONALITY #########################################
	
# Function to lop Blacklisted IP Addresses	
def logIP(ip):

	# Update the global log counter 
	global count
	count += 1

	try:
		logfile = open(output, "a")
		logfile.write("[" + str(count) + "] BLACKLISTED IP: " + ip.getIP())
		logfile.write("\tTIMESTAMP: " + str(datetime.datetime.now()) + "\n")
		logfile.close()

	except IOError:
		print("ERROR: Cannot open " + output)

# Function to log Blacklisted DNS
def logDNS(dns):

	# Update the global log counter 
	global count
	count += 1

	try:
		logfile = open(output, "a")
		logfile.write("[" + str(count) + "] BLACKLISTED DNS: " + dns.getDNS())
		logfile.write("\tTIMESTAMP: " + str(datetime.datetime.now()) + "\n")
		logfile.close()

	except IOError:
		print("ERROR: Cannot open " + output)	

# Function to log Blacklisted Strings
def logString(string, GET_request, dst):

	# Update the global log counter 
	global count
	count += 1

	try:
		logfile = open(output, "a")
		logfile.write("[" + str(count) + "] BLACKLISTED STRING: [" + string + "] in GET request to [" + str(dst) + "]")
		logfile.write("\tTIMESTAMP: " + str(datetime.datetime.now()) + "\n")
		logfile.write(" \ Located in: " + str(GET_request) + "\n")
		logfile.close()

	except IOError:
		print("ERROR: Cannot open " + output)


def logSignature(signature, dst):

	# Update the global log counter 
	global count
	count += 1

	try:
		logfile = open(output, "a")
		logfile.write("[" + str(count) + "] BLACKLISTED SIGNATURE: [" + str(signature) + "] packet to [" + str(dst) + "]")
		logfile.write("\tTIMESTAMP: " + str(datetime.datetime.now()) + "\n")
		logfile.close()

	except IOError:
		print("ERROR: Cannot open " + output)

################### END LOGGING FUNCTIONALITY #########################################



# Function to parse .pcap files
def pcap_parser():

	print("Checking " + pcap + "...")

	# Read in the pcap file
	r_pcap = rdpcap(pcap)

	# Check each packet in the pcap file
	for pkt in r_pcap:
		checkPacket(pkt)
	
	print("Done. Exiting now...")

def main():	
	
	# Parse the command line arguments
	parse()

	# If a pcap file is not provided, monitor live traffic
	if online:
		sniffPackets()

	# If pcap file is provided, check pcap file
	else:
		pcap_parser()


main()
