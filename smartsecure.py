'''
-- CS 6250
-- version 24 : Byte counts + DPI + Rate limiting  
 
-- Final Project : SDN based Rate limiter
		   Features implemented :
		   1. Block flows based on packet flooding
		   2. Block flows based on port scanning
		   3. Block flows based on data limits
Changelog : Removed packet count 
	    Added functionality for byte count with rate limiting
	    Plus dpi functionality


		

Authors : Nitesh Sinha, Jobin John, Srinath Tupil, Akhilesh Anupindi
'''

from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.examples.pyretic_switch import act_like_switch
from csv import DictReader
from collections import namedtuple
from pyretic.lib.query import *
from pyretic.modules.mac_learner import mac_learner
import os
import re
import termcolor as T

from csv import DictReader
from collections import namedtuple

def cprint(s, color, cr=True):
    """Print in color
       s: string to print
       color: color to use"""
    if cr:
        print T.colored(s, color)
    else:
        print T.colored(s, color),



policy_file = "%s/pyretic/pyretic/examples/port_policies.csv" % os.environ[ 'HOME' ]
Policy = namedtuple('Policy', ('port'))

#src_dict = {}
#host_dict = {}
port_scan = {}
#threshold = 20
#portScanThresh = 10
#prev_policy = drop
byteThresh_blocklist = []
total_blocklist = []
#policy = identity
lock = 0
perm_policy = None
temp_policy = None
query_policy = None

class firewall(DynamicPolicy):
	#global host_dict
	#global total_bytes
	
	def __init__(self):		
		global query_policy, temp_policy
		query_policy = count_bytes(1, ['srcip','srcmac','dstport','ethtype','dstip']) 

		temp_policy = identity
			

		# Read in the ports to be blocked from the port_policies.csv file
		def read_policies (file):
			with open(file, 'r') as f:
            			reader = DictReader(f, delimiter = ",")
            			policies = {}
            			for row in reader:
                			policies[row['id']] = Policy((row['port']))
        		return policies
		
		
		def get_byte_count(byte_counts):
			global byteThresh_blocklist
			global total_blocklist
			global perm_policy
			global temp_policy
			global query_policy
			global lock
	
			host_dict = {}
			byte_threshold = 2000
			rate_threshold = 5000 
			portScanThresh = 10
			#total_bytes=0
			#print "inside getbyte"
			#print "byte counts=", byte_counts



			key= byte_counts.keys()
			#print "length of byte_counts=",len(key)
	
			while(len(key)!=0):
				#print "**********One time interval start*****************"
				for flows in byte_counts.keys():
					fields = flows.map
					arp = fields['ethtype']
					dst_ip = fields['dstip']
					src_ip = fields['srcip']

					#print str(dst_ip)
				
					if (str(dst_ip) == '10.0.0.4' and fields['srcmac'] not in total_blocklist):
						#print "Current block list is ",total_blocklist

						#print "@####$$$$$$$$$$$$INNNNNNNNNNNNNNNNNN"
						#q = packets()
						if (lock == 0):
							q = packets()
							self.policy = self.policy + q
							q.register_callback(dpi_function)
							lock = 1
										



					#proto = fields['protocol']
					if(arp == 2048 and  fields['srcmac'] not in byteThresh_blocklist): #and (proto == 6) or (proto == 17)):
						dst_port = fields['dstport']
						host_mac = fields['srcmac']
						if(host_mac not in host_dict):
							host_dict[host_mac] = 0
						if ( src_ip not in port_scan):
                                                	port_scan[src_ip] = []

						#test for port scanning
                                                port_list = port_scan[src_ip]
                                                if dst_port not in port_list:
                                                        port_list.append(dst_port)


						host_dict[host_mac] = byte_counts.get(flows)
						print "total byte count for ",host_mac," is ", host_dict[host_mac]		
						
						if(host_dict[host_mac] > byte_threshold and host_mac not in total_blocklist):
							#print "Blocking based on rate"
							#cprint("*** Lower threshold exceeded!!! Blocking specific ports", "green")
							#print "temp policy is ", temp_policy
							for policy_port in policies.itervalues():
								if( temp_policy is identity):
									temp_policy = if_(match(dstport = policy_port.port ,srcmac = EthAddr(host_mac)),drop)
								else:

									temp_policy = temp_policy + if_(match(dstport = policy_port.port ,srcmac = EthAddr(host_mac)),drop)
								#print "Blocking port: ", policy_port.port
								#cprint("*** Blocking port: %d",polyc_port.port, "green")
							if( perm_policy is not None):
							
								self.policy = perm_policy + query_policy >> temp_policy
								lock = 0
							else:
								self.policy = query_policy + temp_policy
								lock = 0

							#print "self.policy is ", self.policy
							byteThresh_blocklist.append(host_mac)
							print " Lower byte threshold exceeded for mac address ",host_mac,"Blocking specific ports"
							#cprint("*** Lower byte threshold exceeded for mac: %s!! Blocking specific ports",str(host_mac), "green")

						if(len(port_list) > portScanThresh and fields['srcip'] not in total_blocklist):
	                                                #print "Firewall blocking flow due to excessive port scan"
							cprint("Firewall blocking flow due to excessive port scan", "magenta")
							if( perm_policy is not None):
        	                                        	perm_policy = perm_policy +  if_(match(srcip=IPAddr(src_ip),dstip=IPAddr(dst_ip)), drop, identity)
                	                                else:
								perm_policy =  if_(match(srcip=IPAddr(src_ip),dstip=IPAddr(dst_ip)), drop, identity)
							self.policy = perm_policy + query_policy
							lock = 0
							total_blocklist.append(src_ip)
	

					if(arp != 2054 and fields['srcmac'] in byteThresh_blocklist and fields['srcmac'] not in total_blocklist):
							host_mac = fields['srcmac']
							host_dict[host_mac] = byte_counts.get(flows)
							if(host_dict[host_mac] > rate_threshold):
								prev_policy = self.policy
								self.policy = drop
								#print "Policy for current packets is ",self.policy
								time.sleep(5)
								#perm_policy = if_(match(srcmac = EthAddr(host_mac)),drop)
								#self.policy = perm_policy + query_policy 
								self.policy = prev_policy
								#print "After rate limiting policy changed to",self.policy
								
								print "Now",host_mac," has been rate limited"
								#cprint(" Now %s has been rate limited",str(host_mac),"red")
								total_blocklist.append(host_mac)
							#print "self.policy is : ", self.policy
						
						
				

		
				print "current policy is", self.policy		  
				print "*****************One time interval ends**************************"
				break

	
		policies = read_policies(policy_file) 
		query_policy.register_callback(get_byte_count)
		
		#Initialize dynamic policy
		super(firewall,self).__init__(temp_policy + query_policy )
	
	
	
		def dpi_function(pkt):
			global perm_policy
			global query_policy
			global lock
			global total_blocklist
			#global policy
			print "------packet--------"
			print pkt
			if pkt['srcmac'] not in total_blocklist:
				if pkt['ethtype'] == IP_TYPE:
				#print "Ethernet packet, try to decode"
					raw_bytes = [ord(c) for c in pkt['raw']]
					#print "ethernet payload is %d" % pkt['payload_len']    
					eth_payload_bytes = raw_bytes[pkt['header_len']:]   
					#print "ethernet payload is %d bytes" % len(eth_payload_bytes)
					ip_version = (eth_payload_bytes[0] & 0b11110000) >> 4
					ihl = (eth_payload_bytes[0] & 0b00001111)
					ip_header_len = ihl * 4
					ip_payload_bytes = eth_payload_bytes[ip_header_len:]
					ip_proto = eth_payload_bytes[9]
					print " ip_proto = ", ip_proto
					
					if ip_proto == 0x06:
						print "TCP packet, try to decode"
						tcp_data_offset = (ip_payload_bytes[12] & 0b11110000) >> 4
						tcp_header_len = tcp_data_offset * 4
						tcp_payload_bytes = ip_payload_bytes[tcp_header_len:]
						if len(tcp_payload_bytes) > 0:
							tcp_paylod = ''.join([chr(d) for d in tcp_payload_bytes])
							str_tcp = str(tcp_payload)
							print "tcp payload is", str_tcp
							searchTcpObject = re.search("(gatech)",str_tcp)
							if(searchTcpObject.groups()[0] == "gatech"):
								if(perm_policy is not None):
									perm_policy = perm_policy + if_(match(srcip = pkt['srcip']),drop,identity)
								else:
									perm_policy = if_(match(srcip = pkt['srcip']),drop,identity)
								#perm_policy  = perm_policy + if_(match(srcmac =pkt['srcmac']),drop,identity) 
								self.policy =  perm_policy + query_policy
								total_blocklist.append(pkt['srcmac']) 
								lock = 0
								print "DPI blocking TCP flow"
					elif ip_proto == 0x11:
						print "UDP packet, try to decode"
						udp_header_len = 8
						udp_payload_bytes = ip_payload_bytes[udp_header_len:]
						if len(udp_payload_bytes) > 0:
							udp_payload = ''.join([chr(d) for d in udp_payload_bytes])
							str_udp = str(udp_payload)
							print "udp payload is ", str_udp
							searchUdpObject = re.search("(gatech)",str_udp)
							if(searchUdpObject is not None):
								if(searchUdpObject.groups()[0] == "gatech"):
									if(perm_policy is not None):
										perm_policy = perm_policy + if_(match(srcip = pkt['srcip']),drop,identity)							
									else:
										perm_policy = if_(match(srcip = pkt['srcip']),drop,identity)
									self.policy = perm_policy + query_policy
									total_blocklist.append(pkt['srcmac'])
									lock = 0
									#print "DPI blocking UDP flow"
									cprint("DPT blocking UDP flow","yellow")
							
					elif ip_proto == 0x01:
						print "ICMP packet"
					else:
						print "Unhandled packet type"

			print "The current policy after DPI blocking is ", self.policy
			

	
		#def dpi():
		#	global temp_policy
		#	print "inside the dpi bitch"
		#	q = packets()
		#	self.policy = self.policy + q
		#	q.register_callback(dpi_function)
		#	temp_policy = q

		
def main():    
   return ( firewall() >> act_like_switch())


