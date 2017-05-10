import socket
import os
from time import gmtime, strftime
def getKey(item):
	return item[1]

def getConnections():
	# run program as "python.exe PATHTO\connection.py" then move readme.json, topSrc.tsv, topDst.tsv, and topProt.tsv to website folder
	src_list = []
	dst_list = []
	prot_list = []
	print("Please enter file name, must be a pcap\n")	
	filename = input()
	newfilename = strftime("%Y-%m-%d-%H:%M:%S", gmtime())+ ".csv"
	command = "tshark -r " + filename + " -T fields -e ip.src -e ip.dst -e ip.proto -E separator=, >" + newfilename 
	print(command)
	os.system(command)
	with open(newfilename) as f:
		Dict = {}                                                                                               # create empty dictionary
		content = []                                                                                    # create empty list
		content = f.readlines()                                                                 # get every line of the file and add to a list
		content = [item.strip() for item in content]                    # strip each line in the file of newline characters and etc.
		lineNum = 0                                                                                             # Checks line number being processed.
		for line in content:                                                                    # go through each line in the file
			test = 0
			fields = []                                                                                     
			fields = line.split(',')                                                        # split each line into a list   
#			i = 0                                                                                           
#			for item in fields:                                                                     #go through each item in the line list          
#				fields[i] = item[1:-1]                                                  # remove the first and last characters with are " and "
#				i = i + 1                                                                               
			src_ip = fields[0]                                                                      # source ip is at index 2
			dst_ip = fields[1]                                                                      # destination ip is at index 3
			prot_name = fields[2]                                                           # protocol name is at index 4
			
			
			#protocol = fields[4]                                                           # future work
			#src_port = fields[6].split(" ")[0]
			#dst_port = fields[6].split(" ")[4]
			
			try:                                                                                            # check if valid IPv4 address
				socket.inet_aton(src_ip)                                                
			except socket.error:                                                            
				continue
			#creates lists of source and destination IPs, and protocols and counts times they are encountered.
			if(lineNum != 0):
				if (len(src_list) == 0):
					src_list.append([src_ip,1])
				else:
					for src in src_list:
						if (src[0]==src_ip):
							src[1] += 1
							test = 1
					if (test == 0):
						src_list.append([src_ip,1])
				test = 0
				if (len(dst_list) == 0):
					dst_list.append([dst_ip,1])
				else:
					for dst in dst_list:
						if (dst[0]==dst_ip):
							dst[1] += 1
							test = 1
					if (test == 0):
						dst_list.append([dst_ip,1])
				test = 0
				if (len(prot_list) == 0):
					prot_list.append([prot_name,1])
				else:
					for prot in prot_list:
						if (prot[0]==prot_name):
							prot[1] += 1
							test = 1
					if (test == 0):
						prot_list.append([prot_name,1])
			if (src_ip not in Dict):                                                        # check if the source ip is already in Dictionary
				Dict[src_ip] = []                                                               # add the source ip with an empty list value

			if (dst_ip not in Dict[src_ip]):                                        # check if destination ip is already mapped to source ip
				Dict[src_ip].append((dst_ip))                                   # add destination ip to value list of source ip
			lineNum = lineNum + 1 
	fh = open("readme.json","w")
	print("[", file=fh)                                                                                                     # print the Dict in the json format
	nsources = len(Dict) -1                                                                         # get the number of connections 
	for x in Dict:                                                                                          # go through each source/destination list
		print("{\"name\":\"flare." + str(x) + ".end\",\"size\":2000,\"imports\":[",end="", file=fh)
		count = len(Dict[x]) - 1                                                                # get the number of values for current source ip
		for y in Dict[x]:                                                                               # go through each value
			print("\"flare." + str(y) + ".end\"" ,end="", file=fh) 
			if (count != 0):                                                                        # check to see if you are at the end of value list
				print(",",end="", file=fh)                                                              # print a , if not last item in list
				count = count - 1                                                               # increment downwards since you are moving to the next item in list
		print("]}",end="",file=fh)
		if (nsources != 0):                                                                             # check to see if last key in dictionary
			print(",",file=fh)                                                                                      # print a , if not key in dictionary
			nsources = nsources - 1                                                         # increment downwards since you are moving to next item in dictionary
		
	print("\n]",file=fh)
	fh.close()
	src_list = sorted(src_list, key=getKey, reverse=True)
	fh1 = open("topSrc.tsv","w")
	print("ip\tconnections\n",end="",file=fh1)
	ctr = 0
	for src in src_list:
		if(ctr == 5):
			break
		print("%s\t%s\n" % (src[0],src[1]),end="",file=fh1)
		ctr = ctr+1
	fh1.close()
	dst_list = sorted(dst_list, key=getKey, reverse=True)
	fh2 = open("topDst.tsv","w")
	print("ip\tconnections\n",end="",file=fh2)
	ctr = 0
	for dst in dst_list:
		if(ctr == 5):
			break
		print("%s\t%s\n" % (dst[0],dst[1]),end="",file=fh2)
		ctr = ctr+1
	fh2.close()
	prot_list = sorted(prot_list, key=getKey, reverse=True)
	fh3 = open("topProt.tsv","w")
	print("ip\tconnections\n",end="",file=fh3)
	ctr = 0
	for prot in prot_list:
		if(ctr == 5):
			break
		if(prot[0]!="TCP"):
			print("%s\t%s\n" % (prot[0],prot[1]),end="",file=fh3)
			ctr = ctr+1
	fh3.close()
	return Dict

def main():
	getConnections()
	
main()
