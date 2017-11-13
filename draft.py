import argparse

def toprequesters():

	parser = argparse.ArgumentParser()
	parser.add_argument("file", help="specify the log file to analyse.")
	parser.add_argument("top_n_requesters", help="list the top n requesters.")
	args = parser.parse_args()

	file = args.file
	number_of_requesters = int(args.top_n_requesters)

	# file name should be retrieved from command line.
	with open(file, 'r') as f:

	    ips = {}

	    for line in f:

	        ip = line.split()[0]

	        # possible to use setdefault()?
	        if ip not in ips:
	            ips[ip] = 1
	        else:
	            ips[ip] += 1

	    print("Origin\t\t\# of requests")

	    top_requesters_list = [(k, ips[k]) for k in sorted(ips, key=ips.get, reverse=True)]

	    # 10 should be retrieved from user input
	    for ip, requests in top_requesters_list[:number_of_requesters]:
	        print(ip + "\t\t" + str(requests))

def ipOwner():
	pass

def topPages():
	pass