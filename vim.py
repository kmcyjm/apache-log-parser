from ipwhois import: :IPWhois
import re

def extractFields(line):

    log_line_re = re.compile(r'''(?P<remote_host>\S+) #IP ADDRESS
                                 \s+ #whitespace
                                 \S+ #remote logname
                                 \s+ #whitespace
                                 \S+ #remote user
                                 \s+ #whitespace
                                 \[[^\[\]]+\] #time
                                 \s+ #whitespace
                                 (?P<visited_page>"[^"]+") #first line of request
                                 \s+ #whitespace
                                 (?P<status>\d+)
                                 \s+ #whitespace
                                 (?P<bytes_sent>-|\d+)
                                 \s* #whitespace
                                 ''', re.VERBOSE)

    m = log_line_re.match(line)

    if m:
        groupdict = m.groupdict()
        return groupdict
    else:
        print("Please check the regular expression, or the log entry to see why they don't match.")


def whoIs(ip):

    obj = IPWhois(ip)
    results = obj.lookup_rdap(depth=1)
    return results['asn_description']

def topRequesters(file, top_n_requesters):

    ips = {}

    for line in file:

        groupdict = extractFields(line)

        ip = groupdict['remote_host']

        # possible to use setdefault()?
        if ip not in ips:
            ips[ip] = 1
        else:
            ips[ip] += 1

    print("Origin" + "\t\t" + "# of requests" + "\t\t" + "IP Owner")

    requesters_list = [(k, ips[k]) for k in sorted(ips, key=ips.get, reverse=True)]

    # number of requests should be retrieved from user input
    for ip, requests in requesters_list[:top_n_requesters]:
        print(ip + "\t\t" + str(requests) + "\t\t" + whoIs(ip))


def topRequestedPages(file, top_n_requestedPages):

    pages = {}

    for line in file:
        url = extractFields(line)['visited_page']
        print(page)