from ipwhois import IPWhois
import re
import argparse
from dateutil.parser import parse
import datetime


def convert_apache_timestamp(timestamp):
    return parse(timestamp[:11] + " " + timestamp[12:])


def extract_fields(line):

    log_line_re = re.compile(r'''(?P<remote_host>\S+) #IP ADDRESS
                                \s+ #whitespace
                                \S+ #remote log name
                                \s+ #whitespace
                                \S+ #remote user
                                \s+ #whitespace
                                (?P<time>\[[^\[\]]+\]) #time
                                \s+ #whitespace
                                (?P<url>"[^"]+") #first line of request
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


def who_is(ip):
    obj = IPWhois(ip)
    results = obj.lookup_rdap(depth=1)
    return results['asn_description']


def matplotlib_input(list):
    i = 0

    l = []
    m = []

    while i < len(list):
        l.append(list[i][0])
        m.append(list[i][1])
        i += 1

    return ([l, m])


def top_request_ip(file, n):
    ips = {}

    for line in file:

        groupdict = extract_fields(line)

        ip = groupdict['remote_host']

        # possible to use setdefault()?
        if ip not in ips:
            ips[ip] = 1
        else:
            ips[ip] += 1

    # requesters_dict = [(k, ips[k]) for k in sorted(ips, key=ips.get, reverse=True)]
    requesters_dict = [[k, ips[k]] for k in sorted(ips, key=ips.get, reverse=True)]

    # return first n elements
    return requesters_dict[:n]  # [['76.97.16.122', 290], ['217.16.8.81', 161]]


def top(file, keyword, n):
    d = {}

    for line in file:

        groupdict = extract_fields(line)

        field = groupdict[keyword]

        if field not in dict:
            d[field] = 1
        else:
            d[field] += 1

    top_list = [(k, d[k]) for k in sorted(d, key=d.get, reverse=True)]

    # number of requests should be retrieved from user input
    for field_name, count in top_list[:n]:
        print(field_name + "\t\t" + str(count))


def successful_requests(file):
    # number of lines in file should be counted before the file is iterated
    line_count = 0

    successful_req_status_code = {}

    successful_req_re = re.compile('2\d{2}')

    for line in file:

        line_count += 1

        groupdict = extract_fields(line)

        field = groupdict['status']

        # 2xx should be any 2xx successful requests
        if successful_req_re.match(field):
            if field not in successful_req_status_code:
                successful_req_status_code[field] = 1
            else:
                successful_req_status_code[field] += 1

    successful_reqs = sum(successful_req_status_code.values())

    successful_requests_percentage = float(successful_reqs) / float(line_count)

    print("Percentage of successful requests: {:.1%}".format(successful_requests_percentage))

    return successful_requests_percentage


def unsuccessful_requests(file):
    print("Percentage of unsuccessful requests: {:.1%}".format(1 - successful_requests(file)))


def unsuccessful_pages(file, n):
    successful_req_re = re.compile('2\d{2}')

    unsuccessful_pages_dict = {}

    for line in file:

        groupdict = extract_fields(line)

        status = groupdict['status']

        page = groupdict['url']

        if not successful_req_re.match(status):
            if page not in unsuccessful_pages_dict:
                unsuccessful_pages_dict[page] = 1
            else:
                unsuccessful_pages_dict[page] += 1

    # sorted() returns a list includes the key
    unsuccessful_pages_dict_list = [(k, unsuccessful_pages_dict[k]) for k in
                                    sorted(unsuccessful_pages_dict, key=unsuccessful_pages_dict.get, reverse=True)]

    for page, count in unsuccessful_pages_dict_list[:n]:
        print(page + "\t\t" + str(count))


def request_per_min(file):
    req_per_min = {}

    for line in file:
        groupdict = extract_fields(line)
        time = groupdict['time'].strip('[]')
        std_time = convert_apache_timestamp(time)
        integral_min = std_time.replace(second=0)
        add_one_min = datetime.timedelta(minutes=1)
        next_integral_min = integral_min + add_one_min
        next_integral_min_str = str(next_integral_min)  # convert the datetime object to string format

        if integral_min <= std_time <= next_integral_min:
            if next_integral_min_str not in req_per_min:
                req_per_min[next_integral_min_str] = 1
            else:
                req_per_min[next_integral_min_str] += 1
        else:
            print("The time format is invalid.")

    return req_per_min


def top_ip_page_requested(file, m, n):
    """
    :param file: opened apache log file
    :param m: top m request ip
    :param n: top n requested pages for each ip
    :return: print top m request ip, top n requested pages for each ip

    """

    # maintain # of requests made by requesters(ip) list in descending order
    d = {}

    # maintain # of requested pages for each ip in dictionary d in descending order
    e = {}

    for line in file:

        groupdict = extract_fields(line)

        ip = groupdict['remote_host']

        page = groupdict['url'].strip('"')

        if ip not in d:
            d[ip] = 1
            e[ip] = {}
            e[ip][page] = 1
        else:
            d[ip] += 1
            if page not in e[ip]:
                e[ip][page] = 1
            else:
                e[ip][page] += 1

    top_ip = sorted(d, key=d.get, reverse=True)

    top_n_ip_list = top_ip[:m]

    print("IP" + "\t\t" + "Page" + "\t\t" + "Requests")

    for i in top_n_ip_list:

        top_page_request = e.get(i)

        sorted_top_page_request = [(k, top_page_request[k]) for k in
                                   sorted(top_page_request, key=top_page_request.get, reverse=True)]

        for j in sorted_top_page_request[:n]:
            print(str(i) + "\t\t" + j[0] + "\t\t" + str(j[1]))


parser = argparse.ArgumentParser()
parser.add_argument("-f", "--file", help="specify a log file to analyse.")
parser.add_argument("-r", "--top_n_requesters", type=int, help="list the top n requesters.")
parser.add_argument("-p", "--top_n_requested_pages", type=int, help="list the top n requested pages.")
args = parser.parse_args()

apache_log_file = args.file

# both cannot be true at the same time.
if args.top_n_requested_pages:
    search = 'url'
    n = args.top_n_requested_pages
elif args.top_n_requesters:
    search = 'remote_host'
    n = args.top_n_requesters

with open(apache_log_file, 'r') as f:
    # apache_log_parser.ipOwner(n)
    # successful_requests(f)
    # apache_log_parser.top(f, search, n)
    # apache_log_parser.topRequestedPages(f)
    # apache_log_parser.unsuccessful_requests(f)
    # apache_log_parser.unsuccessful_pages_dict(f, 10)
    # print(request_per_min(f))
    # top_ip_page_requested(f, 10 ,5)
    # print(top_request_ip(f, 10))

    import matplotlib

    matplotlib.use('Agg')

    import matplotlib.pyplot as plt

    v = matplotlib_input(top_request_ip(f, 10))

    x_axes = v[0]
    y_axes = v[1]
    plt.plot(x_axes, y_axes, 'ro')
    plt.savefig('top_requesters.png')
