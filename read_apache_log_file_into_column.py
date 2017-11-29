#!/usr/bin/python3

import argparse
import csv
import re


def extract_fields(line):

    log_line_re = re.compile(r'''(?P<remote_host>\S+) #IP ADDRESS
                                \s+ #whitespace
                                (?P<remote_log_name>\S+) #remote log name
                                \s+ #whitespace
                                (?P<remote_user>\S+) #remote user
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


parser = argparse.ArgumentParser()
parser.add_argument("-f", "--file", help="specify a log file to analyse.")
args = parser.parse_args()

apache_log_file = args.file

with open(apache_log_file, 'r') as fr, open("apache_log_file_analysis.csv", 'w') as fw:

    fieldnames = ['remote_host', 'remote_log_name', 'remote_user', 'time', 'url', 'status', 'bytes_sent']
    writer = csv.DictWriter(fw, fieldnames=fieldnames)
    writer.writeheader()

    for line in fr:
        fields = extract_fields(line)
        writer.writerow(fields)


