
import argparse
import apache_log_parser

parser = argparse.ArgumentParser()
parser.add_argument("-f", "--file", help="specify the log file to analyse.")
parser.add_argument("-r", "--top_n_requesters", type=int, help="list the top n requesters.")
parser.add_argument("-p", "--top_n_requested_pages", type=int, help="list the top n requested pages.")
args = parser.parse_args()

apache_log_file = args.file

# both cannot be true at the same time.
if args.top_n_requested_pages:
    search_field = 'visited_page'
    n = args.top_n_requested_pages
elif args.top_n_requesters:
    search_field = 'remote_host'
    n = args.top_n_requesters

if __name__ == '__main__':
    with open(apache_log_file, 'r') as f:
        # apache_log_parser.ipOwner(n)
		# apache_log_parser.topRequesters(f, top_n_requesters)
		# apache_log_parser.top(f, search_field, n)
		# apache_log_parser.topRequestedPages(f)
        # apache_log_parser.unsuccessfulReq(f)
        apache_log_parser.unsuccessfulPages(f, 10)

