#!/Users/yijia/py3/bin/python3

from ipwhois import IPWhois
from pprint import pprint

obj = IPWhois('74.125.225.229')
results = obj.lookup_rdap(depth=1)
pprint(results)
