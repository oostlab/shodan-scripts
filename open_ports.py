#!/usr/bin/env python
#
# open_ports.py
# Search SHODAN with a IP range and print a list of all open ports
#
# Author: Bert Oostland

import shodan

api = shodan.Shodan('*')
result = api.count('net:131.211.0.0/16', facets=[['port', 50]])
all_ports = result['facets']['port']

# print list of a count of all open ports
for port in all_ports:
    print('port: {0:5} - count: {1:5}'.format(port['value'], port['count']))
    