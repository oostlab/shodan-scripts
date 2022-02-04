#!/usr/bin/env python
#
# open_ports.py
# Versie 1.0
# Search SHODAN with a IP range and print a list of all open ports
#
# Author: Bert Oostland

import shodan
import json
import sys

# function section
def save_list():
    # save the all_ports dictionary to file
    with open('port_list.txt', 'w') as convert_file:
        convert_file.write(json.dumps(all_ports))

def load_list(filename):
     # loads reference port dictionary from file
     try:
         with open(filename) as f:
             data = f.read()

         # reconstructing the data as a dictionary
         return json.loads(data)
     except:
         # file does not exists, return empty dictonairy
         dataload = {}
         return dataload

# variable definition
all_ports = {}

print('*****************************************************')       
print('* Shodan port scanner                               *')
print('* Author: Bert Oostland                             *')
print('* Version: 1.0                                      *')
print('*                                                   *')
print('*Usage: open_ports.py api-key IPRange ref-file      *')
print('* api-key: shodan apikey                            *')
print('* IPRange: bv 192.168.0.0/16                        *')
print('* Ref-file: File with port reference,               *')
print('*****************************************************')

if len(sys.argv) != 4:
    print('Wrong number of arguments')
    exit()
else:
    # setting user variables
    shodan_key = sys.argv[1]
    IP_range = 'net:'+sys.argv[2]
    filename = sys.argv[3]
 
# Make shodan query call
api = shodan.Shodan(shodan_key)
result = api.count(IP_range, facets=[['port', 50]])
count_ports = result['facets']['port']

# count_ports is a list of dictionaries with count as key and ports as value
# This list will be converted in a dictionary with port as key and count as value
for port in count_ports:
    # add port and count to port dictionary, reverse key-pair
    # print('  port: {0:5} - count: {1:5} '.format(port['value'], port['count']))
    all_ports[port['value']]= port['count']

ref_ports = load_list(filename)

# print all found ports and compare with ref list
for port in all_ports:
    # Check if port is found in ref_ports
    if str(port) in ref_ports.keys():
        if all_ports[port] == ref_ports[str(port)]:
            # port number and count are the same, no change
            print('  port: {0:5} - current: {1:5} - old {2:5}'.format(port, all_ports[port], ref_ports[str(port)]))
            # remove port from ref list, this way we check if a port is removed from the scan
            ref_ports.pop(str(port))
        else:
            # Count is different, more ports or less ports 
            if all_ports[port] <  ref_ports[str(port)]:
                print('- port: {0:5} - current: {1:5} - old {2:5}'.format(port, all_ports[port], ref_ports[str(port)]))
            else: # More open ports
                print('+ port: {0:5} - current: {1:5} - old {2:5}'.format(port, all_ports[port], ref_ports[str(port)]))
            # remove port from ref list, this way we check if a port is removed from the scan
            ref_ports.pop(str(port))
    else:
        # a new port is found
        print('+ port: {0:5} - current: {1:5}'.format(port, all_ports[port]))

# check if there a less port found the in the reference file
if len(ref_ports) != 0:
    # print all not found again port and values
    print('Ports removed from IP range')
    for port in ref_ports:
        print('-  ref port: {0:5} - old: {1:5}'.format(port, ref_ports[str(port)]))

save_list()
