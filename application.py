#!/usr/bin/python env
#
# read the contents of /proc/net/tcp every 10 seconds and output new connections
# new connections are connections that have the state of established, 01 in /proc/net/tcp
#
# start
#

from datetime import datetime
import time

def split_every_n(data, n):
    return [data[i:i+n] for i in range(0, len(data), n)]

def convert_linux_netaddr(address):

    hex_addr, hex_port = address.split(':')

    addr_list = split_every_n(hex_addr, 2)
    addr_list.reverse()

    addr = ".".join(map(lambda x: str(int(x, 16)), addr_list))
    port = str(int(hex_port, 16))

    return "{}:{}".format(addr, port)

def print_data(timestamp, raddr_sport, host_addr_dport):

    print("{}: New Connection: {} -> {}".format(timestamp, raddr_sport, host_addr_dport))


def main():
    
    # lists to store current and inbound connections
    current = []
    inbound = []
    
    # dict that stores data to be checked for ports scanning activity 
    connection_data = {}

    # this counter is used to check whether a minute has passed - used to trigger the portscan check
    minute_counter = 0
    # this counter is used to determine whether /proc/net/tcp has been read previously
    n = 0
    
    while True:

        # increment the check minute counter by 1
        minute_counter += 1

        with open('/proc/net/tcp') as f:
            raw_sockets = (f.read()).split('\n')[1:-1]
            sockets = [line.strip() for line in raw_sockets]

        time_now = datetime.now()
        timestamp = time_now.strftime("%Y-%m-%d %H:%M:%S")
        
        for s in sockets:            
            host_addr_dport = convert_linux_netaddr(s.split()[1])
            raddr_sport = convert_linux_netaddr(s.split()[2])
            connection_state = s.split()[3]            

            # get the host destination port
            host_dport = host_addr_dport.split(':')[1]

            # an established connection is 01
            if connection_state == '01':
                if n == 0:
                    print_data(timestamp, raddr_sport, host_addr_dport)
                    current.append(raddr_sport + ' ' + host_addr_dport)
                    
                    # dict that stores data to be checked for port scanning activity 
                    connection_data[raddr_sport] = {}
                    connection_data[raddr_sport]['timestamp'] =  timestamp
                    connection_data[raddr_sport]['dport'] = host_dport
                else:
                    # add remote address, source port, host address and destination port to list
                    inbound.append(raddr_sport + ' ' + host_addr_dport)
                    #
                    new_connection_list =  [x for x in inbound if x not in set(current)]
                    #
                    if len(new_connection_list):
                        for entry in new_connection_list:
                            print_data(timestamp, raddr_sport, host_addr_dport)
                            current.append(entry.split(' ')[0] + ' ' + entry.split(' ')[1])            
                            # dict that stores data to be checked for ports scanning activity 
                            connection_data[raddr_sport] = {}
                            connection_data[raddr_sport]['timestamp'] =  timestamp
                            connection_data[raddr_sport]['dport'] =  host_dport               
                            # clear inbound list
                            inbound.clear()
                            
        r_addr_ip_list = []
        # check if the minute counter is equal to 6
        if minute_counter == 4:
            for k, v in connection_data.items():
                r_addr = k.split(':')[0]
                r_addr_ip_list.append(r_addr)
            
            for i in r_addr_ip_list:
                if r_addr_ip_list.count(i) > 2:
                    for k, v in connection_data.items():
                        if i in k:
                            print(i, v.get('dport'))
            
            r_addr_ip_list.clear()
            minute_counter = 0

        # increment minute check counter 
        
        # increment counter            
        n += 1
        # sleep 5 seconds
        time.sleep(5)

if __name__ == '__main__':
    main()

