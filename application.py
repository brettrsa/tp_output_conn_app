#!/usr/bin/python env
#
# read the contents of /proc/net/tcp every 10 seconds and output new connections
# new connections are connections that have the state of established, 01 in hex
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

def print_data(timestamp, raddr_rport, laddr_lport):

    print("{}: New Connection: {} -> {}".format(timestamp, raddr_rport, laddr_lport))

def main():
    
    # lists to store current and inbound connections
    current = []
    inbound = []
    
    # counter
    n = 0
    
    while True:

        with open('/proc/net/tcp') as f:
            raw_sockets = (f.read()).split('\n')[1:-1]
            sockets = [line.strip() for line in raw_sockets]

        time_now = datetime.now()
        timestamp = time_now.strftime("%Y-%m-%d %H:%M:%S")
        
        for s in sockets:            
            laddr_lport = convert_linux_netaddr(s.split()[1])
            raddr_rport = convert_linux_netaddr(s.split()[2])
            connection_state = s.split()[3]            

            # an established connection is 01
            if connection_state == '01':
                if n == 0:
                    print_data(timestamp, raddr_rport, laddr_lport)
                    current.append(raddr_rport + ' ' + laddr_lport)
                else:
                    inbound.append(raddr_rport + ' ' + laddr_lport)
                    new_connection_list =  [x for x in inbound if x not in set(current)]
                    if len(new_connection_list):
                        for entry in new_connection_list:
                            print_data(timestamp, raddr_rport, laddr_lport)
                            current.append(entry.split(' ')[0] + ' ' + entry.split(' ')[1])
                            inbound.clear()
        
        # increment counter             
        n += 1
        # sleep 5 seconds
        time.sleep(5)

if __name__ == '__main__':
    main()

