#!/usr/bin/python

import optparse
import socket
import sys
import time
import math

icmp = socket.getprotobyname('icmp')
udp = socket.getprotobyname('udp')

def create_sockets(ttl, timeout):
    recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)    
    send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, udp)
    #Socket Options setting
    send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
    recv_socket.settimeout(timeout) 
    return recv_socket, send_socket

def avgStdev(array):
    total = 0
    counter = 0
    average = 0
    sdtotal = 0
    ret_array = []

    for i in array:
        if (i != 999): #NotRekted 
            total +=i
            counter +=1

    if (counter != 0): #incase all packets timeout
        average = total / counter
        average = round(average, 2)
        for j in array:
            if (j != 999): #No timeout, so use
                sdtotal += (j-average)*(j-average)

        sdtotal = math.sqrt(sdtotal/counter)
        sdtotal = round(sdtotal, 2)

    ret_array.append(average)
    ret_array.append(sdtotal)
    return ret_array #Returns [Average, SD]


def main(dest_name, port, max_hops, timeout):
    dest_addr = socket.gethostbyname(dest_name)
    ttl = 1
    word = ""
    counter = 1
    while True:
        alltimes = []
        times = []
        emptprint = []
        recv_socket, send_socket = create_sockets(ttl, timeout)


        curr_addr = None
        curr_name = None
        recv_socket.bind(("", port))
        counter = 1 #COUNTER VAR
        while (counter <= 3): #Send 3 Packets
            send_socket.sendto("", (dest_name, port))
            cur_time = time.time() #Get Current Time
            counter += 1 #increment
            #print str(counter)
            while True:
                #print str(counter)
                try:
                    _, curr_addr = recv_socket.recvfrom(512)
                    curr_addr = curr_addr[0]
                    round_trip = time.time() - cur_time

                    round_trip = round(round_trip*1000, 1) #Prevent Ugly Rounding

                    times.append(round_trip) 
                    round_trip = str(round_trip) + "ms"
                    alltimes.append(round_trip)

                    try: 
                        if (curr_name is None): #this is done incase only 1 or 2 packets TO
                            curr_name = socket.gethostbyaddr(curr_addr)[0]
                    except socket.error:
                        curr_name = str(curr_addr)
                    break

                except socket.timeout:
                    alltimes.append("*")
                    times.append(999) #A Timeout to ignore in calculation
                    break #Continue is not going to work in this loop 
                except socket.error:
                    alltimes.append("Error") #Handle Errors a bit better
                    times.append(999) 
                    break
                #Break has to be used to exit the extra while true, continue and pass will get it stuck
                #finally: This line breaks things, moved the outside loop

        emptprint = avgStdev(times) #calculates Average and Stdev
       
        send_socket.close() #After the 3 packets, we can close
        recv_socket.close()
        if (ttl < 10): #string length matching
              space = "     "
        else:
              space = "    "
        #Formatting output string
        if (curr_addr is not None):
              ttl_host = str(ttl) + space + str(curr_name) + " (" + str(curr_addr) + ")"
        else:
	        ttl_host = str(ttl) + space + "*    "

        #DOES NOT WORK ON 4c03.cas.mcmaster cause of python 2.6.6
        #ttl_host = "{:<65}".format(ttl_host)

        if (len(ttl_host) < 66):
            toadd = 65 - len(ttl_host)
            ttl_host += " " * toadd

        printstring = ""

        for i in alltimes:
            printstring += i 
            printstring += ", "

        if (emptprint[0] != 0): #If the avg is not 0
            print ttl_host + printstring + str(emptprint[0]) + "ms(Mean), " + str(emptprint[1]) +"ms(Stdev)     "
        else:
            print ttl_host 

        ttl += 1

        if curr_addr == dest_addr or ttl > max_hops:
            break
        #print alltimes        
    return 0

if __name__ == "__main__":
    parser = optparse.OptionParser(usage="%prog [options] hostname")

    parser.add_option("-p", "--port", dest="port",
                      help="Port to use for socket connection [default: %default]",
                      default=33434, metavar="PORT")
    parser.add_option("-m", "--max-hops", dest="max_hops",
                      help="Max hops before giving up [default: %default]",
                      default=30, metavar="MAXHOPS")
    parser.add_option("-t", "--timeout", dest="timeout",
                      help="Timeout Value in seconds [default: %default]",
                      default=5, metavar="TIMEOUT")

    options, args = parser.parse_args()
    if len(args) != 1:
        parser.error("No destination host")
    else:
        dest_name = args[0]

	#Changed the following line - Cant fix spacing
    sys.exit(main(dest_name=dest_name, port=int(options.port), max_hops=int(options.max_hops), timeout=int(options.timeout)))
