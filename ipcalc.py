#!/usr/local/bin/python3
# Program: IpCalc
# Author: Timothy Pulliam
# Date: 9/11/2017

from sys import argv
import re

# GLOBAL VARIABLES
IS_IPV4 = True
IS_IPV6 = False
IPV4_IS_BINARY = True
IPV4_IS_DECIMAL = False
# ANSI Text Color Codes
G = '\033[32m'
B = '\033[30m'
R = '\033[31m'


# FUNCTIONS
def ipcalc(argv):

    if len(argv) < 2 or argv[1] == 'help':
        print_usage()
        return 0

    # Parse the options and arguments
    command = argv[1]

    if command == 'b2d':
        print(b2d(argv[2]))
    if command == 'd2b':
        print(d2b(argv[2]))
    if command == 'ipv4_to_class':
        ipv4_to_class(argv[2])
    else:
        print("Invalid Command: Use 'ipcalc help' for usage.")

def parse_ip(ip):
    """Determine whehter the given IP address is in a valid
    decimal or binary format."""
    global IPV4_IS_DECIMAL
    global IPV4_IS_BINARY

    # http://www.regular-expressions.info/ip.html
    ipv4_decimal_pattern = re.compile(r'\b(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b')
    ipv4_binary_pattern = re.compile(r'\b([01]{8}\.){3}[01]{8}\b')
    if re.fullmatch(ipv4_decimal_pattern, ip):
        IPV4_IS_DECIMAL = True
        IPV4_IS_BINARY = False
    elif re.fullmatch(ipv4_binary_pattern, ip):
        IPV4_IS_DECIMAL = False
        IPV4_IS_BINARY = True
    else:
        print("Invalid IPv4 Address Format")



def print_usage():
    print("""
    Invalid command. Below are the commands ipcalc accepts

    b2d -- Convert a number in unsigned binary form to decimal form
    d2b -- Convert a number in decimal form to unsigned binary form
    ipv4_to_class -- Return the Class of the given IP address
    help -- Print this help menu
    """)

def b2d(binary_string):
    """Convert a number in unsigned binary form to decimal form"""
    return int(binary_string, 2)

def d2b(decimal_string):
    """Convert a number in decimal form to unsigned binary form"""
    decimal_int = int(decimal_string)
    return '{:0>8b}'.format(decimal_int)

def ipv4_to_class(ipv4):
    """"
    Given an IP address (<str ipv4>) of the form xxxxxxxx.xxxxxxxx.xxxxxxxx.xxxxxxxx
    return the default IP Address class. More information can be found
    at http://www.vlsm-calc.net/ipclasses.php

    IP Address Classes:

    Class A = Leading Bit Pattern 0xxxxxxx.xxxxxxxx.xxxxxxxx.xxxxxxxx
    Class B = Leading Bit Pattern 10xxxxxx.xxxxxxxx.xxxxxxxx.xxxxxxxx
    Class C = Leading Bit Pattern 110xxxxx.xxxxxxxx.xxxxxxxx.xxxxxxxx
    """
    octets = ipv4.split('.')
    if IPV4_IS_BINARY:
        if 0 <= b2d(octets[0]) < 127:
            print("Class A")
        elif 128 <= b2d(octets[0]) <= 191:
            print("Class B")
        elif 192 <= b2d(octets[0]) <= 223:
            print("Class C")
        elif 224 <= b2d(octets[0]) <= 239:
            print("Class D (Multicast)")
        else:
            print("Class E (Experimental)")
    else:
        leading_octet = int(octets[0])
        if 0 <= leading_octet < 127:
            print("Class A")
        elif 128 <= leading_octet <= 191:
            print("Class B")
        elif 192 <= leading_octet <= 223:
            print("Class C")
        elif 224 <= leading_octet <= 239:
            print("Class D (Multicast)")
        else:
            print("Class E (Experimental)")

if __name__ == '__main__':
    ipcalc(argv)