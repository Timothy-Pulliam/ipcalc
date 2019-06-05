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

    # Parse commands
    command = argv[1]
 
    # Check if cidr block was provided
    try:
        ip, cidr = argv[1].split('/')
    except ValueError as e:
        print("Invalid/No cidr range provided")
        ip = argv[1]
        cidr = None 

    if is_ip(ip):
        ip_info(ip, cidr)
    elif command == 'b2d':
        print(b2d(argv[2]))
    elif command == 'd2b':
        print(d2b(argv[2]))
    elif command == 'ipv4_to_class':
        ipv4_to_class(argv[2])
    else:
        print("Invalid Command: Use 'ipcalc help' for usage.")


def ip_info(ip, cidr):
    if is_ip(ip):
        mask = netmask(ip, cidr)
    
        print("Address:\t" + ip_decimal(ip) + "\t" + ip_binary(ip))
        print("CIDR Block:\t", cidr)
        print("Netmask:\t {}.{}.{}.{}".format(mask[0:8], mask[8:18], mask[18:24], mask[24:]) + "\t" + ip_binary(netmask(ip, cidr)))
        print("Class: " + ipv4_to_class(ip))
        if is_private(ip):
            print(G + "Private Internet" + B)



def netmask(ip, cidr=None):
    if cidr:
        return ip_binary(str((2**int(cidr) - 1)))  
    elif ipv4_to_class(ip) == 'A':
        return '255.0.0.0'
    elif ipv4_to_class(ip) == 'B':
        return '255.255.0.0'
    elif ipv4_to_class(ip) == 'C':
        return '255.255.255.0'
    else:
        return 'Classless'

def is_private(ip):
    class_a_pattern = re.compile(r'10\.((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){2}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])')
    class_b_pattern = re.compile(r'172\.(1[6-9]|2[0-9]|3[01])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])')
    class_c_pattern = re.compile(r'192\.168\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])')
    if re.fullmatch(class_a_pattern, ip):
        return True
    elif re.fullmatch(class_b_pattern, ip):
        return True
    elif re.fullmatch(class_c_pattern, ip):
        return True
    else:
        return False

def ip_decimal(ip):
    """Return IP address in decimal form"""
    if IPV4_IS_DECIMAL:
        return ip
    else:
        # Must be in binary form
        ip_decimal = '.'.join([b2d(octet) for octet in ip.split('.')])
        return ip_decimal


def ip_binary(ip):
    """Return IP address in binary form"""
    if IPV4_IS_BINARY:
        return ip
    else:
        # Must be in decimal form
        ip_decimal = '.'.join([d2b(octet) for octet in ip.split('.')])
        return ip_decimal


def is_ip(ip):
    """Determine whether the given IP address is in a valid
    decimal or binary format."""
    global IPV4_IS_DECIMAL
    global IPV4_IS_BINARY

    # http://www.regular-expressions.info/ip.html
    ipv4_decimal_pattern = re.compile(r'\b(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b')
    ipv4_binary_pattern = re.compile(r'\b([01]{8}\.){3}[01]{8}\b')
    if re.fullmatch(ipv4_decimal_pattern, ip):
        IPV4_IS_DECIMAL = True
        IPV4_IS_BINARY = False
        return True
    elif re.fullmatch(ipv4_binary_pattern, ip):
        IPV4_IS_DECIMAL = False
        IPV4_IS_BINARY = True
        return True
    else:
        #print("Invalid IPv4 Address Format")
        return False

def b2d(binary_string):
    """Convert a number in unsigned binary form to decimal form"""
    return '{:0>8b}'.format(str(int(binary_string, 2)))


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
            return "A"
        elif 128 <= b2d(octets[0]) <= 191:
            return "B"
        elif 192 <= b2d(octets[0]) <= 223:
            return "C"
        elif 224 <= b2d(octets[0]) <= 239:
            return "D (Multicast)"
        else:
            print("E (Experimental)")
    elif IPV4_IS_DECIMAL:
        leading_octet = int(octets[0])
        if 0 <= leading_octet < 127:
            return "A"
        elif 128 <= leading_octet <= 191:
            return "B"
        elif 192 <= leading_octet <= 223:
            return "C"
        elif 224 <= leading_octet <= 239:
            return "D (Multicast)"
        else:
            return "E (Experimental)"


def print_usage():
    print("""
    NAME
        ipcalc - IPv4 Addressing and subnetting calculator.
    
    SYNOPSIS
        ipcalc - [ip_address|command] [options]

    COMMANDS
        help
            Print this help menu
        b2d binary_number
            Convert a number in unsigned binary form to decimal form
        d2b decimal_number
            Convert a number in decimal form to unsigned binary form
        ipv4_to_class ipv4_address
            Return the Class of the given IP address

    """)

if __name__ == '__main__':
    ipcalc(argv)