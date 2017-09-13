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


    if is_ip(argv[1]):
        ip = argv[1]
        print("Decimal Notation: " + ipv)

    if command == 'b2d':
        print(b2d(argv[2]))
    if command == 'd2b':
        print(d2b(argv[2]))
    if command == 'ipv4_to_class':
        ipv4_to_class(argv[2])
    else:
        print("Invalid Command: Use 'ipcalc help' for usage.")


def ip_info(ip):
    print("Decimal Notation: " + ip_decimal(ip))
    print("Binary Notation: " + ip_binary(ip))
    print("Class: " + ipv4_to_class(ip))
    print("Netmask: ")    

def ip_d2b(ip):
    """Convert IP address from decimal form to unsigned binary form"""
    if is_ip(ip) and IPV4_IS_DECIMAL:
        ip_binary = '.'.join([d2b(octet) for octet in ip.split('.')])
        return ip_binary
    else:
        print("Not a valid IP address")
        return 1

def ip_decimal(ip):
    """Return IP address in decimal form"""
    if is_ip(ip):
        if IPV4_IS_DECIMAL:
            return ip
        else:
            # Must be in binary form
            ip_decimal = '.'.join([b2d(octet) for octet in ip.split('.')])
    else:
        print("Not a valid IP Address")

def ip_binary(ip):
    """Return IP address in decimal form"""
    if is_ip(ip):
        if IPV4_IS_BINARY:
            return ip
        else:
            # Must be in decimal form
            ip_decimal = '.'.join([d2b(octet) for octet in ip.split('.')])



def is_ip(ip):
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
    return int(binary_string, 2)


def d2b(decimal_string):
    """Convert a number in decimal form to unsigned binary form"""
    decimal_int = int(decimal_string)
    return '{:0>8b}'.format(decimal_int)


def ip_d2b(ip):
    """Convert IP address from decimal form to unsigned binary form"""
    if is_ip(ip) and IPV4_IS_DECIMAL:
        ip_binary = '.'.join([d2b(octet) for octet in ip.split('.')])
        return ip_binary
    else:
        print("Not a valid IP address")
        return 1



def ip_b2d(ip):
    """Convert IP address from unsigned binary form to decimal form"""
    if is_ip(ip) and IPV4_IS_BINARY:
        ip_decimal = '.'.join([b2d(octet) for octet in ip.split('.')])
        return ip_decimal
    else:
        print("Not a valid IP address")
        return 1


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
            print("A")
        elif 128 <= b2d(octets[0]) <= 191:
            print("B")
        elif 192 <= b2d(octets[0]) <= 223:
            print("C")
        elif 224 <= b2d(octets[0]) <= 239:
            print("D (Multicast)")
        else:
            print("E (Experimental)")
    else:
        leading_octet = int(octets[0])
        if 0 <= leading_octet < 127:
            print("A")
        elif 128 <= leading_octet <= 191:
            print("B")
        elif 192 <= leading_octet <= 223:
            print("C")
        elif 224 <= leading_octet <= 239:
            print("D (Multicast)")
        else:
            print("E (Experimental)")


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