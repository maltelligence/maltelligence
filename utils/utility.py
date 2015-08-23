#!/usr/bin/python
# Name: utility.py
# Version: 0.91
# By: Maltelligence Research Group
# Created:  Jan 5, 2015
# Modified: Aug 11, 2015
# Function: all common utility (some functions: get_chunks, get_hases, get_ssdeep were taken
#       from viper https://github.com/viper-framework/viper
#
#    Copyright (c), 2015 Maltelligence Group
#
#    This file is part of Maltelligence.
#
#    Maltelligence is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    Maltelligence is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with Maltelligence.  If not, see <http://www.gnu.org/licenses/>.
#


import hashlib
import pydeep
import subprocess
import binascii
import locale
import ipaddress

import pyprind
from utils.config import *

def is_number(num):
    try:
        float(num)
        return True
    except ValueError:
        return False


def is_subnet(ip, subnet):
    #   check if it is a subnet format
    if len(subnet.split("/")) != 2 and len(subnet.split("/")[0].split(".")):
        msg = '[*] %s is not a subnet format (x.x.x.x/y)' % (subnet)
        logging.info(msg)
        return False
    else:
        try:
            #   ipaddress needs a unicode object instead of (str in Python 2)
            if type(ip) is str:
                ip = unicode(ip, 'utf-8')
            if type(subnet) is str:
                subnet = unicode(subnet, 'utf-8')
            return ipaddress.ip_address(ip) in ipaddress.ip_network(subnet)
        except ValueError:
            return False


def md5sum(data):
    md5 = hashlib.md5()
    md5.update(data)
    return md5.hexdigest()


def convertNumber(data):
    locale.setlocale( locale.LC_ALL, 'en_US.UTF-8')
    num = locale.atoi(data)
    if is_number(num):
        return num
    else:
        msg = '[*] %s is not a number' % (data)
        logging.error(msg)
        return 0

def convertDate(data):
    #   normalize date variables as datetime
    if data == '' or data is None:
        return today
    if type(data) is list:
        if isinstance(data[0], datetime.datetime):
            return data[0]
        else:
            logging.info(data)
            logging.info(type(data))
    if type(data) is str:
        if isinstance(data, datetime.datetime):
            return data
        else:
            logging.info(data)
            logging.info(type(data))
    return data



def get_chunks(path):
    fd = open(path, 'rb')
    while True:
        chunk = fd.read(16*1024)
        if not chunk:
            break
        yield chunk
    fd.close()


def get_hashes(path):
    crc = 0
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()
    
    for chunk in get_chunks(path):
        crc = binascii.crc32(chunk, crc)
        md5.update(chunk)
        sha1.update(chunk)
        
        sha256.update(chunk)
        sha512.update(chunk)
    
    crc32 = ''.join('%02X' % ((crc>>i)&0xff) for i in [24, 16, 8, 0])
    md5 = md5.hexdigest()
    sha1 = sha1.hexdigest()
    sha256 = sha256.hexdigest()
    sha512 = sha512.hexdigest()
    list = (crc32, md5, sha1, sha256, sha512)
    return list


def get_ssdeep(path):
    try:
        return pydeep.hash_file(path)
    except Exception:
        return ''





