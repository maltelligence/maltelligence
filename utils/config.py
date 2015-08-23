#!/usr/bin/python
# Name: config.py
# Version: 0.91
# By: Maltelligence Research Group
# Created:  Aug 5, 2015
# Modified: Aug 7, 2015
# Function: read configuration files
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


import sys
import os
import re
import ast
import argparse
import ConfigParser
import datetime
import time
import logging

import MySQLdb

logging.basicConfig(filename='./log/maltelligence.log',level=logging.INFO,format='%(asctime)s %(levelname)-8s %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

#logging.info('Config loaded successfully')

try:
    config_ini = "./MalProfile.ini"
    config = ConfigParser.ConfigParser()
    config.read(config_ini)
    var = {'VT_APIKEY':config.get("API_KEYS", "VT_APIKEY"), 'MN_APITKEY':config.get("API_KEYS", "MN_APITKEY"), 'VTLIMIT':config.get("VT_4", "VTLIMIT"), 'VTDEPTH':int(config.get("VT_4", "VTDEPTH")), 'ASN':ast.literal_eval(config.get("MALTELLIGENCE", "ASN")), 'LOGO':ast.literal_eval(config.get("MALTELLIGENCE", "LOGO")), 'GEOIP':ast.literal_eval(config.get("MALTELLIGENCE", "GEOIP")), 'EXCLUDE_NONROUTABLE':ast.literal_eval(config.get("MALTELLIGENCE", "EXCLUDE_NONROUTABLE")), 'DB_HOST':config.get("MALTELLIGENCE", "DB_HOST"), 'DB_ID':config.get("MALTELLIGENCE", "DB_ID"), 'DB_PW':config.get("MALTELLIGENCE", "DB_PW"), 'DB':config.get("MALTELLIGENCE", "DB"), 'TLD':config.get("MALTELLIGENCE", "TLD")}
    VT_APIKEY = var.get('VT_APIKEY')
    MN_APITKEY = var.get('MN_APITKEY')
    VTLIMIT = var.get('VTLIMIT')
    VTDEPTH = var.get('VTDEPTH')
    ASN = var.get('ASN')
    LOGO = var.get('LOGO')
    GEOIP = var.get('GEOIP')
    DB_HOST = var.get('DB_HOST')
    DB_ID = var.get('DB_ID')
    DB_PW = var.get('DB_PW')
    DB = var.get('DB')
    TLD = var.get('TLD').split(',')
    EXCLUDE_NONROUTABLE = var.get('EXCLUDE_NONROUTABLE')
    sign_on = 0
    if ASN:
        sign_on = 1
    if GEOIP:
        if os.path.exists('./GeoLite2-City.mmdb') or os.path.exists('./GeoIP2-City.mmdb'):
            msg = 'GeoIP database found'
            logging.info(msg)
        else:
            msg = 'No GeoIP database'
            logging.error(msg)
            GEOIP = False
    today = datetime.datetime.now().strftime("%Y-%m-%d")
except:
    msg = '[*] Cannot read config file: %s ... !' % (config_ini)
    logging.error(msg)
    sys.exit()


def logo():
    print("""\n
        ___  ___      _ _       _ _ _
        |  \/  |     | | |     | | (_)
        | .  . | __ _| | |_ ___| | |_  __ _  ___ _ __   ___ ___
        | |\/| |/ _` | | __/ _ \ | | |/ _` |/ _ \ '_ \ / __/ _ \
        
        | |  | | (_| | | ||  __/ | | | (_| |  __/ | | | (_|  __/
        \_|  |_/\__,_|_|\__\___|_|_|_|\__, |\___|_| |_|\___\___|
                                       __/ |
                                      |___/
            Maltelligence(c) a Malware/Threat Analyst Desktop\n\n
        """)






