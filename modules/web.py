#!/usr/bin/python
# Name: web.py
# Version: 0.91
# By:   Maltelligence Research Group
# Created:  Jan 5, 2015
# Modified: Aug 11, 2015
# Function: all web scan functions
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


import socket
import requests
import wget

from bs4 import BeautifulSoup
from shutil import *
from utils.utility import *
from utils.dnsutils import *
from utils.config import *

#logging.info('Creating web instance')

class web(object):
    
    def __init__(self):
        self.today = datetime.datetime.now().strftime("%Y-%m-%d")
        self.html = ""
        self.server = ""
        self.last_modified = ""
        self.location = ""
        self.encoding = ""
        self.scripts = []
        self.links = []
        self.images = []
        self.iframes = []
    
    
    def init(self):
        pass

    def chkOpen(self, ip_addr, port=None):
        if port is None:
            port = 80
        if chk_ip(ip_addr):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((ip_addr,port))
            if result == 0:
                return True
        else:
            return False


    def chkWeb(self, domain):
        
        base_url = "http://"
        url = base_url+domain
        headers = { 'User-Agent': 'Mozilla/5.0 (X11; U; Linux 2.4.2-2 i586; en-US; m18) Gecko/20010131 Netscape6/6.01'}
        repo = './repo/scripts'
        msg = '... Checking %s ... ' % (domain)
        print msg
        logging.info(msg)
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                self.html = response.text
                self.server = response.headers.get('server')
                self.last_modified = response.headers.get('last-modified')
                self.location = response.headers.get('content-location')
                self.encoding = response.apparent_encoding
                #   create soup
                soup = BeautifulSoup(response.text)
                #   find scripts
                self.scripts = []
                for script in soup.find_all('script'):
                    type = script.get('type')
                    src = script.get('src')
                    content = script.string
                    #   check if downloadable script
                    if src is not None:
                        if src.find('http://') > -1:
                            #   download the script and save to ./repo/scripts
                            filename = wget.download(src, bar=None)
                            list = get_hashes(filename)
                            sha256 = list[3]
                            if src.find(domain) > -1:
                                folder = os.path.join(repo, domain, self.today, sha256[0], sha256[1])
                            else:
                                folder = os.path.join(repo, domain, self.today, 'external', sha256[0], sha256[1])
                            destination_file = os.path.join(folder, filename)
                            if not os.path.exists(folder):
                                os.makedirs(folder, 0750)
                            if os.path.exists(filename):
                                move(filename, destination_file)
                            msg = "[+] script file: %s was downloaded" % (filename)
                            logging.info(msg)
                    self.scripts.append([type, src, content])
                #   find links
                self.links = []
                for link in soup.find_all('a'):
                    url = link.get('href')
                    text = link.string
                    self.links.append([url, text])
                msg = "[+] %s links was parsed" % (len(self.links))
                logging.info(msg)
                #   find images
                self.images = []
                for image in soup.find_all('img'):
                    src = image.get('src')
                    alt = image.get('alt')
                    self.images.append([src, alt])
                msg = "[+] %s images was parsed" % (len(self.images))
                logging.info(msg)
                #   find frames
                self.iframes = []
                for frame in soup.find_all('iframe'):
                    src = frame.get('src')
                    self.iframes.append([src])
                msg = "[+] %s iframes was parsed" % (len(self.iframes))
                logging.info(msg)
        except:
            msg = "[*] Connection errors, try later ... "
            logging.error(msg)
            pass


    def queryWeb(self, domain):
        if chk_domain(domain):
            if self.chkOpen(retIP(domain)[0],80):
                self.chkWeb(domain)
                if self.server != "":
                    logging.info(self.server)
                if self.last_modified != "":
                    logging.info(self.last_modified)
                if self.location != "":
                    logging.info(self.location)
                if self.encoding != "":
                    logging.info(self.encoding)
            else:
                msg = "[*] %s port 80 is not opened" % (domain)
                logging.info(msg)
        else:
            msg = "[*] Please provide a domain, not %s" % (domain)
            logging.info(msg)








