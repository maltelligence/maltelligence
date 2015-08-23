#!/usr/bin/python
# Name: pdns.py - a trimmed class of Maltelligence Tool
# Version: 0.91
# By:   Maltelligence Research Group
# Created:  Dec 25, 2014
# Modified: Aug 12, 2015
# Function: Class of query passive dns sources (VirusTotal and mnemonic Pdns)
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
#
#   Usage, can called by Passive.py or used inside a python prompt
#   1.  from pdns import pdns       // import the class
#   2.  p = pdns()                  // create an instance
#   3.  p.get_Pip(domain)           // query virusTotal passive dns by a domain
#   4.  p.get_Pdns(ip)              // query virusTotal passive dns by an ip address
#   5.  p.get_mnPdns(domain|ip)     // query mnemonic Passive dns by domain or ip address
#   6.  p.get_download(hash, tag)   // download sample from virusTotal to file system of a folder named with the tag
#   7.  p.findPassive(domain)       // query virusTotal recurrsively according to VTDEPTH level
#
#   [-] Please make provide VirusTotal Keys ... !   // you need to provide valid keys in MalProfile.ini
#                                                   // without double-quotes or single-quotes
#
#   To keep queries instead of reading messy data from stdout:
#
#   as_owner, asn, country, urls, downloaded, communicating, resolutions = p.get_Pdns(ip)
#   urls, downloaded, communicating, resolutions = p.get_Pip(domain)
#   as_owners, uri, downloads, comms, c2 = p.findPassive([dns|ip])


import json
import urllib
import urllib2
import simplejson

from prettytable import PrettyTable
from utils.dnsutils import *
from utils.utility import *
from utils.config import *

#logging.info('Creating pdns instance')


if VT_APIKEY == '' or VTLIMIT == 0 or VTDEPTH == 0:
    msg = "[-] Please provide Keys at MalProfile.ini... !"
    logging.error(msg)
    sys.exit()
#else:
    #   add '#' at beginning of the print statement to hide this message, if you don't like it ;)
    #print "\n\n[+] Making queries to VirusTotal with depth level of %s, \nand Key=%s\n" % (VTDEPTH, VT_APIKEY)


class pdns(object):
    
    #   VT_LIMIT = 4, can be removed if user obtained commerical license from VirusTotal
    #   https://www.virustotal.com/en/faq/ (The 4 requests/minute limitation)
    
    def __init__(self):
        pass

    def get_Pdns(self, data):
        """ assume ip address is supplied """

        as_owner = []
        asn = []
        country = []
        urls = []               ##  dictionary list
        downloaded = []         ##  dictionary list
        communicating = []      ##  dictionary list
        resolutions = []        ##  dictionary list

        try:
            if chk_ip(data):
                ip = data
                url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
                parameters = {'ip': ip, 'apikey': VT_APIKEY}
                response = urllib.urlopen('%s?%s' % (url, urllib.urlencode(parameters))).read()
                res = json.loads(response)
                msg = "[+] Checking ip address = %s ..." % (ip)
                logging.info(msg)
                #print msg
                
                if res.get('response_code') == 1:
                    
                    if res.get('as_owner'):
                        as_owner = res.get('as_owner')

                    if res.get('asn'):
                        asn = res.get('asn')

                    if res.get('country'):
                        country = res.get('country')
                    
                    #   keys: 'url', 'positives', 'scan_date'
                    if res.get('detected_urls'):
                        urls = res.get('detected_urls')
                    
                    #   keys: 'date', 'positives', 'sha256'
                    if res.get('detected_downloaded_samples'):
                        downloaded = res.get('detected_downloaded_samples')
                    
                    #   keys: 'date', 'positives', 'sha256'
                    if res.get('detected_communicating_samples'):
                        communicating = res.get('detected_communicating_samples')
                    
                    #   keys: 'last_resolved', 'hostname'
                    if res.get('resolutions'):
                        resolutions = res.get('resolutions')
        
            return as_owner, asn, country, urls, downloaded, communicating, resolutions
    
        except:
            msg = "[*] No data received from VirusTotal, try later ...!"
            logging.error(msg)
            return as_owner, asn, country, urls, downloaded, communicating, resolutions


    def get_Pip(self, data):
        """ assume domain is supplied """

        urls = []               ##  dictionary list
        downloaded = []         ##  dictionary list
        communicating = []      ##  dictionary list
        resolutions = []        ##  dictionary list
        try:

            if chk_domain(data):
                domain = data
                url = 'https://www.virustotal.com/vtapi/v2/domain/report'
                parameters = {'domain': domain, 'apikey': VT_APIKEY}
                response = urllib.urlopen('%s?%s' % (url, urllib.urlencode(parameters))).read()
                res = json.loads(response)
                msg = "[+] Checking domain = %s ..." % (domain)
                logging.info(msg)
                #print msg
            
                if res.get('response_code') == 1:
                    
                    #   keys: 'url', 'positives', 'scan_date'
                    if res.get('detected_urls'):
                        urls = res.get('detected_urls')
                    
                    #   keys: 'date', 'positives', 'sha256'
                    if res.get('detected_downloaded_samples'):
                        downloaded = res.get('detected_downloaded_samples')
                    
                    #   keys: 'date', 'positives', 'sha256'
                    if res.get('detected_communicating_samples'):
                        communicating = res.get('detected_communicating_samples')
                    
                    #   keys: 'last_resolved', 'ip_address'
                    if res.get('resolutions'):
                        resolutions = res.get('resolutions')
                            
            return urls, downloaded, communicating, resolutions
        except:
            msg = "[*] No data received from VirusTotal, try later ...!"
            logging.error(msg)
            return urls, downloaded, communicating, resolutions


    def get_download(self, sha256, tag):
        """ assume hash supplied """
        download_url = ('https://www.virustotal.com/intelligence/download/?hash=%s&apikey=%s')
        response = None
        page = None
        repo = './repo'
        source = tag

        folder = os.path.join(repo, source, 'binaries', sha256[0], sha256[1], sha256[2], sha256[3])
        if not os.path.exists(folder):
            os.makedirs(folder, 0750)
        destination_file = os.path.join(folder, sha256)
        
        parameters = {'query': sha256, 'apikey': VT_APIKEY, 'page': page}
        try:
            data = urllib.urlencode(parameters)
            url = download_url % (sha256, VT_APIKEY)
            success =  urllib.urlretrieve(url, destination_file)
        except:
            success = False
        if success:
            list = []
            downloaded = False
            if os.path.exists(destination_file):
                list = get_hashes(destination_file)
            for hash in list:
                if hash == sha256:
                    downloaded = True
            if downloaded:
                msg = "[+] download was successful, stored at %s" % (folder)
                logging.info(msg)
            else:
                os.remove(destination_file)
                msg = "[-] no such sample: %s" % (destination_file)
                logging.info(msg)
        else:
            msg = "[+] download was failed: %s" % (destination_file)
            logging.error(msg)


    #   return 2 arrays of VirusTotal scanned results by md5 hash provided
    def getClassification(self, hash):
        
        result = []
        url = "https://www.virustotal.com/vtapi/v2/file/report"
        parameters = {'resource': hash, 'apikey': VT_APIKEY}
        data = urllib.urlencode(parameters)
        req = urllib2.Request(url, data)
        response = urllib2.urlopen(req)
        json = response.read()
        
        #   try catching json error
        try:
            response_dict = simplejson.loads(json)
        except:
            msg = "[*] Json Error...No data collected"
            logging.error(msg)
            response_dict = {}
        
        count = len(response_dict.get("scans", []))
        for i in range(0, count):
            k = response_dict.get("scans", []).keys()[i]
            v = response_dict.get("scans", []).values()[i].get('result')
            if v is not None:
                entry = (dict(av_vendor=k, name=v))
                result.append(entry)

        return result


    def get_mnPdns(self, data):
        """ get mnemonic Pdns from ip or dns """

        #   init varaibles
        c2 = []
        #   Check MN_APITKEY
        if MN_APITKEY == '':
            print "\n[-] Please provide mnemonic Pdns Key at MalProfile.ini... !"
        else:
            print "\n[+] Using mnemonic Pdns key: %s" % (MN_APITKEY)
        
        base_url = "http://passivedns.mnemonic.no/api1/?"
        url = base_url + "apikey=" + MN_APITKEY + "&query=" + data + "&method=" + "exact"
        response = requests.get(url)
        res = json.loads(response.text)

        #   keys: 'query', 'first'
        if res.get('message') == 'ok':
            found = res.get('result')
            for i in range(0, len(found)):
                entry = (dict(query=data, answer=found[i]['answer']))
                c2.append(entry)
                
            #   print c2 table
            print "[+] mnemonic pdns results ..."
            table = PrettyTable(['query','answer'])
            table.align = 'l'
            for i in range(0, len(c2)):
                #   ordering the data
                query = c2[i].get('query')
                answer = c2[i].get('answer')
                #   adding to table for showing to console
                line = (query, answer)
                table.add_row(line)
                    
            #print table

            return found
        else:
            return {}


    def findPassive(self, data):
        """ return recurrsive passive DNS (rPdns) info from VirusTotal
            """
        c2 = []
        as_owners = []
        uri = []
        downloads = []
        comms = []
        
        entry = {}
        row = 0
        processed = 0
        localhost = "127.0.0.1"
        chk_localhost = True
        if (EXCLUDE_NONROUTABLE):
            chk_localhost = False
        
        #   query virusTotal
        while (processed <= int(VTDEPTH) and processed <= len(c2)):
            
            # control VT_LIMIT = 4
            if (processed)%4 == 0 and VTLIMIT == "True" and processed != 0:
                print "[+] Pausing 1 min ..... = " + str(processed) +'/' + str(VTDEPTH)
                n = 60
                bar = pyprind.ProgBar(n)
                for i in range(n):
                    time.sleep(1)
                    bar.update()
            
            #   query virusTotal
            if processed != 0:
                data = c2[processed-1].get('_to')
            
            processed = processed + 1
            
            
            if (chk_ip(data) and chk_localhost):
                as_owner, asn, country, urls, downloaded, communicating, resolutions = self.get_Pdns(data)
                
                #   add 1st 10 resolutions
                if len(resolutions) > 10:
                    records = 10
                else:
                    records = len(resolutions)
                for i in range(0, records):
                    ip = data
                    dns = resolutions[i].get('hostname')
                    hash = md5sum(dns+'-'+ip)
                    date = resolutions[i].get('last_resolved').split(" ")[0]
                    entry = (dict(id=row+1, from_=ip, dns_ip=hash , _to=dns, date=date,c2_id=processed-1))
                    #   is_duplicated is False, add entry to c2 list
                    is_duplicated = False
                    for j in range(0, len(c2)):
                        if c2[j].get('dns_ip') == hash:
                            is_duplicated = True
                    if is_duplicated is False:
                        row = row + 1
                        c2.append(entry)
            
                #   add as_owner
                if as_owner and asn:
                    entry = (dict(source=data, owner=as_owner, num=asn, cn=country))
                    as_owners.append(entry)
        
                #   add urls
                for i in range(0, len(urls)):
                    entry = (dict(source=data, url=urls[i].get('url'), date=urls[i].get('scan_date').split(" ")[0]))
                    uri.append(entry)
                
                #   add downloaded
                for i in range(0, len(downloaded)):
                    entry = (dict(id=i, source=data, date=downloaded[i].get('date').split(" ")[0], hash=downloaded[i].get('sha256')))
                    is_duplicated = False
                    for j in range(0, len(downloads)):
                        if downloads[j].get('sha256') == hash:
                            is_duplicated = True
                    if is_duplicated is False:
                        downloads.append(entry)
        
                #   add communicating
                for i in range(0, len(communicating)):
                    entry = (dict(id=i, source=data, date=communicating[i].get('date').split(" ")[0], hash=communicating[i].get('sha256')))
                    is_duplicated = False
                    for j in range(0, len(communicating)):
                        if communicating[j].get('sha256') == communicating[i].get('sha256'):
                            is_duplicated = True
                    if is_duplicated is False:
                        comms.append(entry)
                        
            else:
                urls, downloaded, communicating, resolutions = self.get_Pip(data)

                #   add 1st 10 resolutions
                if len(resolutions) > 10:
                    records = 10
                else:
                    records = len(resolutions)
                for i in range(0, records):
                    dns = data
                    ip = resolutions[i].get('ip_address')
                    hash = md5sum(dns+'-'+ip)
                    date = resolutions[i].get('last_resolved').split(" ")[0]
                    entry = (dict(id=row+1, from_=dns, _to=ip, dns_ip=hash , date=date,c2_id=processed-1))
                    #   is_duplicated is False, add entry to c2 list
                    is_duplicated = False
                    dns_id = 0
                    ip_id = 0
                    for j in range(0, len(c2)):
                        if c2[j].get('dns_ip') == hash:
                            is_duplicated = True
                    if is_duplicated is False:
                        row = row + 1
                        c2.append(entry)

                #   add urls
                for i in range(0, len(urls)):
                    entry = (dict(source=data, url=urls[i].get('url'), date=urls[i].get('scan_date').split(" ")[0]))
                    uri.append(entry)
                
                #   add downloaded ***  and download the file   ***
                for i in range(0, len(downloaded)):
                    entry = (dict(id=i, source=data, date=downloaded[i].get('date').split(" ")[0], hash=downloaded[i].get('sha256')))
                    is_duplicated = False
                    for j in range(0, len(downloads)):
                        if downloads[j].get('sha256') == hash:
                            is_duplicated = True
                    if is_duplicated is False:
                        downloads.append(entry)
            
                #   add communicating ***  and download the file   ***
                for i in range(0, len(communicating)):
                    entry = (dict(id=i, source=data, date=communicating[i].get('date').split(" ")[0], hash=communicating[i].get('sha256')))
                    is_duplicated = False
                    for j in range(0, len(communicating)):
                        if communicating[j].get('sha256') == hash:
                            is_duplicated = True
                    if is_duplicated is False:
                        comms.append(entry)

        #   print c2 table
        print "[+] recursive pdns results ..."
        table = PrettyTable(['id','from','to','date'])
        table.align = 'l'
        for i in range(0, len(c2)):
            #   ordering the data
            table_id = c2[i].get('id')
            scan_date = c2[i].get('date')
            from_ = c2[i].get('from_')
            _to = c2[i].get('_to')
            #c2_id = c2[i].get('c2_id')
            #   adding to table for showing to console
            line = (table_id, from_, _to, scan_date)
            table.add_row(line)
        #print table
            
        #   print as_owners table
        print "[+] IP addresses and their owner & AS numbers ..."
        table = PrettyTable(['source','owner','AS','country'])
        table.align = 'l'
        for i in range(0, len(as_owners)):
            line = (as_owners[i].get('source'), as_owners[i].get('owner'), as_owners[i].get('num'), as_owners[i].get('cn'))
            table.add_row(line)
        #print table

        #   print uri table
        table = PrettyTable(['source','url','scan_date'])
        table.align = 'l'
        for i in range(0, len(uri)):
            line = (uri[i].get('source'), uri[i].get('url'), uri[i].get('date'))
            table.add_row(line)
        #print table
    
        #   print downloads table
        print "[+] All matched downloads ..."
        table = PrettyTable(['id', 'source','date','hash'])
        table.align = 'l'
        for i in range(0, len(downloads)):
            line = (downloads[i].get('id'), downloads[i].get('source'), downloads[i].get('date'), downloads[i].get('hash'))
            table.add_row(line)
        if len(downloads) > 0:
            msg =''
            #print table

        #   print comms table
        table = PrettyTable(['id', 'source','date','hash'])
        table.align = 'l'
        items = 10
        if len(comms) < items:
            items = len(comms)
        for i in range(0, items):
            line = (comms[i].get('id'), comms[i].get('source'), comms[i].get('date'), comms[i].get('hash'))
            table.add_row(line)
        if items > 0:
            msg =''
            #print table

        #   In case using in Python shell, remove the '#' can keep the return values 
        return as_owners, uri, downloads, comms, c2


    def findmn(self, data):
        """ return recurrsive passive DNS info from passivedns.mnemonic.no
            
            Example:
            # c2 = findmn([dns|ip])
            """
        entry = {}
        row = 0
        c2 = []
        processed = 0
        localhost = "127.0.0.1"
        chk_localhost = True
        if (EXCLUDE_NONROUTABLE):
            chk_localhost = False
        
        #   query mnemonic.no
        while (processed <= len(c2)):
            
            #   1st record
            if processed != 0:
                data = c2[processed-1].get('_to')
            
            processed = processed + 1
            resolutions = self.get_mnPdns(data)
            #print_info('processing...'+data)
            
            if (chk_ip(data) and chk_localhost):
                #   add 1st 50 queries
                if len(resolutions) > 50:
                    records = 50
                else:
                    records = len(resolutions)
                for i in range(0, records):
                    ip = data
                    dns = resolutions[i].get('answer')
                    hash = md5sum(dns+'-'+ip)
                    t = time.gmtime(resolutions[0].get('first'))
                    try:
                        date = time.strftime('%Y-%m-%d', t)
                    except:
                        date = ""
                        pass
                    entry = (dict(id=row+1, from_=ip, dns_ip=hash , _to=dns, date=date,c2_id=processed-1))
                    #   is_duplicated is False, add entry to c2 list
                    is_duplicated = False
                    for j in range(0, len(c2)):
                        if c2[j].get('dns_ip') == hash:
                            is_duplicated = True
                    if is_duplicated is False:
                        row = row + 1
                        c2.append(entry)
            else:
                #   add 1st 50 queries
                if len(resolutions) > 50:
                    records = 50
                else:
                    records = len(resolutions)
                for i in range(0, records):
                    dns = data
                    ip = resolutions[i].get('answer')
                    hash = md5sum(dns+'-'+ip)
                    t = time.gmtime(resolutions[0].get('first'))
                    try:
                        date = time.strftime('%Y-%m-%d', t)
                    except:
                        date = ''
                    entry = (dict(id=row+1, from_=dns, dns_ip=hash , _to=ip, date=date,c2_id=processed-1))
                    #   is_duplicated is False, add entry to c2 list
                    is_duplicated = False
                    for j in range(0, len(c2)):
                        if c2[j].get('dns_ip') == hash:
                            is_duplicated = True
                    if is_duplicated is False:
                        row = row + 1
                        c2.append(entry)

        #   print c2 table
        table = PrettyTable(['id','from','to','date','c2_id'])
        table.align = 'l'
        for i in range(0, len(c2)):
            #   ordering the data
            table_id = c2[i].get('id')
            scan_date = c2[i].get('date')
            from_ = c2[i].get('from_')
            _to = c2[i].get('_to')
            c2_id = c2[i].get('c2_id')
            #   adding to table for showing to console
            line = (table_id, from_, _to, scan_date, c2_id)
            table.add_row(line)
        #print table
        return c2


