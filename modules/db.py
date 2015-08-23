# encoding: utf-8
#!/usr/bin/python
# Name: db.py
# Version: 0.91
# By:   Maltelligence Research Group
# Created:  Apr 16, 2015
# Modified: Aug 11, 2015
# Function: Class to handle all database functions
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


import warnings
import geoip2
import geoip2.database

from modules.pdns import pdns
from modules.web import web
from utils.config import *
from utils.utility import *
from utils.dnsutils import *
from utils.findASN import *

if sys.getdefaultencoding()!='utf-8':
    reload(sys)
    sys.setdefaultencoding('utf-8')

warnings.simplefilter('ignore')
#logging.info('Creating db instance')

class db(object):
    
    def __init__(self):
        self.today = datetime.datetime.now().strftime("%Y-%m-%d")
        self.db = MySQLdb.connect(DB_HOST,DB_ID,DB_PW,DB)
        self.cursor = self.db.cursor()


    def clean_db(self):
        #   fix domain table column names
        #   *** These 2 statements apply only to maltelligence_0813.sql
        #self.cursor.execute('drop table GeoTemp')
        #self.cursor.execute('alter table domain change 2LD secondLD varchar(255) after hostname')
        
        #self.cursor.execute('alter table autonomous_system change monitoring_code monitoring_code tinyint(2) unsigned default 1')
        #self.cursor.execute('alter table domain change monitoring_code monitoring_code tinyint(2) unsigned default 0')
        #self.cursor.execute('alter table ip change monitoring_code monitoring_code tinyint(2) unsigned default 0')
        #self.cursor.execute('alter table whois change monitoring_code monitoring_code tinyint(2) unsigned default 0')
        #self.cursor.execute('alter table subnet change monitoring_code monitoring_code tinyint(2) unsigned default 0')
        #self.cursor.execute('alter table subnet add column monitoring_count int(10) unsigned default 0 after monitoring_code')
        #self.cursor.execute('alter table country add column monitoring_code tinyint(2) unsigned default 1 after GDP')
        #self.cursor.execute('alter table c2 add column monitoring_count int(10) unsigned default 0 after source')
        #self.cursor.execute('alter table c2 add column monitoring_code tinyint(2) unsigned default 1 after source')
        #   ***     cleaning data       ***
        self.cursor.execute('set foreign_key_checks=0')
        self.cursor.execute('truncate av_classification')
        self.cursor.execute('truncate c2')
        self.cursor.execute('truncate case_artefacts')
        self.cursor.execute('truncate cases')
        self.cursor.execute('truncate communicate_with')
        self.cursor.execute('truncate dns')
        self.cursor.execute('truncate domain')
        self.cursor.execute('truncate geoip')
        self.cursor.execute('truncate htmls')
        self.cursor.execute('truncate iframes')
        self.cursor.execute('truncate images')
        self.cursor.execute('truncate ioc')
        self.cursor.execute('truncate ip')
        self.cursor.execute('truncate links')
        self.cursor.execute('truncate malware_sample')
        self.cursor.execute('truncate metadata')
        self.cursor.execute('truncate scan_detection')
        self.cursor.execute('truncate scripts')
        self.cursor.execute('truncate urls')
        self.cursor.execute('truncate whois')
        #   *** data needed to be kept      ***
        #self.cursor.execute('truncate as_registrar')
        #self.cursor.execute('truncate autonomous_system')
        #self.cursor.execute('truncate country')
        #self.cursor.execute('truncate subnet')
        #self.cursor.execute('truncate tlp')
        self.cursor.execute('set foreign_key_checks=1')
        self.db.commit()


    def findCount(self, table):
        #   tables list that contains monitoring_count column
        tables = ['domain', 'autonomous_system', 'ip', 'whois', 'subnet']
        leastCount = -1
        if table in tables:
            #   Check current monitoring_count number from the table
            sql = "select distinct monitoring_count from %s where monitoring_code!=0 order by monitoring_count asc" % (table,)
            self.cursor.execute(sql)
            found = self.cursor.fetchone()
            if found:
                if found[0] > leastCount:
                    leastCount = int(found[0])
        else:
            logging.info('Using findCount')
            msg = "[*] table: %s, does not contains monitoring_code ..." % (table)
            logging.info(msg)
        return leastCount


    def findDns_id(self, domain, ip):
        #   check input is a domain then followed by an IP Address
        dns_id = 0
        sql = "select dns.id, dns.domain_id, dns.ip_id, domain.domain, ip.ip from dns inner join ip inner join domain on dns.ip_id = ip.id and dns.domain_id = domain.id  where ip.ip = %s and domain.domain = %s"
        self.cursor.execute(sql, (ip, domain))
        found = self.cursor.fetchone()
        if found:
            dns_id = int(found[0])
        return dns_id


    def findDomain_id(self, domain):
        #   check input is a domain
        domain_id = 0
        sql = "select id from domain where domain = %s"
        self.cursor.execute(sql, (domain,))
        found = self.cursor.fetchone()
        if found:
            domain_id = int(found[0])
        return domain_id


    def findIP_id(self, ip):
        #   check input is an IP Address
        ip_id = 0
        sql = "select id from ip where ip = %s"
        self.cursor.execute(sql, (ip,))
        found = self.cursor.fetchone()
        if found:
            ip_id = int(found[0])
        return ip_id


    def findCase_id(self, tag):
        #   check input is a string
        case_id = 0
        sql = "select id from cases where name = %s"
        self.cursor.execute(sql, (tag,))
        found = self.cursor.fetchone()
        if found:
            case_id = int(found[0])
        return case_id


    def findSample_id(self, hashs):
        #   check if hashs is a list
        sample_id = 0
        sha256 = hashs[3]
        sql = "select id from malware_sample where sha256 = %s"
        self.cursor.execute(sql, (sha256,))
        found = self.cursor.fetchone()
        if found:
            sample_id = int(found[0])
        return sample_id


    def scanASN(self, num=None):
        #   Scan & update subnets based on the selected asn from autonomous_system table
        if num is None:
            number = 20
        else:
            number = int(num)
        #   Find current working count number
        table = 'autonomous_system'
        leastCount = self.findCount(table)
        if leastCount == -1:
            leastCount = 0
        scan_date = self.today
        msg = '... Checking %s asn with monitoring_count=%s' % (number, leastCount)
        print msg
        #   Extract marked asn list
        self.cursor.execute("select * from autonomous_system where monitoring_code=1 and monitoring_count=%s", (leastCount,))
        found = self.cursor.fetchall()
        records = len(found)
        if number < records:
            records = number
        #bar = pyprind.ProgBar(records)
        for i in range(0, records):
            id = found[i][0]
            asn = found[i][1]
            monitoring_code = found[i][2]
            parseSubnet(asn)
            self.cursor.execute("update autonomous_system set monitoring_count=%s where id = %s", (leastCount+1,id))
            #bar.update()
        self.db.commit()


    def scanPdns(self, num=None):
        #   Scan & update rPdns based on the dns_id from c2 table
        if num is None:
            number = 20
        else:
            number = int(num)
        #   Find current working count number
        table = 'c2'
        leastCount = self.findCount(table)
        if leastCount == -1:
            leastCount = 0
        scan_date = self.today
        msg = '... Checking %s c2 with monitoring_count=%s' % (number, leastCount)
        print msg
        #   Extract marked asn list
        self.cursor.execute("select domain.domain, ip.ip, c2.id from c2 inner join dns inner join domain inner join ip on dns.domain_id=domain.id and dns.ip_id=ip.id and c2.dns_id=dns.id where c2.monitoring_code=1 and c2.monitoring_count=%s", (leastCount,))
        found = self.cursor.fetchall()
        records = len(found)
        if number < records:
            records = number
        #bar = pyprind.ProgBar(records)
        for i in range(0, records):
            domain = found[i][0]
            ip = found[i][1]
            id = found[i][2]
            self.getPdns(domain)
            self.cursor.execute("update c2 set monitoring_count=%s where id = %s", (leastCount+1,id))
            #bar.update()
        self.db.commit()


    def scanCountry(self):
        #   Scan & update asn based on the selected country [code] from country table
        #   This is a monthly crontab job, callable only if ASN is turned on
        msg = "Updating asn for all countries ..."
        print msg
        self.cursor.execute("select id, country from country")
        found = self.cursor.fetchall()
        for i in range(0, len(found)):
            id = found[i][0]
            parseASN(found[i][1])
        self.db.commit()
    
    
    def scanDomain(self, num=None):
        #   Scan & update IP Address based on the selected domain from domain table
        if num is None:
            number = 20
        else:
            number = int(num)
        #   Find current working count number
        table = 'domain'
        leastCount = self.findCount(table)
        if leastCount == -1:
            leastCount = 0
        scan_date = self.today
        msg = '... Checking %s domains with monitoring_count=%s' % (number, leastCount)
        logging.info(msg)
        print msg
        source = 'Monitoring'
        #   Extract marked domain list
        self.cursor.execute("select * from domain where monitoring_code=1 and monitoring_count=%s", (leastCount,))
        found = self.cursor.fetchall()
        records = len(found)
        if number < records:
            records = number
        try:
            bar = pyprind.ProgBar(records)
            for i in range(0, records):
                hostname = found[i][1]
                secondLD = found[i][2]
                domain = found[i][3]
                #   can use difference ns servers using ns in nameservers
                ip, c_name = retIP(domain)
                if ip !='' and ip != None:
                    #   Check if same dns-IP pair found, if not adding records
                    self.saveDomainIP(domain, ip, scan_date, source)
                    if domain != secondLD:
                        self.saveDomainIP(secondLD, ip, scan_date, source)
                    if c_name is not None:
                        cname = c_name.to_text()
                        if cname.endswith('.'):
                            cname = cname[:-1]
                        if cname != domain:
                            self.saveDomainIP(cname, ip, scan_date, source)
                self.cursor.execute("update domain set monitoring_count=%s where domain = %s", (leastCount+1,domain))
                number = number - 1
                bar.update()

            self.db.commit()

        except MySQLdb.Error, e:
            if self.db:
                self.db.rollback()
            msg = "[*] Exception %d: %s" % (e.args[0],e.args[1])
            logging.error(msg)
            pass


    def scanSubnet(self, num=None):
        #   Scan & update parked domains based on the selected subnet from subnet table
        if num is None:
            number = 20
        else:
            number = int(num)
        #   Find current working count number
        table = 'subnet'
        leastCount = self.findCount(table)
        if leastCount == -1:
            leastCount = 0
        scan_date = self.today
        msg = '... Checking %s subnet with monitoring_count=%s' % (number, leastCount)
        logging.info(msg)
        print msg
        source = 'Monitoring Subnets'
        #   Extract marked subnet list
        self.cursor.execute("select * from subnet where monitoring_code=1 and monitoring_count=%s", (leastCount,))
        found = self.cursor.fetchall()
        records = len(found)
        if number < records:
            records = number
        try:
            #bar = pyprind.ProgBar(records)
            for i in range(0, records):
                id = found[i][0]
                subnet = found[i][1]
                #   find ip and submit to get_parkedSubnet
                ip, mask = subnet.split('/')
                parknets = get_parkedSubnet(ip)
                bar = pyprind.ProgBar(len(parknets))
                for j in range(0, len(parknets)):
                    ip = parknets[j]['data']
                    domain = parknets[j]['domain']
                    self.saveDomainIP(domain, ip, scan_date, source)
                    bar.update()
                self.cursor.execute("update subnet set monitoring_count=%s where subnet = %s", (leastCount+1,subnet))
                number = number - 1
                #bar.update()

            self.db.commit()

        except MySQLdb.Error, e:
            if self.db:
                self.db.rollback()
            msg = "[*] Exception %d: %s" % (e.args[0],e.args[1])
            logging.error(msg)
            pass


    def scanGeoIP(self,data=None):
        if not GEOIP:
            sys.exit()
        #   Scan & update GeoIP based on the ip table provided
        #   Extract ip list
        msg = '[+] Building ip list for processing ... '
        print msg
        self.cursor.execute("select * from ip where monitoring_code=1")
        found = self.cursor.fetchall()
        bar = pyprind.ProgBar(len(found))
        for i in range(0, len(found)):
            ip_id = found[i][0]
            ip = found[i][1]
            self.saveGeo(ip_id, ip)
            bar.update()


    def getGeo(self, ip):
        response = ''
        if not os.path.exists('GeoLite2-City.mmdb'):
            msg = "[*] GeoLite2-City.mmdb is not found ..."
            logging.error(msg)
        else:
            try:
                reader = geoip2.database.Reader('GeoLite2-City.mmdb')
                response = reader.city(ip)
            except:
                #   *** need fixing exception messages ***
                msg = "[*] AddressNotFoundError for ip: %s" % (ip)
                logging.error(msg)
        return response


    def getPdns(self, data):
        
        if chk_ip(data) or chk_domain(data):
            p = pdns()
            as_owners, uri, downloads, comms, c2 = p.findPassive(data)
            self.savePdnsC2(c2, 'VirusTotal')
            self.savePdns(uri, downloads, comms, c2)
        else:
            msg = "[*] %s is neither an IP Address or a domain" % (data)
            logging.error(msg)

    
    def getWeb(self, domain):

        if chk_domain(domain):
            #   find dns_id
            #   *** need to consider use current IP Address or historical IP Address in the db
            ip, c_name = retIP(domain)
            domain_id = self.findDomain_id(domain)
            
            if domain_id != 0:
                try:
                    #   using web.py class
                    w = web()
                    if w.chkOpen(ip,80):
                        w.chkWeb(domain)
                        self.cursor.execute("INSERT INTO htmls(domain_id, server, modified_date, location, encoding, no_of_scripts, no_of_links, no_of_images, no_of_iframes, html_page, scan_date) values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)", (domain_id, w.server, convertDate(w.last_modified), w.location, w.encoding, len(w.scripts), len(w.links), len(w.images), len(w.iframes), w.html.encode('utf-8'), self.today))
                        htmls_id = int(self.cursor.lastrowid)
                        #   Updating scripts
                        #   *** need checking if scripts are downloaded automatically by the web.py class
                        for i in range(0, len(w.scripts)):
                            if w.scripts[i][0] is None:
                                type = ''
                            else:
                                type = w.scripts[i][0]
                            if w.scripts[i][1] is None:
                                src = ''
                            else:
                                src = w.scripts[i][1]
                            if w.scripts[i][2] is None:
                                content = ''
                            else:
                                content = w.scripts[i][2]
                            self.cursor.execute("INSERT INTO scripts(htmls_id, type, src, content) values (%s,%s,%s,%s)", (htmls_id, type, src, content))
                        #   Updating links
                        #   *** need parsing 2nd level inside links ***
                        for i in range(0, len(w.links)):
                            if w.links[i][0] is None:
                                url = ''
                            else:
                                url = w.links[i][0]
                            if w.links[i][1] is None:
                                text = ''
                            else:
                                text = w.links[i][1]
                            self.cursor.execute("INSERT INTO links(htmls_id, url, text) values (%s,%s,%s)", (htmls_id, url.encode('utf-8'), text.encode('utf-8')))
                        #   Updating images
                        for i in range(0, len(w.images)):
                            if w.images[i][0] is None:
                                src = ''
                            else:
                                src = w.images[i][0]
                            if w.images[i][1] is None:
                                alt = ''
                            else:
                                alt = w.images[i][1]
                            self.cursor.execute("INSERT INTO images(htmls_id, src, alt) values (%s,%s,%s)", (htmls_id, src, alt.encode('utf-8')))
                        #   Updating iframes
                        #   *** need parsing and download external iframes ***
                        for i in range(0, len(w.iframes)):
                            if w.iframes[i][0] is None:
                                src = ''
                            else:
                                src = w.iframes[i][0]
                            self.cursor.execute("INSERT INTO iframes(htmls_id, src) values (%s,%s)", (htmls_id, src))
                        self.db.commit()
                    else:
                        msg = "[-] %s port 80 is not opened" % (domain)
                        logging.info(msg)
    
                except MySQLdb.Error, e:
                    if self.db:
                        self.db.rollback()
                        msg = "[*] Exception %d: %s" % (e.args[0],e.args[1])
                        logging.error(msg)
                        pass
            else:
                msg = "[*] %s domain is not found, update first" % (domain)
                logging.error(msg)
                print msg
        else:
            msg = "[*] Please provide a domain, not %s" % (domain)
            logging.error(msg)


    def updateDomain(self, domain, source=None, tlp_id=None, monitoring_code=None, monitoring_count=None):
        #   validate dns, ip, source
        if monitoring_code is None:
            monitoring_code = 0
        if tlp_id is None:
            tlp_id = 3
        scan_date = self.today
        if source is None:
            source = 'Manual'
        if chk_domain(domain):
            ip, c_name = retIP(domain)
            hostname, secondLD = chk_hostname(domain)
            self.saveDomainIP(domain, ip, scan_date, source, tlp_id, monitoring_code, monitoring_count)
            if domain != secondLD:
                self.saveDomainIP(secondLD, ip, scan_date, source, tlp_id, monitoring_code, monitoring_count)
            if c_name is not None and c_name !='':
                cname = c_name.to_text()
                if cname[-1] == '.':
                    cname = cname[:-1]
                if cname != domain:
                    self.saveDomainIP(cname, ip, scan_date, source, tlp_id, monitoring_code, monitoring_count)
        else:
            msg = "[*] Please provide domain, not %s" % (domain)
            logging.error(msg)


    def updateIP(self, ip, source=None, tlp_id=None, monitoring_code=None, monitoring_count=None):
        #   validate dns, ip, source
        if monitoring_code is None:
            monitoring_code = 0
        if tlp_id is None:
            tlp_id = 3
        scan_date = self.today
        if source is None:
            source = 'Manual'
        if chk_ip(ip):
            domain = ''
            self.saveDomainIP(domain, ip, scan_date, source, tlp_id, monitoring_code, monitoring_count)
        else:
            msg = "[-] Please provide an IP Address, not %s" % (ip)
            logging.error(msg)


    def updatePair(self, domain, ip, source=None, tlp_id=None, monitoring_code=None, monitoring_count=None):
        
        #   validate dns, ip, source
        if monitoring_code is None:
            monitoring_code = 0
        if tlp_id is None:
            tlp_id = 3
        scan_date = self.today
        if source is None:
            source = 'Manual'
        #   using 'or' to handle cases of ip = '' or domain = ''
        if chk_ip(ip) or chk_domain(domain):
            hostname, secondLD = chk_hostname(domain)
            self.saveDomainIP(domain, ip, scan_date, source, tlp_id, monitoring_code, monitoring_count)
            if domain != secondLD:
                self.saveDomainIP(secondLD, ip, scan_date, source, tlp_id, monitoring_code, monitoring_count)
        else:
            msg = "[-] Please provide domain=%s, IP Address=%s" % (domain, ip)
            logging.error(msg)


    def saveGeo(self, ip_id, ip):
        #   update geo locations
        scan_date = self.today
        if chk_ip(ip) and chk_routable(ip):
            response = self.getGeo(ip)
            if response is not str and response !='' and response is not None and response.country.iso_code is not None:
                #   check if record found
                sql = "select * from geoip where ip_id = %s" % (ip_id)
                self.cursor.execute(sql)
                found = self.cursor.fetchone()
                if found:
                    sql = "update geoip set latitude=%s, longitude=%s, scan_date='%s' where ip_id=%s" % (response.location.latitude, response.location.longitude, self.today, ip_id)
                    self.cursor.execute(sql)
                    msg = '[-] Record found, only geo location of %s is updated' % (ip)
                    logging.info(msg)
                else:
                    sql = "insert into geoip(country_code, country_name, city_name, latitude, longitude, ip_id, scan_date) values (%s,%s,%s,%s,%s,%s,%s)"
                    self.cursor.execute(sql, (response.country.iso_code, response.country.name, response.city.name, response.location.latitude, response.location.longitude, ip_id, self.today))
                    msg = '[+] Adding Geo location for ip: %s' % (ip)
                    logging.info(msg)
                self.db.commit()
        else:
            msg = "[*] No Geo location updated to ip: %s" % (ip)
            logging.error(msg)


    def saveCases(self, tag, desc=None):
        if desc == None:
            desc = ''
        name = tag
        case_date = self.today
        description = desc
        #   check if same case name found
        sql = "select id from cases where name = %s"
        self.cursor.execute(sql, (name,))
        found = self.cursor.fetchone()
        if found:
            case_id = int(found[0])
        else:
            self.cursor.execute("INSERT ignore INTO cases(name, description, case_date) values (%s,%s,%s)", (name, description, case_date))
            sample_id = int(self.cursor.lastrowid)
        self.db.commit()


    def saveC2(self, sample_id, dns_id, tag, detection_date=None):
        if detection_date == None:
            detection_date = self.today
        source = tag
        #   check if same C2 with dns_id found
        sql = "select id from c2 where dns_id = %s"
        self.cursor.execute(sql, (dns_id,))
        found = self.cursor.fetchone()
        if found:
            msg = '[-] C2 with same dns_id found, not update'
            logging.info(msg)
        else:
            #   *** separate sql statement and log it ***
            self.cursor.execute("INSERT ignore INTO c2(dns_id, sample_id, detection_date, source) values (%s,%s,%s,%s)", (dns_id, sample_id, detection_date, source))
        self.db.commit()


    def saveArtefacts(self, ip_id, domain_id, sample_id, case_id):
        #   check if same case_artefacts with sample_id found
        sql = "select id from case_artefacts where sample_id = %s and ip_id =%s and domain_id=%s"
        self.cursor.execute(sql, (sample_id, ip_id, domain_id))
        found = self.cursor.fetchone()
        if found:
            msg = '[-] Artefacts with same sample_id found, not update'
            logging.info(msg)
        else:
            self.cursor.execute("INSERT ignore INTO case_artefacts(ip_id, domain_id, sample_id, case_id) values (%s,%s,%s,%s)", (ip_id, domain_id, sample_id, case_id))
            self.db.commit()


    def savePdnsC2(self, c2, tag):
        #   init variables
        source = tag
        confidence = 3
        monitoring_code = 1
        monitoring_count = 0
        tlp_id = 3
        bar = pyprind.ProgBar(len(c2))
        for i in range(0, len(c2)):
            #   find dns, ip, scan_date
            scan_date = c2[i].get('date')
            if chk_ip(c2[i].get('from_')):
                ip = c2[i].get('from_')
                domain = c2[i].get('_to')
            else:
                domain = c2[i].get('from_')
                ip = c2[i].get('_to')

            #   Updating (domain, ip, asn, subnet, domain, whois) tables
            hostname, secondLD = chk_hostname(domain)
            self.saveDomainIP(domain, ip, scan_date, source, tlp_id, monitoring_code, monitoring_count)
            if secondLD != domain:
                self.saveDomainIP(secondLD, ip, scan_date, source, tlp_id, monitoring_code, monitoring_count)
            bar.update()


    def savePdns(self, uri, downloads, comms, c2):
        #   init variables
        source = 'rPdns'

        #   check if data is an ip address or a domain
        for i in range(0, len(c2)):
            
            try:
                sha256 = ''
                scan_date = c2[i].get('date')
                if chk_ip(c2[i].get('from_')):
                    ip = c2[i].get('from_')
                    domain = c2[i].get('_to')
                else:
                    domain = c2[i].get('from_')
                    ip = c2[i].get('_to')
                
                dns_id = self.findDns_id(domain, ip)
                #   find if sample in download *** insert a global var to auto download the samples ***
                for j in range(0, len(downloads)):
                    src = downloads[j].get('source')
                    sample_date = downloads[j].get('date')
                    hash = downloads[j].get('hash')
                    if src == c2[i].get('_to'):
                        sha256 = hash
                        #   Updating malware_sample table
                        self.cursor.execute("select id from malware_sample where sha256 = %s", (sha256,))
                        found2 = self.cursor.fetchone()
                        if found2:
                            sample_id = found2[0]
                            msg = '[-] Sample found, no update'
                            #logging.info(msg)
                        else:
                            msg = "[+] Updating sample: %s (%s) on %s" % (domain, ip, scan_date)
                            logging.info(msg)
                            self.cursor.execute("INSERT ignore INTO malware_sample(sha256, source) values (%s,%s)", (sha256, source))
                            sample_id = int(self.cursor.lastrowid)
                        #   Updating c2 table
                        self.cursor.execute("select id from c2 where dns_id = %s and sample_id = %s", (dns_id, sample_id))
                        found2 = self.cursor.fetchone()
                        if found2:
                            c2_id = int(found2[0])
                        else:
                            msg = "[+] Updating c2: %s [%s] (dns_id=%s, sample_id=%s)" % (domain, ip, dns_id, sample_id)
                            logging.info(msg)
                            self.cursor.execute("INSERT INTO c2(dns_id, sample_id, detection_date, source) values (%s,%s,%s,%s)", (dns_id, sample_id, scan_date, source))
                            c2_id = int(self.cursor.lastrowid)
        
                        #   *** PDNSDOWNLOAD is to be set in MalProfile.ini ***
                        PDNSDOWNLOAD = True
                        if PDNSDOWNLOAD:
                            msg = '... Trying to download sample: %s' % (hash)
                            logging.info(msg)
                            sha256 = hash
                            repo = './repo'
                            folder = os.path.join(repo, source, 'binaries', sha256[0], sha256[1], sha256[2], sha256[3])
                            destination_file = os.path.join(folder, sha256)
                            if not os.path.exists(destination_file):
                                msg = '... Preparing download of %s' % (sha256)
                                logging.info(msg)
                                p = pdns()
                                p.get_download(sha256, source)
                            else:
                                msg = '[-] Sample is found in repository folder: %s' % (folder)
                                logging.info(msg)
                            if not os.path.exists(destination_file):
                                msg = "[*] No sample downloaded: %s" % (sha256)
                                logging.info(msg)
                            else:
                                hashs = get_hashes(destination_file)
                                self.saveSample(hashs, source)
                                msg = '[+] Saving download of %s to %s' % (sha256, folder)
                                logging.info(msg)
        
                msg = "[+] Updating urls (%s): %s (%s) on %s" % (dns_id, domain, ip, scan_date)
                logging.info(msg)
                
                #   updating urls and communicate_with tables
                for k in range(0, len(uri)):
                    src = uri[k].get('source')
                    detection_date = uri[k].get('date')
                    url = uri[k].get('url')
                    if src == c2[i].get('from_') and url is not None and url != '':
                        self.cursor.execute("INSERT ignore INTO urls(dns_id, detection_date, url) values (%s,%s,%s)", (dns_id, detection_date, url))
                
                for k in range(0, len(comms)):
                    src = comms[k].get('source')
                    detection_date = comms[k].get('date')
                    hash = comms[k].get('hash')
                    if src == c2[i].get('from_'):
                        self.cursor.execute("INSERT ignore INTO communicate_with(dns_id, detection_date, sha256) values (%s,%s,%s)", (dns_id, detection_date, hash))
                self.db.commit()

            except MySQLdb.Error, e:
                
                if self.db:
                    self.db.rollback()
                    msg = "Exception %d: %s" % (e.args[0],e.args[1])
                    logging.error(msg)
                pass


    def saveSample(self, hashs, tag, detection_date=None):
        #   init variables, assume hashs is passed as a list from get_hashes(path)
        md5 = ''
        sha1 = ''
        sha256 =''
        if detection_date is None:
            detection_date = self.today
        crc32 = hashs[0]
        md5 = hashs[1]
        sha1 = hashs[2]
        sha256 = hashs[3]
        
        #   Updating malware_sample table
        self.cursor.execute("select * from malware_sample where md5 = %s or sha1 = %s or sha256 = %s", (md5,sha1,sha256))
        found2 = self.cursor.fetchone()
        if found2:
            sample_id = found2[0]
            msg = '[-] Sample %s found, no update' % (md5)
            #logging.info(msg)
            if (not found2[3]) or (not found2[1]):
                self.cursor.execute("update malware_sample set md5=%s, sha1=%s, sha256=%s, source=%s where id=%s", (md5, sha1, sha256, tag, sample_id))
        else:
            self.cursor.execute("INSERT ignore INTO malware_sample(md5, sha1, sha256, source) values (%s,%s,%s,%s)", (md5, sha1, sha256, tag))
            sample_id = int(self.cursor.lastrowid)
            msg = "[+] Sample from %s (%s), updated" % (tag, sample_id)
            logging.info(msg)

        #   update av_classification from VirusTotal
        p = pdns()
        if md5:
            hash = md5
        elif sha1:
            hash = sha1
        else:
            hash = sha256
        #   check if av_classification added
        self.cursor.execute("select * from av_classification where sample_id=%s", (sample_id,))
        found2 = self.cursor.fetchone()
        if found2:
            msg = "[-] sample's av_classification found, no update..."
            #logging.info(msg)
        else:
            #   *** consider to download the samples ***
            result = p.getClassification(hash)
            for i in range(0, len(result)):
                av_vendor = result[i].get('av_vendor')
                detection_name = result[i].get('name')
                self.cursor.execute("INSERT ignore INTO av_classification(av_vendor, detection_name, sample_id) values (%s,%s,%s)", (av_vendor, detection_name, sample_id))

        self.db.commit()


    def saveDomainIP(self, domain, ip, scan_date, source, tlp_id=None, monitoring_code=None, monitoring_count=None, confidence=None):

        #  init varialbles
        resolve_date = self.today
        if tlp_id is None:
            tlp_id = 3
        if confidence is None:
            confidence = 3
        if monitoring_code is None:
            monitoring_code = 0
        if monitoring_count is None:
            monitoring_count = 0
        new_count = 0

        try:
            
            hostname, secondLD = chk_hostname(domain)
        
            #   if using: AS number & subnets, [cookies.sqlite] is needed
            asn_id = 0
            if ASN:
                asn = 0
                subnet = ''
                if chk_ip(ip) and chk_routable(ip):
                    #   try finding asn from db
                    asn, subnet = get_asn1(ip)
                    if not is_subnet(ip, subnet):
                        msg = "[*] asn(%s) was found in subnet(%s) db ... " % (ip, subnet)
                        logging.info(msg)
                        asn = 0
                    if asn == 0:
                        #   try finding asn from ipwhois modules
                        asn, subnet = get_asn2(ip)
                    if asn == 0:
                        #   try finding asn from bgp.he.net(Hurricane)
                        msg = "[*] using Hurricane web free access ..."
                        logging.info(msg)
                        asn, subnet = get_asn3(ip)
                        #if asn != 0:
                        #  update subnets if not found
                        parseSubnet(asn)
                    if asn == '':
                        asn = 0
                    
                    sql = 'select id from autonomous_system where asn = %s' % (asn)
                    self.cursor.execute(sql)
                    found = self.cursor.fetchone()
                    if found:
                        asn_id = int(found[0])


            #   Update ip, if not found
            ip_id = self.findIP_id(ip)
            if ip_id == 0:
                if asn_id == 0:
                    self.cursor.execute("INSERT ignore INTO ip(ip, source, tlp_id, monitoring_code, monitoring_count) values (%s,%s,%s,%s,%s)", (ip, source, tlp_id, monitoring_code, monitoring_count))
                    ip_id = int(self.cursor.lastrowid)
                else:
                    self.cursor.execute("INSERT ignore INTO ip(ip, source, asn_id, tlp_id, monitoring_code, monitoring_count) values (%s,%s,%s,%s,%s,%s)", (ip, source, asn_id, tlp_id, monitoring_code, new_count))
                    ip_id = int(self.cursor.lastrowid)
                msg = '[+] Adding ip %s (ip_id=%s)' % (ip, ip_id)
                logging.info(msg)
                #   if using: geoip, [GeoLite2-City.mmdb] is needed
                if GEOIP:
                    self.saveGeo(ip_id, ip)

            #   update domain, if not found
            domain_id = self.findDomain_id(domain)
            if domain_id == 0:
                self.cursor.execute("INSERT ignore INTO domain(hostname, domain, secondLD, source, tlp_id, monitoring_code, monitoring_count) values (%s,%s,%s,%s,%s,%s,%s)", (hostname, domain, secondLD, source, tlp_id, monitoring_code, new_count))
                domain_id = int(self.cursor.lastrowid)
                msg = '[+] Updating domain %s (domain_id=%s)' % (domain, domain_id)
                logging.info(msg)
                
            #   Update dns_link, if not found
            dns_id = self.findDns_id(domain, ip)
            if dns_id ==0:
                self.cursor.execute("INSERT INTO dns(ip_id, domain_id, source, confidence, tlp_id, scan_date) values (%s,%s,%s,%s,%s,%s)", (ip_id, domain_id, source, confidence, tlp_id, resolve_date))
                dns_id = int(self.cursor.lastrowid)
                msg = '[+] Updating dns_link(dns_id=%s) of %s(domain_id=%s) & %s(ip_id=%s))' % (dns_id, domain, domain_id, ip, ip_id)
                logging.info(msg)

            #   Update whois if not found, only secondLD will point to a whois record
            if domain == secondLD:
                ws = chk_whois(secondLD)
                if len(ws['createdate']) > 1:
                    createdate = ws['createdate'][0]
                else:
                    createdate = ws['createdate']
                domain_id = self.findDomain_id(secondLD)
                #   check if whois record found with same registrant & email
                self.cursor.execute("select id from whois where domain_id = %s and registrant_name = %s and registrant_email = %s", (domain_id, ws['registrant'], ws['email']))
                found = self.cursor.fetchone()
                if found:
                    msg = '[-] Found %s registered by %s (%s), no whois updated' % (domain, ws['registrant'], ws['email'])
                    #logging.info(msg)
                else:
                    self.cursor.execute("INSERT INTO whois(creation_date, registrar, registrant_name, registrant_email, name_servers, telephone, last_scan_date, domain_id, monitoring_code, monitoring_count) values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)", (convertDate(createdate), ws['registrar'], ws['registrant'], ws['email'], ws['ns'], ws['tel'], today, domain_id, monitoring_code, new_count))
                    msg = '[+] Updating %s whois records by (%s) on %s' % (domain, ws['email'], self.today)
                    logging.info(msg)

            self.db.commit()

        except MySQLdb.Error, e:
            
            if self.db:
                self.db.rollback()
            
            msg = "Exception %d: %s" % (e.args[0],e.args[1])
            logging.error(msg)
            pass





