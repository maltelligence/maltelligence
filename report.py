#!/usr/bin/python
# Name: MalReport.py
# Version: 0.91
# By:   Maltelligence Research Group
# Created:  Dec 25, 2014
# Modified: Aug 7, 2015
# Function: a caller script to generate report from Maltelligence Tool
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


import MySQLdb
import MySQLdb.cursors

from utils.config import *
from utils.utility import *
from utils.dnsutils import *

from modules.pdns import pdns
from modules.db import db
from modules.web import web
from prettytable import PrettyTable


db = MySQLdb.connect(DB_HOST,DB_ID,DB_PW,DB,charset="utf8", cursorclass=MySQLdb.cursors.DictCursor)
cursor = db.cursor()
cursor.execute("SET NAMES utf8mb4")

if LOGO:
    logo()
else:
    print ''


def main():
    
    parser = argparse.ArgumentParser()
    
    parser.add_argument("-c", action="store_true", dest="case", default=False, help="Case Report")
    parser.add_argument("-d", action="store_true", dest="domain", help="Domain Report")
    parser.add_argument("-i", action="store_true", dest="ip", help="IP Address Report")
    parser.add_argument("-p", action="store_true", dest="passive", help="Passive DNS Report")
    parser.add_argument("-w", action="store_true", dest="whois", help="Whois Report")
    parser.add_argument("-t", action="store_true", dest="db", help="Table Records Summary")
    parser.add_argument("-a", action="store", dest="as_report", default=False, help="AS Number Report")
    parser.add_argument("-r", action="store", dest="registrant", help="Reverse Whois Registrant Report")
    parser.add_argument("-e", action="store", dest="email", help="Reverse Whois email Report")
    parser.add_argument("-s", action="store", dest="source", help="Source Report")

    
    parser.add_argument("--asn", action="store_true", dest="asn", default=False, help="show AS number")
    parser.add_argument("--hash", action="store_true", dest="hash", default=False, help="show sample hash")
    parser.add_argument("--target", type=str, action="store", dest="target", help="<domain> or <ip>")
    
    args = parser.parse_args()
    
    #logging.info(args)
    
    if args.case:
        
        sql = 'select cases.case_date, cases.name, domain.domain, ip.ip, m.md5 from cases inner join case_artefacts as c inner join malware_sample as m inner join ip inner join domain on c.case_id = cases.id and c.sample_id = m.id and c.ip_id = ip.id and c.domain_id = domain.id order by c.sample_id'
        cursor.execute(sql)
        found = cursor.fetchall()
        if found:
            table = PrettyTable(found[0].keys())
            table.align = 'l'
            for i in range(0, len(found)):
                table.add_row(found[i].values())
            print table


    if args.db:
    
        base_sql = 'select count(*) from %s'
        table = PrettyTable(['Table name','Record'])
        table.align = 'l'

        tables = ['cases', 'c2', 'malware_sample', 'av_classification', 'case_artefacts', 'domain', 'whois', 'ip', 'geoip', 'subnet', 'autonomous_system', 'as_registrar', 'htmls', 'links', 'iframes', 'country']
        for t in tables:
            sql = base_sql % (t)
            cursor.execute(sql)
            record = cursor.fetchone()
            rec = record['count(*)']
            table.add_row((t, str(rec)))
        print table



    if args.source:
        if ASN:
            sql = 'select ip.ip, dns.scan_date, domain.domain, geoip.country_name as Country, geoip.city_name as City, geoip.latitude, geoip.longitude, a.asn from dns inner join ip inner join domain inner join geoip inner join autonomous_system as a on (dns.ip_id = ip.id and dns.domain_id = domain.id and geoip.ip_id=ip.id and a.id=ip.asn_id)  where  ip.source like "%' + args.source + '%" order by a.asn'
        else:
            sql = 'select ip.ip, dns.scan_date, domain.domain, geoip.country_name as Country, geoip.city_name as City, geoip.latitude, geoip.longitude from dns inner join ip inner join domain inner join geoip on (dns.ip_id = ip.id and dns.domain_id = domain.id and geoip.ip_id=ip.id)  where  ip.source like "%' + args.source + '%" order by ip'
        cursor.execute(sql)
        found = cursor.fetchall()
        if found:
            table = PrettyTable(found[0].keys())
            table.align = 'l'
            for i in range(0, len(found)):
                table.add_row(found[i].values())
            print table
        else:
            print "[*] Source Report: -s SOURCE <%s> is not found" % (args.source)


    if args.passive:

        if args.target == None:
            print "[*] Pdns Report: -p [--asn] --target DOMAIN [IP]"
        else:
            sql = ''
            if chk_ip(args.target):
                ip_addr = args.target
                sql = 'select ip.ip, dns.scan_date, domain.domain, geoip.country_name as Country, geoip.city_name as City, geoip.latitude, geoip.longitude from dns inner join ip inner join domain inner join geoip on (dns.ip_id = ip.id and dns.domain_id = domain.id and geoip.ip_id=ip.id)  where ip.ip = "%s"' % (ip_addr)
                if args.asn:
                    sql = 'select ip.ip, dns.scan_date, domain.domain, geoip.country_name as Country, geoip.city_name as City, geoip.latitude, geoip.longitude, a.asn from dns inner join ip inner join domain inner join geoip inner join autonomous_system as a on (dns.ip_id = ip.id and dns.domain_id = domain.id and geoip.ip_id=ip.id and a.id=ip.asn_id)  where ip.ip = "%s"' % (ip_addr)
            elif chk_domain(args.target):
                domain = args.target
                sql = 'select domain.domain, dns.scan_date, ip.ip, geoip.country_name as Country, geoip.city_name as City, geoip.latitude, geoip.longitude from dns inner join ip inner join domain inner join geoip on (dns.ip_id = ip.id and dns.domain_id = domain.id and geoip.ip_id=ip.id)  where domain.domain = "%s"' % (domain)
                if args.asn:
                    sql = 'select domain.domain, dns.scan_date, ip.ip, geoip.country_name as Country, geoip.city_name as City, geoip.latitude, geoip.longitude, a.asn from dns inner join ip inner join domain inner join geoip inner join autonomous_system as a on (dns.ip_id = ip.id and dns.domain_id = domain.id and geoip.ip_id=ip.id and a.id=ip.asn_id)  where domain.domain = "%s"' % (domain)
            if sql != '':
                cursor.execute(sql)
                found = cursor.fetchall()
                if found:
                    table = PrettyTable(found[0].keys())
                    table.align = 'l'
                    for i in range(0, len(found)):
                        table.add_row(found[i].values())
                    print table
            else:
                print "[*] %s is neither a domain or an ip" % (args.target)

    if args.whois:
        
        if args.target == None or not chk_domain(args.target):
            print "[*] Whois Report: -w --target DOMAIN"
        else:
            hostname, secondLD = chk_hostname(args.target)
            sql = 'select domain.domain, w.creation_date as created_on, w.registrar, w.registrant_name as registrant, w.registrant_email as email, w.name_servers as NS, w.telephone as Tel, w.last_scan_date as scanned_on from whois as w inner join domain on (w.domain_id=domain.id) where domain.domain like "%s"' % ("%"+secondLD+"%")
            cursor.execute(sql)
            found = cursor.fetchall()
            if found:
                table = PrettyTable(found[0].keys())
                table.align = 'l'
                table.max_width = 20
                for i in range(0, len(found)):
                    table.add_row(found[i].values())
                print table


    if args.domain:
    
        if args.target == None or not chk_domain(args.target):
            print "[*] Domain Report: -d [--hash] --target DOMAIN"
            sys.exit(1)
        else:
            #hostname, secondLD = chk_hostname(args.target)
            if args.hash:
                #sql = 'select dns.scan_date as date, ip.ip, domain.domain, m.md5 from dns inner join domain inner join ip inner join case_artefacts as c inner join malware_sample as m on (dns.domain_id=domain.id and dns.ip_id=ip.id and c.ip_id=ip.id and m.id=c.sample_id) where domain.domain like "%s"' % ("%"+secondLD+"%")
                sql = 'select dns.scan_date as date, ip.ip, domain.domain, domain.monitoring_code as M, m.md5 from dns inner join domain inner join ip inner join case_artefacts as c inner join malware_sample as m on (dns.domain_id=domain.id and dns.ip_id=ip.id and c.ip_id=ip.id and m.id=c.sample_id) where domain.domain="%s"' % (args.target)
            else:
                sql = 'select dns.scan_date as date, ip.ip, domain.domain, domain.monitoring_code as M from dns inner join domain inner join ip on (dns.domain_id=domain.id and dns.ip_id=ip.id) where domain.domain = "%s"' % (args.target)
            cursor.execute(sql)
            found = cursor.fetchall()
            if found:
                table = PrettyTable(found[0].keys())
                table.align = 'l'
                table.max_width = 20
                for i in range(0, len(found)):
                    table.add_row(found[i].values())
                print table


    if args.registrant:

        sql = 'select domain.domain, w.creation_date as created_on, w.registrar, w.registrant_name as registrant, w.registrant_email as email, w.name_servers as NS, w.telephone as Tel, w.last_scan_date as scaned_on from whois as w inner join domain on (w.domain_id=domain.id) where w.registrant_name like "%' + args.registrant + '%" order by email'
        cursor.execute(sql)
        found = cursor.fetchall()
        if found:
            table = PrettyTable(found[0].keys())
            table.align = 'l'
            table.max_width = 20
            for i in range(0, len(found)):
                table.add_row(found[i].values())
            print table

    if args.email:
        
        sql = 'select domain.domain, w.creation_date as created_on, w.registrar, w.registrant_name as registrant, w.registrant_email as email, w.name_servers as NS, w.telephone as Tel, w.last_scan_date as scaned_on from whois as w inner join domain on (w.domain_id=domain.id) where w.registrant_email like "%' + args.email + '%" order by domain.domain'
        cursor.execute(sql)
        found = cursor.fetchall()
        if found:
            table = PrettyTable(found[0].keys())
            table.align = 'l'
            table.max_width = 20
            for i in range(0, len(found)):
                table.add_row(found[i].values())
            print table


    if args.ip:
        
        if args.ip == False or not chk_ip(args.target):
            print "[*] IP Address Report: -i [--hash] --target IP"
            sys.exit(1)
        else:
            if ASN:
                if GEOIP:
                    if args.hash == False:
                        sql = 'select domain.domain, dns.scan_date as date, ip.ip, ip.monitoring_code as M, geoip.country_name as Country, geoip.city_name as City, geoip.latitude, geoip.longitude, a.asn, as_registrar.name from ip inner join dns inner join domain inner join geoip inner join autonomous_system as a inner join as_registrar on (domain.id = dns.domain_id and dns.ip_id=ip.id and geoip.ip_id=ip.id and a.id=ip.asn_id and as_registrar.id=a.registrar_id)  where ip.ip = "%s"' % (args.target)
                    else:
                        sql = 'select domain.domain, dns.scan_date as date, ip.ip, ip.monitoring_code as M, m.md5, geoip.country_name as Country, geoip.city_name as City, geoip.latitude, geoip.longitude, a.asn, as_registrar.name from ip inner join dns inner join domain inner join geoip inner join autonomous_system as a inner join as_registrar inner join case_artefacts as c inner join malware_sample as m  on (domain.id = dns.domain_id and dns.ip_id=ip.id and geoip.ip_id=ip.id and a.id=ip.asn_id and as_registrar.id=a.registrar_id and c.ip_id=ip.id and m.id=c.sample_id)  where ip.ip = "%s"' % (args.target)
                else:
                    if args.hash == False:
                        sql = 'select domain.domain, dns.scan_date as date, ip.ip, ip.monitoring_code as M, a.asn, as_registrar.name from ip inner join dns inner join domain inner join autonomous_system as a inner join as_registrar  on (domain.id = dns.domain_id and dns.ip_id=ip.id and a.id=ip.asn_id and as_registrar.id=a.registrar_id) where ip.ip = "%s"' % (args.target)
                    else:
                        sql = 'select domain.domain, dns.scan_date as date, ip.ip, ip.monitoring_code as M, a.asn, as_registrar.name, m.md5  from ip inner join dns inner join domain inner join autonomous_system as a inner join as_registrar inner join case_artefacts as c inner join malware_sample as m on (domain.id = dns.domain_id and dns.ip_id=ip.id and a.id=ip.asn_id and as_registrar.id=a.registrar_id and c.ip_id=ip.id and m.id=c.sample_id) where ip.ip = "%s"' % (args.target)
            else:
                if GEOIP:
                    if args.hash == False:
                        sql = 'select domain.domain, dns.scan_date as date, ip.ip, ip.monitoring_code as M, geoip.country_name as Country, geoip.city_name as City, geoip.latitude, geoip.longitude from ip inner join dns inner join domain inner join geoip on (domain.id = dns.domain_id and dns.ip_id=ip.id and geoip.ip_id=ip.id)  where ip.ip = "%s"' % (args.target)
                    else:
                        sql = 'select domain.domain, dns.scan_date as date, ip.ip, ip.monitoring_code as M, m.md5, geoip.country_name as Country, geoip.city_name as City, geoip.latitude, geoip.longitude from ip inner join dns inner join domain inner join geoip join case_artefacts as c inner join malware_sample as m  on (domain.id = dns.domain_id and dns.ip_id=ip.id and geoip.ip_id=ip.id and c.ip_id=ip.id and m.id=c.sample_id)  where ip.ip = "%s"' % (args.target)
                else:
                    if args.hash == False:
                        sql = 'select domain.domain, dns.scan_date as date, ip.ip, ip.monitoring_code as M from ip inner join dns inner join domain on (domain.id = dns.domain_id and dns.ip_id=ip.id) where ip.ip = "%s"' % (args.target)
                    else:
                        sql = 'select domain.domain, dns.scan_date as date, ip.ip, ip.monitoring_code as M, m.md5  from ip inner join dns inner join domain inner join case_artefacts as c inner join malware_sample as m on (domain.id = dns.domain_id and dns.ip_id=ip.id and c.ip_id=ip.id and m.id=c.sample_id) where ip.ip = "%s"' % (args.target)
            cursor.execute(sql)
            found = cursor.fetchall()
            if found:
                table = PrettyTable(found[0].keys())
                table.align = 'l'
                table.max_width = 20
                for i in range(0, len(found)):
                    table.add_row(found[i].values())
                print table


    if args.as_report:

        if args.as_report == False:
            print "[*] AS number Report: -a asn [hash]"

        if args.as_report.isdigit():
            if args.hash == False:
                sql = 'select a.asn, as_registrar.name, country.country, s.subnet, s.monitoring_code as M, s.country as residing from autonomous_system as a inner join as_registrar inner join country inner join subnet as s on (as_registrar.id=a.registrar_id and country.id=a.country_id and s.asn_id=a.id) where a.asn=%s' % (args.as_report)
            else:
                sql = 'select a.asn, as_registrar.name, country.country, ip.ip, ip.source as tag, m.md5 from ip inner join as_registrar inner join country inner join case_artefacts as c inner join malware_sample as m inner join autonomous_system as a on (as_registrar.id=a.registrar_id and country.id=a.country_id and c.ip_id=ip.id and m.id=c.sample_id and ip.asn_id=a.id) where a.asn=%s order by ip.ip' % (args.as_report)
            cursor.execute(sql)
            found = cursor.fetchall()
            if found:
                table = PrettyTable(found[0].keys())
                table.align = 'l'
                #table.max_width = 40
                for i in range(0, len(found)):
                    table.add_row(found[i].values())
                print table
        else:
            print "[*] %s is not number" % (args.as_report)


    if args.as_report==False and args.asn==False and args.case==False and args.db==False and args.email==None and args.hash==False and args.ip==False and args.passive==False and args.registrant==None and args.source==None and args.target==None and args.whois==False:
        #   all default value provided
        print "usage: report.py [-h]\n"




if __name__ == '__main__':
    main()

