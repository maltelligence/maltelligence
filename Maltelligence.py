#!/usr/bin/python
# Name: Maltelligence.py
# Version: 0.91
# By:   Maltelligence Research Group
# Created:  Dec 25, 2014
# Modified: Aug 13, 2015
# Function: a caller script for Maltelligence Tool from bash shell
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


from utils.config import *
from utils.utility import *
from utils.dnsutils import *
from modules.pdns import pdns
from modules.db import db
from modules.web import web

#logging.info('Maltelligence start')

if LOGO:
    logo()
else:
    print ''

def main():
    
    parser = argparse.ArgumentParser()
    
    parser.add_argument("-b", action="store_true", dest="batch", default=False, help="BATCH processing a [domain|ip|md5] file")
    parser.add_argument("-c", action="store_true", dest="case", default=False, help="create a CASE by providing [domain or ip] and a sample")
    parser.add_argument("-d", action="store_true", dest="download", help="to DOWNLOAD sample")
    parser.add_argument("-p", action="store", dest="parked", choices=['ip', 'subnet'], help="parse & update PARKED domains by a submitted ip")
    parser.add_argument("-q", action="store_true", dest="query", help="make & update recursive Pdns QUERIES")
    parser.add_argument("-u", action="store_true", dest="update", default=False, help="UPDATE [domain or ip]")
    parser.add_argument("-w", action="store_true", dest="web", help="parse domain's html details")
    parser.add_argument("-m", action="store_true", dest="monitor", default=False, help="specify if MONITORED")
    parser.add_argument("-r", action="store_true", dest="move", help="transfer file to REPOSITORY")
    
    parser.add_argument("--path", action="store", dest="path", help="specify PATH of sample, pcap or memory_dump file")
    parser.add_argument("--hash", action="store", dest="hash", help="specify HASH to download")
    
    parser.add_argument("--tlp", type=int, action="store", dest="tlp", choices=[1,2,3,4], default=3, help="specify a tlp code")
    parser.add_argument("--tag", type=str, action="store", dest="tag", help="provide a SOURCE tag")

    parser.add_argument("--target", type=str, nargs="*", action="store", dest="target", help="<domain>, <ip> or <dns ip>")
    
    args = parser.parse_args()
    
    #print args
    d = db()
    
    if args.update:
        #   check monitoring?
        if args.monitor:
            monitoring_code = 1
        else:
            monitoring_code = 0
        if args.target == None or args.tag ==None:
            print "[*] update: -u [-m] --target DOMAIN [IP] --tag TAG"
            sys.exit(1)
        elif len(args.target) == 1:
            if chk_ip(args.target[0]):
                ip = args.target[0]
                print '[+] Updating ip %s' % (ip)
                d.updateIP(ip, args.tag, args.tlp, monitoring_code)
            elif chk_domain(args.target[0]):
                domain = args.target[0]
                print '[+] Updating domain %s' % (domain)
                d.updateDomain(domain, args.tag, args.tlp, monitoring_code)
            else:
                print "[*] %s is neither a domain or an ip" % (args.target[0])
        elif len(args.target) == 2:
            if chk_ip(args.target[0]):
                ip = args.target[0]
                domain = args.target[1]
            else:
                domain = args.target[0]
                ip = args.target[1]
            msg = '[*] Updating domain-ip pair: %s, %s with tag=%s' % (domain, ip, args.tag)
            logging.info(msg)
            print msg
            d.updatePair(domain, ip, args.tag, args.tlp, monitoring_code)
        else:
            print "[*] update: -u [-m] --target DOMAIN [IP] --tag TAG"


    if args.parked:
        #   check monitoring?
        if args.monitor:
            monitoring_code = 1
        else:
            monitoring_code = 0
        if args.target == None or args.tag ==None:
            print "[*] check parked: -p [-m] {ip, subnet} --target [IP] --tag TAG"
            sys.exit(1)
        elif len(args.target) == 1:
            if chk_ip(args.target[0]) and args.parked == 'ip':
                ip = args.target[0]
                print '[+] Check parked domains of ip %s' % (ip)
                parked = get_parked(ip)
                #   save parked
                print '[+] Updating %s records' % (len(parked))
                for i in range(0, len(parked)):
                    domain = parked[i]['domain']
                    ip = parked[i]['data']
                    d.updatePair(domain, ip, args.tag, args.tlp, monitoring_code)
            elif args.parked == 'subnet':
                ip = args.target[0]
                print '[+] Updating parked domains from subnet of ip %s' % (ip)
                parknets = get_parkedSubnet(ip)
                #   save parknets
                print 'Updating %s records' % (len(parknets))
                bar = pyprind.ProgBar(len(parknets))
                for i in range(0, len(parknets)):
                    domain = parknets[i]['domain']
                    ip = parknets[i]['data']
                    d.updatePair(domain, ip, args.tag, args.tlp, monitoring_code)
                    bar.update()
            else:
                print "[*] %s is neither a subnet or an ip" % (args.target[0])

    
    if args.web:
        #   check --target to parse domain's web details
        if args.target == None:
            print "[*] parse web: -w --target DOMAIN"
            sys.exit(1)
        elif len(args.target) == 1:
            if chk_domain(args.target[0]):
                domain = args.target[0]
                print '[+] Parsing html page of %s' % (domain)
                d.getWeb(domain)
            else:
                print "[*] %s is not a domain" % (args.target[0])
        else:
            print "[*] parse web: -w --target DOMAIN"


    if args.query:
        #   make of recursive pdns queries
        if args.target == None:
            print "[*] query rPdns: -q --target DOMAIN or IP"
            sys.exit(1)
        elif len(args.target) == 1:
            if chk_ip(args.target[0]):
                ip = args.target[0]
                print '[+] Preparing rPdns %s' % (ip)
                d.getPdns(ip)
            elif chk_domain(args.target[0]):
                domain = args.target[0]
                print '[+] Preparing rPdns %s' % (domain)
                d.getPdns(domain)
            else:
                    print "[*] %s is neither a domain or an ip" % (args.target[0])


    if args.move:
        #   read source_file and write destination_file, then compute hashs and save to db
        if args.move == False or args.path ==None or args.tag == None:
            print "[*] move: -s --path PATH --tag TAG"
            sys.exit(1)
        elif os.path.exists(args.path):
            list = get_hashes(args.path)
            sha256 = list[3]
            repo = './repo'
            folder = os.path.join(repo, args.tag, 'binaries', sha256[0], sha256[1], sha256[2], sha256[3])
            if not os.path.exists(folder):
                os.makedirs(folder, 0750)
            destination_file = os.path.join(folder, sha256)
            if not os.path.exists(destination_file):
                with open(destination_file, 'wb') as reading:
                    for chunk in get_chunks(args.path):
                        reading.write(chunk)
                msg = '[+] Sample move to repository folder: %s' % (folder)
                logging.info(msg)
                print msg
            else:
                list = get_hashes(destination_file)
                msg = '[*] Sample is found in repository folder: %s' % (folder)
                logging.info(msg)
                print msg
            #   update to database
            d.saveSample(list, args.tag)
        else:
            print "[*] move: -s --path PATH --tag TAG"


    if args.case:
        
        #   check monitoring?
        if args.monitor:
            monitoring_code = 1
        else:
            monitoring_code = 0

        #   create a case by supplying domain [ip] and a sample with tag
        if args.case == False or (args.hash == None and args.tag == None) or args.target == None:
            print "[*] create case: -c [-m] --target DOMAIN [IP] --tag TAG --hash HASH [--path PATH]"
            sys.exit(1)
        elif len(args.target) == 1:
            if chk_ip(args.target[0]):
                ip = args.target[0]
                domain = ''
                #   if dns_id found, skip adding and grap ip_id, domain_id
                msg = '[+] Updating ip %s' % (ip)
                print msg
                d.updateIP(ip, args.tag, args.tlp, monitoring_code)
            elif chk_domain(args.target[0]):
                domain = args.target[0]
                ip, c_name = retIP(domain)
                #   try update dns-pair, if not update domain only
                if ip == '':
                    msg = '[+] Updating domain %s' % (domain)
                    print msg
                    d.updateDomain(domain, args.tag, args.tlp, monitoring_code)
                else:
                    msg = '[+] Updating current domain-ip pair: %s, %s with tag=%s' % (domain, ip, args.tag)
                    logging.info(msg)
                    print msg
                    d.updatePair(domain, ip, args.tag, args.tlp, monitoring_code)
            else:
                print "[*] %s is neither a domain or an ip" % (args.target[0])
        elif len(args.target) == 2:
            if chk_ip(args.target[0]):
                ip = args.target[0]
                domain = args.target[1]
            else:
                domain = args.target[0]
                ip = args.target[1]
            #   if dns_id found, skip adding and grap ip_id, domain_id
            print '[*] Updating domain-ip pair: %s, %s with tag=%s' % (domain, ip, args.tag)
            d.updatePair(domain, ip, args.tag, args.tlp, monitoring_code)

        #   try download from VirusTotal or save sample if PATH supplied. With sample, update malware_sample & check av_classification and create a case
        with_sample = 0

        if args.hash and not args.path:

            if len(args.hash) == 32 or len(args.hash) == 40 or len(args.hash) == 64:
                sha256 = args.hash
                source = args.tag
                repo = './repo'
                folder = os.path.join(repo, args.tag, 'binaries', sha256[0], sha256[1], sha256[2], sha256[3])
                destination_file = os.path.join(folder, sha256)
                if not os.path.exists(destination_file):
                    print '... Preparing download of: %s' % (sha256)
                    p = pdns()
                    p.get_download(sha256, source)
                else:
                    msg = '[-] Sample is found in repository folder: %s' % (folder)
                    logging.info(msg)
                    with_sample = 1
                if not os.path.exists(destination_file):
                    msg = "[*] Sample NOT saved in repository folder: %s" % (folder)
                    logging.info(msg)
                else:
                    with_sample = 1
            else:
                print "[*] %s is not a hash of: md5, sha1 or sha256" % (args.hash)


        if args.path and not args.hash:
            
            if os.path.exists(args.path):
                list = get_hashes(args.path)
                sha256 = list[3]
                repo = './repo'
                folder = os.path.join(repo, args.tag, 'binaries', sha256[0], sha256[1], sha256[2], sha256[3])
                if not os.path.exists(folder):
                    os.makedirs(folder, 0750)
                destination_file = os.path.join(folder, sha256)
                if not os.path.exists(destination_file):
                    with open(destination_file, 'wb') as reading:
                        for chunk in get_chunks(args.path):
                            reading.write(chunk)
                    msg = '[+] Sample saved in repository folder: %s' % (folder)
                    logging.info(msg)
                    print msg
                else:
                    msg = '[-] Sample is found in repository folder: %s' % (folder)
                    logging.info(msg)
                if os.path.exists(destination_file):
                    #   mark for d.saveSample(list, source)
                    with_sample = 1
                else:
                    msg = "[*] Sample NOT saved in repository folder: %s" % (folder)
                    logging.info(msg)

        if with_sample == 1:

            #   save sample, find dns_id, update c2
            hashs = get_hashes(destination_file)
            d.saveSample(hashs, args.tag)
            
            #   find sample_id
            sample_id = d.findSample_id(hashs)
            #   find dns_id
            dns_id = d.findDns_id(domain, ip)
            #   find domain_id
            domain_id = d.findDomain_id(domain)
            
            #   find ip_id
            ip_id = d.findIP_id(ip)
            
            if sample_id != 0 and dns_id != 0:

                #   update c2
                d.saveC2(sample_id, dns_id, args.tag)
                
                #   update cases
                d.saveCases(args.tag)
                msg = '... Trying to add cases, c2 & artefacts from source: %s' % (args.tag)
                logging.info(msg)
                
                #   find case_id
                case_id = d.findCase_id(args.tag)
                    
                #   update case_artefacts
                d.saveArtefacts(ip_id, domain_id, sample_id, case_id)


    if args.download:
        #   specify hash to download a sample from VirusTotal
        if args.hash == None or args.tag ==None:
            print "[*] download: -d --hash HASH --tag TAG"
            sys.exit(1)
        elif type(args.hash) is str:
            if len(args.hash) == 32 or len(args.hash) == 40 or len(args.hash) == 64:
                sha256 = args.hash
                source = args.tag
                repo = './repo'
                folder = os.path.join(repo, args.tag, 'binaries', sha256[0], sha256[1], sha256[2], sha256[3])
                destination_file = os.path.join(folder, sha256)
                if not os.path.exists(destination_file):
                    print '[+] Preparing download of %s' % (sha256)
                    p = pdns()
                    p.get_download(sha256, source)
                else:
                    msg = '[-] Sample is found in repository folder: %s' % (folder)
                    logging.info(msg)
                if not os.path.exists(destination_file):
                    print '[*] No sample downloaded: %s' % (sha256)
                else:
                    list = get_hashes(destination_file)
                    d.saveSample(list, source)
                msg = '[+] Saving download of %s' % (sha256)
                logging.info(msg)
                print msg

            else:
                print "[*] %s is not a hash of: md5, sha1 or sha256" % (args.hash)


    if args.batch:
        
        #   check monitoring?
        if args.monitor:
            monitoring_code = 1
        else:
            monitoring_code = 0

        #   check if batch file exist?
        if args.path == None or args.tag == None:
            print "[*] Batch Process: -b [-m] --path PATH --tag TAG"
            sys.exit(1)
        else:
            if os.path.exists(args.path):
                lines = readBatch(args.path)
                bar = pyprind.ProgBar(len(lines))
                for i in range(0, len(lines)):
                    #   check what's inside the lines[i]
                    domain = ip = md5 = ''
                    for k in lines[i].keys():
                        if k == 'domain':
                            domain = lines[i][k]
                        if k == 'ip':
                            ip = lines[i][k]
                        if k == 'md5':
                            md5 = lines[i][k]
                    if md5 != '':
                        msg = '[+] Download sample & open case of %s for %s:%s' % (md5, domain, ip)
                        #   download the sample
                        with_sample = 0
                        sha256 = md5
                        source = args.tag
                        repo = './repo'
                        folder = os.path.join(repo, args.tag, 'binaries', sha256[0], sha256[1], sha256[2], sha256[3])
                        destination_file = os.path.join(folder, sha256)
                        
                        if not os.path.exists(destination_file):
                            msg = '[+] Preparing download of %s' % (sha256)
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
                            d.saveSample(hashs, source)
                            msg = '[+] Saving download of %s' % (sha256)
                            logging.info(msg)
                            with_sample = 1

                        if domain !='' or ip !='':
                            msg = '[+] update dns-link with %s:%s' % (domain, ip)
                            logging.info(msg)
                            d.updatePair(domain, ip, args.tag, args.tlp, monitoring_code)

                            #   find sample_id
                            sample_id = d.findSample_id(hashs)
                            #   find dns_id
                            dns_id = d.findDns_id(domain, ip)
                            #   find domain_id
                            domain_id = d.findDomain_id(domain)
                                
                            #   find ip_id
                            ip_id = d.findIP_id(ip)
                            
                            if sample_id != 0 and dns_id != 0:
                                
                                #   update c2
                                d.saveC2(sample_id, dns_id, args.tag)
                                
                                #   update cases
                                d.saveCases(args.tag)
                                msg = '[+] Cases, C2 & Artefacts is added from source: %s' % (args.tag)
                                logging.info(msg)
                                
                                #   find case_id
                                case_id = d.findCase_id(args.tag)
                                
                                #   update case_artefacts
                                d.saveArtefacts(ip_id, domain_id, sample_id, case_id)

                    else:
                        if domain or ip:
                            msg = '[+] update dns-link with %s:%s' % (domain, ip)
                            logging.info(msg)
                            if domain != '' and ip !='':
                                logging.info('updatePair')
                                d.updatePair(domain, ip, args.tag, args.tlp, monitoring_code)
                            if domain != '' and ip == '':
                                logging.info('updateDomain')
                                d.updateDomain(domain, args.tag, args.tlp, monitoring_code)
                            if domain == '' and ip != '':
                                logging.info('updateIP')
                                d.updateIP(ip, args.tag, args.tlp, monitoring_code)
                        else:
                            msg = "[*] No processing, data dropped"
                            logging.info(msg)
                            logging.info(lines[i])
                    bar.update()


    if args.batch==False and args.case==False and args.download==False and args.hash==None and args.monitor==False and  args.move==False and args.parked==None and args.path==None and args.query==False and args.tag==None and args.target==None and args.tlp==3 and args.update==False and args.web==False:
        #   all default value provided
        print "usage: Maltelligence.py [-h]\n"



if __name__ == '__main__':
    main()

