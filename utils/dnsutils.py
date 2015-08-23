#!/usr/bin/python
# Name: dnsutils.py
# Version: 0.91
# By: Maltelligence Research Group
# Created:  Jan 5, 2015
# Modified: Aug 7, 2015
# Function: all functions used in DNS queries
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


import mechanize
import urllib2
import dns.resolver
import pythonwhois
from ipwhois import IPWhois

from utils.config import *
from utils.utility import *
from utils.findASN import *

nameservers = {'TW':'114.34.4.1','HK':'61.244.40.66' , 'US':'64.60.46.130', 'CN':'114.66.4.54', 'GB':'213.208.238.54', 'AU':'59.154.226.27', 'SG':'203.126.107.195', 'JP':'124.146.181.113', 'FR':'195.25.102.114', 'RU':'89.179.241.19', 'KR':'112.155.225.123', 'TH':'202.183.133.18', 'DE':'87.138.68.66', 'CN1':'202.196.96.179', 'CN2':'116.246.40.160', 'CN3':'163.177.98.243'}


def chk_ip(ip):
    if ip is None:
        return False
    else:
        parts = ip.split('.')
        return (len(parts) == 4
                and all(part.isdigit() for part in parts)
                and all(0 <= int(part) <= 255 for part in parts)
                )


def chk_routable(ip):
    #   check if ip a routable IP Address
    if ip == '127.0.0.1' or ip == '0.0.0.0':
        routable = False
    else:
        routable = True
        non_routable =['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16', '127.0.0.0/8', '239.255.255.0/24', '0.0.0.0/24', '224.0.0.0/28', '240.0.0.0/27']
        if chk_ip(ip):
            for item in non_routable:
                if is_subnet(ip, item):
                    routable = False
                    break
        else:
            routable = False
    return routable


def chk_domain(domain):
    if chk_ip(domain):
        return False
    else:
        regex = '[a-zA-Z\d-]{,63}(\.[a-zA-Z\d-]{,63})*'
        p = re.compile(regex)
        matched = p.search(domain)
        if matched.lastindex == 1:
            return True
        else:
            return False


def chk_subnet(subnet):
    #   *** consider to use the is_subnet logic contains under utility
    if len(subnet.split("/")) != 2 and len(subnet.split("/")[0].split(".")):
        msg = '[*] "%s" is not a subnet format (x.x.x.x/y)' % (subnet)
        logging.info(msg)
        return False
    else:
        return True


def chk_hostname(domain):
    secondLD = hostname = ''
    parts = domain.split('.')
    j = len(parts)
    for i in range(len(parts)):
        hostname = '.'.join(parts[:i-1])
        secondLD = '.'.join(parts[i-1:])
        if parts[i].upper() in TLD and i !=0:
            break
    return hostname, secondLD


def chk_whois(domain):
    #   *** .ca is not working, check more ***
    email = ns = createdate = expirationdate = updateddate = registrar = registrant = tel = ''
    w = dict(email=email, registrar=registrar, registrant=registrant, tel=tel, ns=ns, createdate=createdate, expirationdate=expirationdate, updateddate=updateddate)
    
    if chk_domain(domain):
        hostname, secondLD = chk_hostname(domain)
        try:
            #   find whois for second-level domain
            msg = 'parsing whois data of: %s ... ' % (secondLD)
            #logging.info(msg)
            ans = pythonwhois.get_whois(secondLD, True)
        except:
            return w
        if ans['contacts'].has_key('admin'):
            if ans['contacts']['admin'] is not None:
                if ans['contacts']['admin'].has_key('email'):
                    if ans['contacts']['admin']['email'] is not None:
                        email = ans['contacts']['admin']['email']
        if ans['contacts'].has_key('registrant'):
            if ans['contacts']['registrant'] is not None:
                if ans['contacts']['registrant'].has_key('name'):
                    if ans['contacts']['registrant']['name'] is not None:
                        registrant = ans['contacts']['registrant']['name']
                if ans['contacts']['registrant'].has_key('phone'):
                    if ans['contacts']['registrant']['phone'] is not None:
                        tel = ans['contacts']['registrant']['phone']
        if ans.has_key('registrar'):
            if ans['registrar'] is not None:
                registrar = ans['registrar']
            if type(ans['registrar']) is list:
                registrar = ans['registrar'][0]
        if ans.has_key('nameservers'):
            if ans['nameservers'] is not None:
                ns = ans['nameservers'][0]
        if ans.has_key('creation_date'):
            if ans['creation_date'] is not None:
                createdate = ans['creation_date']
        if ans.has_key('expiration_date'):
            if ans['expiration_date'] is not None:
                expirationdate = ans['expiration_date']
        if ans.has_key('updated_date'):
            if ans['updated_date'] is not None:
                updateddate = ans['updated_date']
        if createdate == '' and updateddate != '':
            createdate = updateddate
        w = dict(email=email, registrar=registrar.encode('utf-8'), registrant=registrant.encode('utf-8'), tel=tel, ns=ns, createdate=createdate, expirationdate=expirationdate, updateddate=updateddate)
    else:
        msg = '[*] no whois record: %s ...' % (domain)
        logging.info(msg)
    return w


def chk_connected():
    try:
        response=urllib2.urlopen('http://www.google.com',timeout=1)
        return True
    except urllib2.URLError as err:
        pass
    return False


def retIP(domain, ns=None):
    #   added the ns option to handle CDN case where cn format = "x.x.x.x",
    #   consider using public name servers provided http://public-dns.tk or use nameservers.keys()
    ip = ''
    c_name = ''
    if domain == '':
        return ip, c_name
    resolver = dns.resolver.Resolver()
    resolver.timeout = 1
    try:
        answers = resolver.query(domain)
        ip = str(answers[0]).split(": ")[0]
        c_name = answers.canonical_name
    except Exception, e:
        msg = '[*] No IP Addressed: Timeout, NXDOMAIN, NoAnswer or NoNameservers'
        logging.info(msg)
    return ip, c_name


def retCdnIP(domain):
    #   resolve ip addresses from nameservers
    bar = pyprind.ProgBar(len(nameservers))
    ip_list = []
    for ns in nameservers:
        ip, c_name = retIP(domain, nameservers[ns])
        list = (dict(country=ns, ip=ip, c_name=c_name))
        ip_list.append(list)
        bar.update()
    return ip_list


def retDomains(ip):
    #   find parked domains by ip from Hurricane Electric, can use other source
    #   may be duplicate with get_parked(data)
    domains = []
    try:
        url = "http://bgp.he.net/ip/" + ip + "#_dns"
        userAgent = [('User-agent','Mozilla/5.0 (X11; U; '+\
                      'Linux 2.4.2-2 i586; en-US; m18) Gecko/20010131 Netscape6/6.01')]
        browser = mechanize.Browser()
        browser.addheaders = userAgent
        page = browser.open(url)
        html = page.read()
        link_finder = re.compile('href="(.*?)"')
        links = link_finder.findall(html)
        for i in range (0, len(links)):
          if links[i].find('/dns/') == 0:
              domains.append(links[i][5:])
        return domains
    except:
        return domains


def get_subnet(ip):
    #   find the subnet by ip from Hurricane Electric, can use other source
    url = "http://bgp.he.net/ip/" + ip
    html = get_url(url)
    subnets = []
    link_finder = re.compile(r'<a href="/net/([0-9.]+)/([0-9]+)">')
    links = link_finder.findall(html)
    for t in links:
        subnets.append('/'.join(t))
    return subnets[0]


def get_parked(data):
    #   find parked domains by {ip} from Hurricane Electric, same as retDomains (cancel either one)
    if chk_domain(data):
        ip, c_name = retIP(data)
    if chk_ip(data):
        ip = data
    parked = []
    try:
        msg = '... Checking bgp.he.net for %s' % (ip)
        logging.info(msg)
        url = "http://bgp.he.net/ip/" + ip + "#_dns"
        html = get_url(url)
        link_finder = re.compile('href="(.*?)"')
        links = link_finder.findall(html)
        for i in range (0, len(links)):
            if links[i].find('/dns/') == 0:
                entry = (dict(data=ip, domain=links[i][5:]))
                parked.append(entry)
    except:
        pass
    return parked


def get_parkedSubnet(data):
     #   find parked domains by {subnet} from Hurricane Electric, can use other source
    if chk_domain(data):
        ip, c_name = retIP(data)
    if chk_ip(data):
        ip = data

    net = get_subnet(ip)
    num, subnet = get_asn2(ip)
    parknets = []

    url = "http://bgp.he.net/net/" + net + "#_dns"
    html = get_url(url)
    #   check error if html is empty
    link_finder = re.compile('href="(.*?)"')
    links = link_finder.findall(html)
    msg = '... Processing parked domains of: %s ...' % (len(links))
    logging.info(msg)
    for i in range(0, len(links)):
        if links[i].find('/ip/') == 0:
            ip = links[i][4:]
        else:
            if links[i].find('/dns/') == 0:
                domain = links[i][5:]
                entry = (dict(data=ip, domain=links[i][5:]))
                parknets.append(entry)
    return parknets


def get_asn1(data):
    #   *** This function need to be further update, now NOT used ***
    if chk_domain(data):
        ip, c_name = retIP(data)
    if chk_ip(data):
        ip = data

    parts = ip.split('.')
    likes = '"%'+ parts[0]+'.'+parts[1]+'%"'
    as_number = 0
    subnet = ''
    db = MySQLdb.connect(DB_HOST,DB_ID,DB_PW,DB)
    cursor = db.cursor()
    #   try to find the largest subnet
    sql = "select a.asn, s.subnet, as_registrar.name, country.country, s.monitoring_code as M, s.country as residing from autonomous_system as a inner join as_registrar inner join country inner join subnet as s on (as_registrar.id=a.registrar_id and country.id=a.country_id and s.asn_id=a.id) where s.subnet like %s order by s.subnet desc" % (likes)
    cursor.execute(sql)
    found = cursor.fetchall()
    for i in range(0, len(found)):
        as_number = int(found[i][0])
        subnet = found[i][1]
        #   use utils.utility is_subnet function
        if is_subnet(ip, subnet):
            break
    cursor.close()
    return as_number, subnet


def get_asn2(data):
    #   find as number with ipwhois modules
    if chk_domain(data):
        ip, c_name = retIP(data)
    if chk_ip(data):
        ip = data
    
    obj = IPWhois(ip)
    results = obj.lookup()
    as_number = 0
    subnet = ''
    try:
        if results.has_key('asn'):
            as_number = int(results['asn'])
    except:
        pass
    if results.has_key('asn_cidr'):
        subnet = results['asn_cidr']
    return as_number, subnet


def get_asn3(data):
    #   get as number from bgp.he.net(Hurricane)
    if chk_domain(data):
        ip, c_name = retIP(data)
    if chk_ip(data):
        ip = data

    as_number = 0
    subnet = ''

    url = "http://bgp.he.net/ip/" + ip + "#_ipinfo"
    userAgent = [('User-agent','Mozilla/5.0 (X11; U; '+\
                  'Linux 2.4.2-2 i586; en-US; m18) Gecko/20010131 Netscape6/6.01')]
    browser = mechanize.Browser()
    browser.addheaders = userAgent
    try:
        page = browser.open(url)
        
        if page.code == 200:
            html = page.read()
            link_finder = re.compile('href="(.*?)"')
            links = link_finder.findall(html)
            as_number = ''
            for i in range(0, len(links)):
                if links[i].find('/AS') == 0:
                    as_number = int(links[i][3:])
                if links[i].find('/net') == 0:
                    subnet = links[i][5:]
    except:
        msg ="[*] Exception: in accessing Hurrican (bgp.het.net)"
        logging.error(msg)
    return as_number, subnet


def get_url(url):
    #   parse html by url supplied using mechanize
    userAgent = [('User-agent','Mozilla/5.0 (X11; U; '+\
                  'Linux 2.4.2-2 i586; en-US; m18) Gecko/20010131 Netscape6/6.01')]
    try:
        browser = mechanize.Browser()
        browser.addheaders = userAgent
        page = browser.open(url)
        html = page.read()
    except:
        html =''
    return html


def readBatch(path):
    #   Assume path found
    rows = []
    lines = []
    with open(path, 'rb') as fd:
        for row in fd:
            rows.append(row.split())
    for i in range(0, len(rows)):
        line = {}
        for j in range(0, len(rows[i])):
            data = rows[i][j]
            if chk_ip(data):
                line.update({'ip':data})
            elif chk_domain(data):
                line.update({'domain':data})
            elif len(data) == 32 or len(data) == 40 or len(data) == 64:
                line.update({'md5':data})
            else:
                msg = '[*] %s cannot be identified, skip processing' % (data)
                logging.info(msg)
        lines.append(line)
    return lines


