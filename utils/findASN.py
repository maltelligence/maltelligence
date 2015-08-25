# encoding: utf-8
#!/usr/bin/python
# Name: findASN.py
# By: Frankie Li
# Created:  Jan 5, 2015
# Modified: Aug 11, 2015
# Function: parsing data from  http://www.tcpiputils.com with functions of parseASN & parseSubnet
# See the file 'LICENSE' for copying permission

import sqlite3
import cookielib
import urllib2
import requests
import re

import MySQLdb

from bs4 import BeautifulSoup
from utils.config import *
from utils.utility import *
from utils.dnsutils import *

if sys.getdefaultencoding()!='utf-8':
    reload(sys)
    sys.setdefaultencoding('utf-8')

#   The html pages cannot be queried more than 10 times/day unless you have a premium account
#   0=no sign on, 1=sign on using local cookies.sqlite
#   http://www.tcpiputils.com to parseASN & parseSubnet

#logging.info('Using findASN')

def withSignOn(url):
    #   get html page from http://tcpiputils.com
    html = ''
    status = 200
    COOKIE_DB = "./cookies.sqlite"
    
    if os.path.isfile(COOKIE_DB):
        msg = '... Using tcpiputils.com Premium website access'
        #logging.info(msg)
    else:
        msg = "[*] no %s found ...!\n" % (COOKIE_DB)
        logging.error(msg)
        return html

    #   reading http://tcpiputils.com sign on cookie from firefox sqlite db
    CONTENTS = "host, path, isSecure, expiry, name, value"
    COOKIEFILE = 'cookies.lwp'
    host = 'tcpiputils.com'
    cj = cookielib.LWPCookieJar()
    con = sqlite3.connect(COOKIE_DB)
    cur = con.cursor()
    sql = "SELECT {c} FROM moz_cookies WHERE host LIKE '%{h}%'".format(c=CONTENTS, h=host)
    cur.execute(sql)
    for item in cur.fetchall():
        c = cookielib.Cookie(0, item[4], item[5],
             None, False,
             item[0], item[0].startswith('.'), item[0].startswith('.'),
             item[1], False,
             item[2],
             item[3], item[3]=="",
             None, None, {})
        cj.set_cookie(c)
    #   open html page with sign on cookie
    opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))
    urllib2.install_opener(opener)
    txheaders =  {'User-agent' : 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)'}
    txdata = None
    req = urllib2.Request(url, txdata, txheaders)
    try:
        handle = urllib2.urlopen(req)
        html = handle.read()
    except urllib2.HTTPError as e:
        logging.error(e.code)
        logging.error(e.read())
        status = e.code
    finally:
        return html, status


def parseASN(country):
    #   update country information by country code supplied
    #   normalize country code
    country = country.upper()
    
    try:
        db = MySQLdb.connect(DB_HOST,DB_ID,DB_PW,DB)
        cursor = db.cursor()
        monitoring_code = 0
        url = "http://www.tcpiputils.com/browse/as/" + country
        if sign_on == 0:
            req = requests.get(url)
            html_text = req.text
            status = req.status_code
        else:
            html_text, status = withSignOn(url)

        if status == 200:
            soup = BeautifulSoup(html_text, "html.parser")
            found = soup.find("table", {"class":"table table-condensed table-hover table-striped"})
            data = []
            if found:
                rows = found.find_all('tr')
                for row in rows:
                    cols = row.find_all('td')
                    cols = [ele.text.strip() for ele in cols]
                    data.append([ele for ele in cols if ele])

                #   update country table
                cursor.execute("select id from country where country = %s", (country,))
                found = cursor.fetchone()
                if found:
                    country_id = int(found[0])
                else:
                    cursor.execute("INSERT ignore INTO country(country) values (%s)", (country,))
                    country_id = int(cursor.lastrowid)
                print '... update country information by country code supplied'
                bar = pyprind.ProgBar(len(data))
                for i in range(0, len(data)):
                    bar.update()
                    #   update as_registrar table
                    if data[i] != []:
                        if (len(data[i]) == 7 or len(data[i]) == 6):
                            try:
                                cursor.execute("select id from as_registrar where name = %s", (data[i][1],))
                                found = cursor.fetchone()
                                if found:
                                    registrar_id = int(found[0])
                                    cursor.execute("UPDATE as_registrar set ranking=%s, ipv4=%s, ipv4_pre=%s where id=%s", (convertNumber(data[i][3]), convertNumber(data[i][4]), convertNumber(data[i][5]), registrar_id))
                                    msg = '[-] Registrar: %s (%s) updated ... ' % (data[i][1], convertNumber(data[i][0]))
                                    logging.info(msg)
                                else:
                                    cursor.execute("INSERT INTO as_registrar(name, registration_date, ranking, ipv4, ipv4_pre) values (%s,%s,%s,%s,%s)", (data[i][1], data[i][2], convertNumber(data[i][3]), convertNumber(data[i][4]), convertNumber(data[i][5])))
                                    registrar_id = int(cursor.lastrowid)
                                    msg = '[+] Registrar: %s (%s) added ... ' % (data[i][1], convertNumber(data[i][0]))
                                    logging.info(msg)
                            except UnicodeEncodeError:
                                pass
                    
                        if len(data[i]) == 3:
                            cursor.execute("select id from as_registrar where name = %s", (data[i][1].encode('utf-8'),))
                            found = cursor.fetchone()
                            if found:
                                registrar_id = int(found[0])
                                msg = '[-] Registrar: %s (%s) updated ... ' % (data[i][1], convertNumber(data[i][0]))
                                logging.info(msg)
                            else:
                                cursor.execute("INSERT ignore INTO as_registrar(name, registration_date) values (%s,%s)", (data[i][1].encode('utf-8'), data[i][2]))
                                registrar_id = int(cursor.lastrowid)
                                msg = '[+] Registrar: %s (%s) added ... ' % (data[i][1], convertNumber(data[i][0]))
                                logging.info(msg)
                        #   update autonomous_system table
                        cursor.execute("INSERT ignore INTO autonomous_system(asn, country_id, registrar_id) values (%s,%s,%s)", (convertNumber(data[i][0]), country_id, registrar_id))
            else:
                msg = "[*] Country code: %s was not found ..." % (country)
                logging.error(msg)
        else:
            msg = "[*] html request was blocked : %s" % str(status)
            logging.error(msg)
        db.commit()

    except MySQLdb.Error, e:
        if db:
            db.rollback()
        msg = "[*] Exception %d: %s" % (e.args[0],e.args[1])
        logging.error(msg)
        pass



def parseSubnet(asn):

    if type(asn) == str and asn != '':
        asn = int(asn)

    try:
        db = MySQLdb.connect(DB_HOST,DB_ID,DB_PW,DB)
        cursor = db.cursor()
        monitoring_code = 0
        
        #   check if subnet was added
        cursor.execute("select id from autonomous_system where asn = %s", (asn,))
        found = cursor.fetchone()
        if found:
            asn_id = int(found[0])
            url = "http://www.tcpiputils.com/browse/as/"+str(asn)
            if sign_on == 0:
                msg = '... Using free tcpiputils.com account without sign on...'
                logging.info(msg)
                req = requests.get(url)
                html_text = req.text
                status = req.status_code
            else:
                html_text, status = withSignOn(url)

            if status == 200:
                soup = BeautifulSoup(html_text, "html.parser")
                found = soup.findAll("table", {"class":"table table-condensed table-hover table-striped"})
                data = []
                if found:
                    rows = found[2].find_all('tr')
                    for row in rows:
                        cols = row.find_all('td')
                        cols = [ele.text.strip() for ele in cols]
                        data.append([ele for ele in cols if ele])
                #   update subnet table
                bar = pyprind.ProgBar(len(data))
                for i in range(0, len(data)):
                    bar.update()
                    if data[i] != [] and len(data[i]) == 3:
                        #   check if subnet was added
                        cursor.execute("INSERT ignore INTO subnet(subnet, asn_id, country, description, scan_date, monitoring_code) values (%s,%s,%s,%s,%s,%s)", (data[i][0], asn_id, data[i][1], data[i][2], today, monitoring_code))
                        msg = '[+] Adding: %s \t %s' % (data[i][0], data[i][1])
                        logging.info(msg)
            else:
                msg = "[*] http code: %s, web access for (%s) failed, try later ....!)" % (status, asn)
                logging.error(msg)
            db.commit()
        else:
            msg = "[*] asn (%s) not found try update country asn number first ....!)" % (asn)
            logging.error(msg)

    except MySQLdb.Error, e:
        if db:
            db.rollback()
            msg = "[*] Exception %d: %s" % (e.args[0],e.args[1])
            loggine.error(msg)
            pass

