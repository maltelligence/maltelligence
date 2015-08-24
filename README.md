#Maltelligence
###a Malware/Threat Analyst Desktop


##About

**Maltelligence** is a tool developed by Maltelligence Research Group to automatically 
collect malicious network infrastructure information and malware samples 
RECURSIVELY from various open source intelligence (OSINT) sources including 
virustotal, whois, passive DNS, IP subnets, AS number and Geolocation information.   

You may run **Maltelligence** PERIODICALLY to capture and profile the behaviour 
of malicious group of domain, IP, whois and html content along different stage/time 
of APT attacks.

**Maltelligence** is a project from the insight of [MalProfile](https://code.google.com/p/malicious-domain-profiling/)


##Installation
If you want to run your instance of Maltelligence locally on your machine, be sure 
you have the following requirements installed:

###Requirements

Below procedure is tested in Ubuntu 14.04

- Mysql installation

  The root password configured will be used in MalProfile.ini 
  
``` sh
  sudo apt-get install mysql-client-core-5.6
  sudo apt-get install mysql-server-5.6
```

- Install dependencies

``` sh
   sudo apt-get install git
   sudo apt-get install python-setuptools
   sudo apt-get install build-essential python-dev libmysqlclient-dev
   sudo apt-get install libfuzzy-dev
   sudo easy_install pip

   mkdir download
   cd download

   wget http://sourceforge.net/projects/ssdeep/files/ssdeep-2.13/ssdeep-2.13.tar.gz/download 
   tar xvfz download
   cd ssdeep-2.13/
   ./configure
   make
   make check
   sudo make install
   
   cd..
   git clone https://github.com/kbandla/pydeep.git
   cd pydeep
   python setup.py build
   sudo python setup.py install
```

- Install python modules

``` sh
   sudo pip install MySQL-python
   sudo pip install ipaddress
   sudo pip install pyprind
   sudo pip install mechanize
   sudo pip install dnspython
   sudo pip install pythonwhois
   sudo pip install ipwhois
   sudo pip install beautifulsoup4
   sudo pip install simplejson
   sudo pip install prettytable
   sudo pip install geoip2
   sudo pip install wget
```

###Installation

   Assume you use ~/Malyzer/maltelligence as the program folder

``` sh
   mkdir Malyzer
   cd Malyzer
   git clone git://github.com/maltelligence/maltelligence.git
   cd maltelligence
   mkdir log
   mkdir repo
   cd..
```

###Configuration

- Prepare Mysql database

   ONLY drop the "maltelligence"" database if it exists

``` sh
   mysql -u root -p -e "drop database maltelligence"
```

   Create the schema and import the database
   
``` sh
   mysql -u root -p -e "create schema maltelligence default character set utf8"
   mysql -u root -p maltelligence < ./db/maltelligence.sql
```

- MalProfile.ini

   Obtain a public API key from [VirusTotal](https://www.virustotal.com/) and put it on
   (THIS IS COMPULSORY!!!)(NO single or double quotes are required!!!)

``` sh
   VT_APIKEY=
```
  
   If you have API key in [passivedns.mnemonic.no](http://passivedns.mnemonic.no) for passivedns query, 

``` sh
   MN_APIKEY=
```

   VTLIMIT = True means Maltelligence will stop query when VTDEPTH is reached

``` sh
   VTLIMIT=True
```

   If one domain query from virustotal returns 4 IP addresses, VTDEPTH = 1(domain)+4(IP) = 5
   (If VTDEPTH is too large 100 or more, the query time may be extremely long and the APIKEY may be blocked!)   

``` sh 
   VTDEPTH=15
```

   If you have subcripitons on [tcpiputils.com](http://www.tcpiputils.com/premium-access) Premium account for AS Number query,
   use firefox to signin to the website with your acocunt, then copy the cookie.sqlite file from firefox under Maltelligence 
   folder then setup the below parameter.  

``` sh 
   ASN=True
```

   If you want to add Geolocation based on IP addresses   

``` sh 
   GEOIP=True
```

   If you want to display the Maltelligence logo   

``` sh    
   LOGO=True
```

   If you want to disable collection of nonroutable IP addresses (e.g. 127.0.0.1, 192.168.0.0/24)

``` sh      
   EXCLUDE_NONROUTABLE=True
```

   If you want to add additional Top Level Domain

``` sh        
   TLD=
```

   Fill in the Mysql database information under [MALTELLIGENCE] session

``` sh 
   DB_HOST=localhost
   DB_ID=root
   DB_PW=password
   DB=maltelligence
```

- Sample MalProfile.ini config:   

``` sh   
---------------------------------------------------------------------------------   
[API_KEYS]
VT_APIKEY=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
MN_APITKEY=

[VT_4]
VTLIMIT=True
VTDEPTH=15

[MALTELLIGENCE]
ASN=False
GEOIP=True
LOGO=True
EXCLUDE_NONROUTABLE=True
DB_HOST=localhost
DB_ID=root
DB_PW=password
DB=maltelligence
TLD=AC,ACADEMY,ACTOR,AD,AE,AERO,AF,AG,AGENCY,AI,AL,AM,AN,AO,AQ,AR,ARPA,AS,ASIA,...
----------------------------------------------------------------------------------
```
 
- Geolocation database setup
    
   Download (and unzip) Geolocation data from MaxMind here: 
   [http://dev.maxmind.com/geoip/geoip2/geolite2/](http://dev.maxmind.com/geoip/geoip2/geolite2/) 
   [http://geolite.maxmind.com/download/geoip/database/GeoLite2-City.mmdb.gz](http://geolite.maxmind.com/download/geoip/database/GeoLite2-City.mmdb.gz)
   Put it under the Maltelligence folder ~/Malyzer/Maltelligence/ as

``` sh
   ~/Malyzer/maltelligence/GeoLite2-City.mmdb
```

- Setup the shell to include Maltelligence path at the bottom of .profile file 

``` sh
   vi ~/.profile
   export PATH=$PATH:$HOME/Malyzer/maltelligence
```

- Database clean up

   Maltelligence comes with a sample case from Xecure incident, if you want to remove this case or start from scratch

``` sh  
   ./utils/clean_up.sh
```

   
## Usage

   **Maltelligence** composes of two main python script: Maltelligence.py and report.py
   
   Maltelligence.py - script for OSINT collection
   report.py - script for basic reporting

   **Maltelligence** group all data in a **case** as **tag**
   For each case, you need to provide at least one sample, one domain and one IP addresses
   If you don't have a sample, you could still collect the domains and IP addresses information   

   
#Maltelligence.py
   
- To get help

``` sh
   python Maltelligence.py -h
   python report.py -h
```

   To obtain the syntax of specific function, just run the related command:
   
``` sh
   python Maltelligence.py -d
```
 
- Batch collection based on groups of domain, IP and hashes in file

  For format of data file, please refer to readme/*.txt, any combination of
  IP,domain and hashes can be used

``` sh
  python Maltelligence.py -m -b --path ./readme/Xecure.txt --tag Xecure
```

- To update the database with a malicious FQDN/domain/ip (e.g. www.maltelligence.org)

``` sh
   python Maltelligence.py -u --target www.maltelligence.org --tag SampleCase
   python Maltelligence.py -c --target x.x.x.x --tag SampleCase 
```

- To create/update the database with a malicious FQDN/domain/ip AND malware samples (e.g. www.maltelligence.org)

``` sh
   python Maltelligence.py -c --tag SampleCase --target x.x.x.x www.maltelligence.org --hash  xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 
```

- To download a malware sample

``` sh
   python Maltelligence.py -d --hash  xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx --tag SampleCase
```

- To recursively collecting the domain/ip information 

``` sh
   python Maltelligence.py -q --target www.maltelligence.org 
```

- To update Parked domain from IP (IP can be a subet with format 192.168.0.0/24)

``` sh
   python Maltelligence.py -p ip --target x.x.x.x/y 
```

- To download the web page of malicious Domain

``` sh
   python Maltelligence.py -w --target www.maltelligence.org
```

#report.py

- To show summary of current collected data

``` sh
   python report.py -t
```
- To show case details in database

``` sh
   python report.py -c
```

- To show date and IP details of specific domain 

``` sh
   python report.py -d --target www.maltelligence.org
```

- To show date and domain details of specific IP 

``` sh
   python report.py -i --target x.x.x.x
```

- To show passive DNS report of specific domain 

``` sh
   python report.py -p --target www.maltelligence.org
```

- To show whois report of specific domain 

``` sh
   python report.py -w --target www.maltelligence.org
```

- To show domain of same register (search contain input string)

``` sh
   python report.py -r registername (search contain similar string)
```

- To show domain of same email (search contain similar string)

``` sh
   python report.py -e emailaddress
```

- To show domain of same case (search contain similar string)

``` sh
   python report.py -s casename
```

- Command like -d and -i can include --hash to get the malware related to specific domain/IP

``` sh
   python report.py -d --target www.maltelligence.org --hash
```


##Roadmap

- New core engine to improve data collection
- Elasticsearch/Logstash/Kibana (ELK) migration


##Team

**Maltelligence** has been developed and maintained at Maltelligence Research Group by:

Frankie
Michael
Dan
Leng
Frank

If you want to know more about Maltelligence, how it works and future developments, 
please visit the [Blog](http://maltelligence.blogspot.hk). For any specific request 
or comment we suggest you to use Github. If none of these worked for you, you can 
write us at <info@maltelligence.org>.


##License

Maltelligence is provided under the [GPL (General Public License)](https://github.com/maltelligence/raw/master/COPYING.txt) v.3:

	Copyright (c), 2015 Maltelligence Research Group
	
	<info@maltelligence.org>  
	 
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

