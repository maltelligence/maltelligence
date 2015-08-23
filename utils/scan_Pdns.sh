#!/bin/bash

cd $HOME/Malyzer/Maltelligence
echo "Start scheduled job to scan rPdns for domains in c2" >> ./log/scan_rPdns.log 
date +"%Y-%m-%d %T" >> ./log/scan_rPdns.log
python Maltelligence.py -s 5 --Pdns >> ./log/scan_rPdns.log
