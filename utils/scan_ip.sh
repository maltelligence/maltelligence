#!/bin/bash

cd $HOME/Malyzer/Maltelligence
echo "Starting scheduled job to scan GeoIP ..." >> ./log/scan_ip.log
date +"%Y-%m-%d %T" >> ./log/scan_ip.log
python Maltelligence.py -s 1 --ip >> ./log/scan_ip.log
