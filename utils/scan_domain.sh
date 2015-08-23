#!/bin/bash

cd $HOME/Malyzer/Maltelligence
echo "Start scheduled job to scan domain" >> ./log/scan_domain.log  
date +"%Y-%m-%d %T" >> ./log/scan_domain.log
python Maltelligence.py -s 100 --domain >> ./log/scan_domain.log
