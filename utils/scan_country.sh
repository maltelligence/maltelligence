#!/bin/bash

cd $HOME/Malyzer/Maltelligence
echo "Start scheduled job to scan country to update asn" >> ./log/scan_country.log
date +"%Y-%m-%d %T" >> ./log/scan_country.log
python Maltelligence.py -s 0 --country >> ./log/scan_country.log
