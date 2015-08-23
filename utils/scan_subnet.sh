#!/bin/bash

cd $HOME/Malyzer/Maltelligence
echo "Start scheduled job to scan subnet" >> ./log/scan_subnet.log
date +"%Y-%m-%d %T" >> ./log/scan_subnet.log
python Maltelligence.py -s 50 --subnet >> ./log/scan_subnet.log
