#!/bin/bash

cd $HOME/Malyzer/Maltelligence
echo "Start scheduled job to scan subnet to update parked domains" >> ./log/scan_parked.log
date +"%Y-%m-%d %T" >> ./log/scan_parked.log
python Maltelligence.py -s 2 --parked >> ./log/scan_parked.log
