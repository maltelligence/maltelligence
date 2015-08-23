#!/bin/bash

cd $HOME/Malyzer/Maltelligence
mysql -u root -p -e "drop database maltelligence"
mysql -u root -p -e "create schema maltelligence default character set utf8"
mysql -u root -p maltelligence < ./db/maltelligence_0818a.sql
rm ./log/maltelligence.log
#rm -rf ./repo/*
python clean_up.py
python report.py -t
