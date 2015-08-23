#!/bin/sh
echo "Scheduled backup ..." >> /root/Malyzer/Maltelligence/log/backup.log
date +"%Y-%m-%d %T" >> /root/Malyzer/Maltelligence/log/backup.log
NOW=$(date +"%m%d")
FILE="/root/Malyzer/Maltelligence/db/maltelligence_$NOW.sql"
echo $FILE >> /root/Malyzer/Maltelligence/log/backup.log
MUSER="root"
MPASS=""
MYSQLDUMP="/usr/bin/mysqldump"
#MYSQLDUMP="/usr/local/mysql-5.6.24-osx10.8-x86_64/bin/mysqldump"
db="maltelligence"
echo `$MYSQLDUMP -u $MUSER --password=$MPASS $db > $FILE`

FILE_OLD_LOG="/root/Malyzer/Maltelligence/log/maltelligence.log"
FILE_LOG="/root/Malyzer/Maltelligence/log/maltelligence_$NOW.log"
echo `mv $FILE_OLD_LOG $FILE_LOG`
