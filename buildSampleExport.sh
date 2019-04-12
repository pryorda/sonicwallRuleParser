cat /mnt/sampleExport.txt |sed ':a;N;$!ba;s/\n/\&/g' |base64 -w 0 > /mnt/sampleExport.exp
