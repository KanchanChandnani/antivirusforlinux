# antivirusforlinux
Signature Based Antivirus for Linux
Source files
--------------------------------------------------------
inputfile - file to be scanned
whitelist - hashes of legitimate programs [linux utilities like ls]
signature - Virus definitions

install_module.sh - script to install match LKM
userdaemon - user space daemon to display pop up on detecting virus.
sys_match - LKM retuns whether pattern exists in the targer string or not.
ondemand.c - user space program to run on demand scanning of a file.


Usage
-----------------------------------------------
Boot into kernel 3.16.0
cd /home/utpal/Documents/NetSec/proj/antivirusforlinux/scanner
make clean
make
sudo sh install_module.sh
./ondemand /bin/ls signature whitelist
./ondemand hw signature whitelist



  
# antivirusforlinux
