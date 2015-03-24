ccflags-y += -DEXTRA_CREDIT
obj-m += sys_match.o
obj-m += syscallhijack.o

all: ondemand match userdaemon 

ondemand: ondemand.c
	gcc -g -Wall -Werror  -I/lib/modules/$(shell uname -r)/build/arch/x86/include ondemand.c -o ondemand -lssl -lcrypto


match:
	make  -Wall  -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f ondemand sys_match
	rm -rf *~	
userdaemon:
	gcc -g `pkg-config gtk+-3.0 --cflags` userdaemon.c -o userdaemon `pkg-config gtk+-3.0 --libs`
