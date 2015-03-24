#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/unistd.h>
#include <asm/cacheflush.h> 
#include <asm/page.h> 
#include <asm/current.h>
#include <linux/sched.h>
#include <linux/kallsyms.h>
#include <asm/pgtable_types.h>
#include <linux/preempt.h>
#include <asm/pgtable_types.h>
#include <linux/types.h>
#include <linux/stddef.h>
#include <linux/unistd.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/in.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/dirent.h>
#include <linux/proc_fs.h>
#include <asm/processor.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>
#include <linux/init.h>
#include <asm/pgtable_types.h>
#include <linux/syscalls.h>
#include <asm/current.h>
#include <linux/moduleparam.h>


unsigned long *syscall_table = (unsigned long *) 0xc1684100;
void (*pages_rw)(struct page *page, int numpages) =  (void *) 0xc1051d50;
void (*pages_ro)(struct page *page, int numpages) =  (void *) 0xc1051cf0;

asmlinkage int (*original_write)(unsigned int, const char  *, size_t);
asmlinkage int (*original_open)(const char *, int);
int call_usermodehelper_mod(char *path, char **argv, char **envp, int wait);

static int pid_list [100];
static int last_index = -1;


struct process_id {
int size;
int pid;
};


int scanner (char * inputfile) {
	
	static int prev_pid = -1;
	
	/* if(prev_pid == -1) {
		printk("Open Called by %d", current->pid);
		prev_pid = current->pid;
	}else if(prev_pid == current->pid){
		return;
	}else{
		prev_pid = current->pid;
	} */

	printk("\nScanner called by \"%s\" (%d)", current->comm, current->pid);

	loff_t pos = 0;
	int result = 0;
	struct file *fp;
	 char cmdPath [] = "/home/utpal/Documents/NetSec/proj/antivirusforlinux/scanner/ondemand";
	 char * cmdArgv [] = {inputfile,"/home/utpal/Documents/NetSec/proj/antivirusforlinux/scanner/signature", "/home/utpal/Documents/NetSec/proj/antivirusforlinux/scanner/whitelist",NULL};
	 char * cmdEnvp [] = {"HOME = /home/utpal/Documents/NetSec/proj/antivirusforlinux/scanner",
	 "PATH = /sbin :/bin :/usr /bin", NULL};
	 result = call_usermodehelper_mod (cmdPath, cmdArgv, cmdEnvp, UMH_WAIT_PROC);

//fp = (*original_open)("/tmp/result.txt", O_RDONLY);
	fp = filp_open("/mnt/tmp/result.txt",O_RDONLY,0777);
	if(IS_ERR(fp))
	{
		printk("\n erorr in  result file is %ld" , PTR_ERR(fp));
		return 0;
	}
	char buf[10];
	 int ret = vfs_read(fp, buf,1,&pos);

	filp_close(fp,NULL);
	printk("Result: %s",buf);


printk (KERN_DEBUG "\nScanner exec! The result of call_usermodehelper is %d \n", result);

 return result;
}
 
 


static void disable_page_protection(unsigned long flags) {

    preempt_disable();
    local_irq_save(flags);    /* interrupts are now disabled */
    unsigned long value;
    asm volatile("mov %%cr0,%0" : "=r" (value));
    if (value & 0x00010000) {
            value &= ~0x00010000;
            asm volatile("mov %0,%%cr0": : "r" (value));
    }
}

static void enable_page_protection(unsigned long flags) {

    unsigned long value;
    asm volatile("mov %%cr0,%0" : "=r" (value));
    if (!(value & 0x00010000)) {
            value |= 0x00010000;
            asm volatile("mov %0,%%cr0": : "r" (value));
    }
    local_irq_restore(flags); /* interrupts are restored to their previous state */
    preempt_enable();
}



asmlinkage int new_open(const char *pathname, int flags) {
	int i=0;

/*	File * fp = filp_open("/mnt/tmp/plist",O_RDONLY,0);
	if(IS_ERR(fp)) {
        	err = PTR_ERR(filp);
       		 return err;
    	} else {
		//struct process_id p;
	
	}
	filp_close(fp,NULL); */

	for(i=0; i<last_index; i++){	
		if(pid_list[i] == current->pid){
			 return (*original_open)(pathname, flags);
		}
	}
	unsigned long flags1;
	if(pathname == NULL){
		return -ENOENT;
	}

	printk(KERN_ALERT "\nOpening %s", pathname);
	int len = strlen("/home/utpal/Documents/NetSec/");
	if (strncmp("/home/utpal/Documents/NetSec/",pathname,len) == 0) {

		printk(KERN_ALERT "\nScanning the file before opening");
		/* struct page *sys_call_page_temp;
		//printk(KERN_ALERT "\n Disabling interrupts \n");        		
		disable_page_protection(flags1);
    		sys_call_page_temp = virt_to_page(syscall_table);

    		syscall_table[__NR_open] = original_open;  
		//printk(KERN_ALERT "\n Enabling interrupts \n");    
		enable_page_protection(flags1); */ 
        	scanner(pathname);   
	
		/* printk(KERN_ALERT "\n Disabling interrupts \n");    
	    	disable_page_protection(flags1);
		    sys_call_page_temp = virt_to_page(&syscall_table);
	   // printk(KERN_ALERT "\n Modifying syscall_table \n");

	    original_open = (void *)syscall_table[__NR_open];

	    syscall_table[__NR_open] = new_open;  
	   // printk(KERN_ALERT "\n Enabling interrupts \n");    
	    enable_page_protection(flags1); */
		
		 
	}

	

	
    // hijacked open
 

 
    return (*original_open)(pathname, flags);
}
 


static int init(void) {
 
    struct page *sys_call_page_temp;
    unsigned long flags;


    printk(KERN_ALERT "\nHIJACK INIT\n");
   // printk(KERN_ALERT "\n Disabling interrupts \n");    
    disable_page_protection(flags);
    sys_call_page_temp = virt_to_page(&syscall_table);
   // printk(KERN_ALERT "\n Modifying syscall_table \n");

    original_open = (void *)syscall_table[__NR_open];

    syscall_table[__NR_open] = new_open;  
   // printk(KERN_ALERT "\n Enabling interrupts \n");    
    enable_page_protection(flags);
 
    return 0;
}
 
static void exit(void) {
     unsigned long flags;
    struct page *sys_call_page_temp;
        disable_page_protection(flags);
    sys_call_page_temp = virt_to_page(syscall_table);

    syscall_table[__NR_open] = original_open;  
	enable_page_protection(flags);
     
    printk(KERN_ALERT "MODULE EXIT\n");
 
    return;
}
int init_scanner(struct subprocess_info *info, struct cred *new){

	printk("\nInit scanner called by \"%s\" %d", current->comm, current->pid);
	last_index++;
	pid_list[last_index] = current->pid;
	char p[10];
 
	snprintf(p,10,"%d",current->pid);


	struct file * fp = filp_open("/mnt/tmp/plist",O_RDWR,0);
	if(IS_ERR(fp)) {
        	int err = PTR_ERR(fp);
       		 return err;
    	} else {
		vfs_write(fp,p,sizeof(p),0);
		vfs_write(fp,":",sizeof(":"),0);
	}
	filp_close(fp,NULL);
	return 0;	

}
 
int call_usermodehelper_mod(char *path, char **argv, char **envp, int wait){

   struct subprocess_info *info;
        gfp_t gfp_mask = (wait == UMH_NO_WAIT) ? GFP_ATOMIC : GFP_KERNEL;

        info = call_usermodehelper_setup(path, argv, envp, gfp_mask,
                                         &init_scanner, NULL, NULL);
        if (info == NULL)
                return -ENOMEM;

        return call_usermodehelper_exec(info, wait);
}




module_init(init);
module_exit(exit);
