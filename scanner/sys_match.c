
#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fcntl.h>
#include <linux/uaccess.h>
#include <linux/slab.h>


#define SUCCESS 0
#define PAGE_SIZE_COPY 4096


struct userArgs {
	__user char * target;
	__user char * pattern;
	unsigned int tsize;
	unsigned int psize;
	
};

int kmp(char *target, int tsize, char *pattern, int psize);
asmlinkage extern long (*sysptr)(void *arg);

asmlinkage long scanner(void * args, int argslen)
{
	struct userArgs *usrArg ;
	char * target;
	unsigned int tsize;
	char * pattern;
	unsigned int psize;
	
	usrArg = kmalloc(sizeof(struct userArgs), GFP_KERNEL);
	int ret = -1;
	if (usrArg == NULL) {
		printk(KERN_DEBUG "ERROR: error occured in memory allocation\n");
		ret = -ENOMEM;
		
	}
	/* Copy the structure from user space to address space */
	ret = copy_from_user(usrArg, args, argslen);
	
	if (ret < 0) {
		printk(KERN_DEBUG "ERROR: error occured from copy_from_user\n");
		ret = -EFAULT;
	}
	
	target = usrArg->target;
	pattern = usrArg->pattern;
	tsize = strnlen(usrArg->target,100000);
	psize = strnlen(usrArg->pattern,100000);
	
	/* printk("%s", target);
	printk("%s", pattern);
	printk("%d", tsize);
	printk("%d", psize); */
	
	int retval = SUCCESS;
	retval = kmp(target,tsize,pattern,psize);
	return retval;
}





int *compute_prefix_function(char *pattern, int psize)
{
	int k = -1;
	int i = 1;
	int *pi = kmalloc(sizeof(int)*psize, GFP_KERNEL);
	if (!pi)
		return NULL;

	pi[0] = k;
	for (i = 1; i < psize; i++) {
		while (k > -1 && pattern[k+1] != pattern[i])
			k = pi[k];
		if (pattern[i] == pattern[k+1])
			k++;
		pi[i] = k;
	}
	return pi;
}

int kmp(char *target, int tsize, char *pattern, int psize)
{
	int i;
	int *pi = compute_prefix_function(pattern, psize);
	int k = -1;
	if (!pi)
		return -1;
	for (i = 0; i < tsize; i++) {
		while (k > -1 && pattern[k+1] != target[i])
			k = pi[k];
		if (target[i] == pattern[k+1])
			k++;
		if (k == psize - 1) {
			kfree(pi);
			return i-k;
		}
	}
	kfree(pi);
	return -1;
}




static int __init init_sys_match(void)
{
	if (sysptr == NULL)
		sysptr = scanner;
	
	printk(KERN_INFO "installed new sys_match module %p %p\n", sysptr, &scanner);
	return SUCCESS;
}
static void  __exit exit_sys_match(void)
{
	if (sysptr != NULL)
		sysptr = NULL;
	printk(KERN_INFO "removed sys_match module\n");
}
module_init(init_sys_match);
module_exit(exit_sys_match);
MODULE_LICENSE("GPL");
