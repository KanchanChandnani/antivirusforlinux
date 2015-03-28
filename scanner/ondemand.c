#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>


#define __NR_scanner    354     /* our private syscall number */
#define __user
#define SHMSZ     27

/* This program takes input file , whitelist file and signature file names as arguments
   It reads the input file in binary mode and converts it to hex string.
   SHA-1 of the input file is compared against the list of legitimate hashes of programs in whitelist. It found a match file is skipped from 	scanning. 
   Hex string representation is compared to the virus patterns in signature file(stored as list of hex strings) by calling a LKM to do pattern 	  search.
*/


/* Todo - Handling large files 
   Send a signal to daemon process on detecting a virus
*/


struct myargs{
	char * target;
	char * pattern;
	unsigned int tsize;
	unsigned int psize;
};
void binaryToHex(unsigned char *inStr,int size, unsigned char outStr []);
unsigned char * calculate_digest(char * msg1, int len, unsigned char md_value []);




int kmp(char *target, int tsize, char *pattern, int psize);


 long scanner(struct myargs * args, int argslen)
{

	char * target;
	unsigned int tsize;
	char * pattern;
	unsigned int psize;
	



	


	target = args->target;
	pattern = args->pattern;
	tsize = strlen(args->target);
	psize = strlen(args->pattern);
	
	/* printf("%s", target);
	printf("%s", pattern);
	printf("%d", tsize);
	printf("%d", psize); */
	
	int retval = -1;
	retval = kmp(target,tsize,pattern,psize);
	return retval;
}





int *compute_prefix_function(char *pattern, int psize)
{
	int k = -1;
	int i = 1;
	int *pi = malloc(sizeof(int)*psize);
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
			free(pi);
			return i-k;
		}
	}
	free(pi);
	return -1;
}


int main(int argc, char *argv[]) {

	char * input_file_name = argv[0];
	char * signature_file_name = argv[1];
	char * whitelist_file_name = argv[2];
	
	char * file_contents;
	unsigned char * hex_file_contents;
	
	long input_file_size;
	int retval = 0;
	char str[3];
	FILE *input_file = fopen(input_file_name, "rb");
	if(input_file == NULL){
		printf("Input File not found\n");
		return -1;
	}
	fseek(input_file, 0, SEEK_END);
	input_file_size = ftell(input_file);
	rewind(input_file);
	file_contents = malloc(input_file_size * (sizeof(char)));
	hex_file_contents = malloc(input_file_size * (sizeof(char)) * 2);
	
	
	fread(file_contents, sizeof(char), input_file_size, input_file);

	fclose(input_file);

	binaryToHex((unsigned char *)file_contents, input_file_size , hex_file_contents);
	
	
	//Get sha1 hash of input file
	

        unsigned char hex_md_value[SHA_DIGEST_LENGTH * 2 + 1];		
	//printf("SHA_DIGEST_LENGTH = %d",SHA_DIGEST_LENGTH);
	//Compare against whitelist
	unsigned char md_value[SHA_DIGEST_LENGTH];
	calculate_digest((char *)file_contents, input_file_size, md_value);
	char line_buffer[BUFSIZ]; 

	
	
	binaryToHex(md_value, SHA_DIGEST_LENGTH , hex_md_value);

	int found = 0;
	input_file = fopen(whitelist_file_name, "rb");
	
	if(input_file == NULL){
		printf("whitelist File not found\n");
		retval = -2;
		goto end;
	}
	//printf("Hex hash: %s", hex_md_value);
	//Compare sha1 of inputfile with the whitelist
	while (fgets(line_buffer, 1000, input_file)) 
	{ 

		line_buffer[strlen(line_buffer)-1] = '\0';
		

		

		if (strcmp((const char *)line_buffer,(const char *) hex_md_value) == 0){
					found = 1;
					break;		
			} 
		


		
	}
	fclose(input_file);

	if(found) {
		printf("Legitimate program. Skipped from scanning");			
		retval = -3;
		goto end;		
	}
	
	// Read the signature file for virus definitions

	input_file = fopen(signature_file_name, "rb");
	if(input_file == NULL){
		printf("signature file not found\n");
		retval = -4;
		goto end;
	}
	
	while (fgets(line_buffer, sizeof(line_buffer), input_file)) 
	{ 

		int len = strlen(line_buffer);
		line_buffer[len - 2] = '\0';
		struct myargs args;
		args.target = (char *) hex_file_contents;
		args.pattern = line_buffer;
		args.tsize = strlen((const char *) line_buffer);
		args.psize = strlen((const char *) hex_file_contents);
		
		void *dummy = (void *)&args;	
		int i =-1;	
		//i = syscall(__NR_scanner, dummy, sizeof(args));
		i = scanner(dummy,sizeof(args));
		if (i >= 0) {
			printf("Virus Alert !! File: %s is infected",  input_file_name );
			//Todo Check why permissions are getting wrong
			/* char * temp1 = malloc(sizeof(char) * 2 * strlen(input_file_name) + 11);
			temp1 = strcat(temp1,"mv ");
			temp1 = strcat(temp1,input_file_name);
			strcat(temp1," ");
			strcat(temp1, input_file_name);
			strcat(temp1,".virus");	
			char * temp2 = malloc(sizeof(char) * strlen(input_file_name) + 18);
			strcat(temp2,"chmod 000 ");			
			strcat(temp2, input_file_name);
			strcat(temp2, ".virus");
			system(temp1);
			system(temp2); */
			retval = 1;
			
		}	
	}
	fclose(input_file);	

	
end:	str[0] = retval + '0'; 



	input_file = fopen( "/home/utpal/result.txt" , "w+" );
	system("chmod 666 /home/utpal/result.txt");
	fwrite(str,1,1,input_file);
	fclose(input_file);
	return retval;
	

}




void binaryToHex(unsigned char *file_contents, int input_file_size, unsigned char  hex_file_contents []) {
  	char str[3];
	int i = 0;
	int m = 0;

	for(i=0; i < input_file_size; i++){
		
		
		snprintf(str,3,"%02x", file_contents[i]);

		
		hex_file_contents[m++] = str[0];

		hex_file_contents[m++] = str[1];

	}
		hex_file_contents[m] = '\0';		
		
}

 unsigned char * calculate_digest(char * msg1, int len, unsigned char  md_value [] ){

 EVP_MD_CTX *mdctx;
 const EVP_MD *md;


 int md_len;

 OpenSSL_add_all_digests();

 

 md = EVP_get_digestbyname("sha1");

 if(!md) {
        printf("Unknown message digest %s\n", "EVP_sha1");
        exit(1);
 }

 mdctx = EVP_MD_CTX_create();
 EVP_DigestInit_ex(mdctx, md, NULL);
 EVP_DigestUpdate(mdctx, msg1, len);
 
 EVP_DigestFinal_ex(mdctx, (unsigned char *)md_value, (unsigned int *)&md_len);
 EVP_MD_CTX_destroy(mdctx);

 /* printf("Digest is: ");
 for(i = 0; i < md_len; i++)
        printf("%02x", md_value[i]);
 printf("\n"); */

 /* Call this once before exit. */
 EVP_cleanup();
return md_value;
}

void send_signal(){

    int shmid;
    key_t key;
    char *shm, *s;

    /*
     * We'll name our shared memory segment
     * "5678".
     */
    key = 5678;

    /*
     * Create the segment.
     */
    if ((shmid = shmget(key, SHMSZ, IPC_CREAT | 0666)) < 0) {
        perror("shmget");
        exit(1);
    }

    /*
     * Now we attach the segment to our data space.
     */
    if ((shm = shmat(shmid, NULL, 0)) == (char *) -1) {
        perror("shmat");
        exit(1);
    }

    /*
     * Now put some things into the memory for the
     * other process to read.
     */
    s = shm;

    /* for (c = 'a'; c <= 'z'; c++)
        *s++ = c;
    *s = NULL; */

    strcpy(s,"Virus");

}
