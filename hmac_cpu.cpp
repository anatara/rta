//anatara Arun  Natarajan

#include <stdio.h>
#include "rta.h"
#include <stdlib.h>
#include <sys/time.h>
#include <string.h>



long long hmac_sign_cpu(char *message_files[])
{
    SHA1Context sha, sha2;         
    FILE       *f_key,*fp;                
    int i,j,fd, times;
	unsigned char message[FILESIZE+1];
	char opad[65],ipad[65];
	char  s_val[RECEIVERS][65];

	unsigned * md=(unsigned *)malloc(4*RECEIVERS*5);

	struct timeval s_time,e_time;
  
   	
	f_key=fopen("shared_key","r");
	
	fd=fileno(f_key);

	for (i=0;i<RECEIVERS;i++)
	{
		fscanf(f_key,"%s\n",s_val[i]);
		//read(fd,s_val[i],64);
	}
	fclose(f_key);

	if (!(fp = fopen(message_files[1],"r"))) {
		perror("Error in opening file \n");
		exit(0);
	}
	for(i=0;i<FILESIZE;i++)
	{
		message[i]=fgetc(fp);
	}
	fclose(fp);
/*
	printf("\nRunning test on CPU:\n");
	printf("----------------------\n");
	printf("Message Length  : %d bytes\n",FILESIZE);
	printf("No of Messages  : %d \n",NO_OF_MESSAGES);
	printf("No of Receivers : %d \n",RECEIVERS);
	printf("\n");
*/
	gettimeofday(&s_time,NULL);

	for(times=0; times<NO_OF_MESSAGES; times++) {
	
		for(i=0; i<RECEIVERS; i++) {	
			
			for(j=0;j<64;j++) {
				ipad[j]=s_val[i][j]^0x36;
				opad[j]=s_val[i][j]^0x5c;

			}
			
			SHA1Reset_cpu(&sha);
			SHA1Input_cpu(&sha, (char *)ipad, 64);
			SHA1Input_cpu(&sha, (char *)message,FILESIZE);
			if (!SHA1Result_cpu(&sha))
			{
				fprintf(stderr,"sha: could not compute message digest for %s\n", message_files[1]);
			}
			else
			{
				SHA1Reset_cpu(&sha2);
				SHA1Input_cpu(&sha2, (char *)opad, 64);
				SHA1Input_cpu(&sha2, (char *)sha.Message_Digest,20);
				
			if (!SHA1Result_cpu(&sha2))
			{
				fprintf(stderr,"sha: could not compute message digest for %s\n", message_files[1]);
			}

				md[i]=sha2.Message_Digest[0];
				md[i + 1* RECEIVERS]=sha2.Message_Digest[1];
				md[i + 2* RECEIVERS]=sha2.Message_Digest[2];
				md[i + 3* RECEIVERS]=sha2.Message_Digest[3];		
				md[i + 4* RECEIVERS]=sha2.Message_Digest[4];		
				md[i + 4* RECEIVERS]=i;
				#ifdef PRINTF
				printf( "%08X %08X %08X %08X %08X %d\n",sha2.Message_Digest[0],sha2.Message_Digest[1],sha2.Message_Digest[2],sha2.Message_Digest[3],sha2.Message_Digest[4],i);
				#endif
			}
		}
		#ifdef PRINTF
		printf("\n");
		#endif 
	}
	
	gettimeofday(&e_time,NULL);

    //printf("Time taken : %ld microsec and %d sec\n", ((e_time.tv_usec)-(s_time.tv_usec)), ((e_time.tv_sec)-(s_time.tv_sec)));

	//printf("Time taken on CPU :  %lld microseconds\n", timeval_diff(NULL,&e_time,&s_time));		
	
	return timeval_diff(NULL,&e_time,&s_time);
	
}

