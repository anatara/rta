//anatara Arun  Natarajan

#include <stdio.h>
#include "rta.h"
#include <stdlib.h>
#include <sys/time.h>
#include <string.h>




long long hors_gen_public_key_cpu(){

	SHA1Context sha;
	int i,j;
	FILE *f_private, *f_public;
	char buf[20];
	struct timeval s_time,e_time;
	unsigned temp;

	f_private=fopen("hors_private_key","r");
	if (f_private == NULL)
	{
		perror("Hors private Key - Error");
		exit(0);
	}

	f_public=fopen("hors_public_key_cpu","w");
	if (f_public == NULL)
	{
		perror("Hors Public Key - Error");
		exit(0);
	}

	gettimeofday(&s_time,NULL);
	
	fscanf(f_private,"%s\n",buf);
	fprintf(f_public,"%s\n",buf);


	for (i=0;i<1024;i++)
	{
		fscanf(f_private,"%s\n",buf);
		temp=atol(buf);
		SHA1Reset_cpu(&sha);
		SHA1Input_cpu(&sha, (char *) &temp, 4);

		if (!SHA1Result_cpu(&sha))
		{
			fprintf(stderr, "ERROR-- could not compute message digest\n");
		}
		else
		{
		  for(j = 0; j < 5 ; j++)
			{
				fprintf(f_public,"%08X", sha.Message_Digest[j]);
			}
		  fprintf(f_public,"\n");
		}
	}	
	gettimeofday(&e_time,NULL);

	fclose(f_private);
	fclose(f_public);
	return timeval_diff(NULL,&e_time,&s_time);
}


long long hors_sign_cpu(char *message_files[]) {

    SHA1Context sha;
    int i, times;
	FILE *fp,*f_key,*f_sign;
	char message[FILESIZE];
	int h_val[16];
	struct timeval s_time,e_time;

	if (!(fp = fopen(message_files[1],"r"))) {
		perror("Error in opening file \n");
		exit(0);
	}

	for(i=0;i<FILESIZE;i++)
	{
		message[i]=fgetc(fp);
	}
	fclose(fp);

	char  s_val[1024][11];
	f_key=fopen("hors_private_key","r");
	
	fscanf(f_key,"%s\n",s_val[0]);
	for (i=0;i<1024;i++)
	{
		fscanf(f_key,"%s\n",s_val[i]);
	}
//	printf("\nSignature is : \n");
	fclose(f_key);


	gettimeofday(&s_time,NULL);

	for(times=0; times<NO_OF_MESSAGES; times++) {
		SHA1Reset_cpu(&sha);

		SHA1Input_cpu(&sha, (char *)message,FILESIZE);
		
		if (!SHA1Result_cpu(&sha))
		{
			fprintf(stderr, "ERROR-- could not compute message digest\n");
			exit(0);
		}

		#ifdef PRINTF
		int j;
		printf("SHA1 of '%s' = ",message_files[1]);
		for(j = 0; j < 5 ; j++)
		{
			printf("%08X ",sha.Message_Digest[j]);
		}
		printf("\n");
		#endif

		h_val[0]= (sha.Message_Digest[0]>>22) & 0x000003FF;
		h_val[1]= (sha.Message_Digest[0]>>12) & 0x000003FF;
		h_val[2]= (sha.Message_Digest[0]>>2) & 0x000003FF;
		h_val[3]= (((sha.Message_Digest[0]) & 0x00000003) << 8)+ ((sha.Message_Digest[1]>>24) & 0x000000FF );
		h_val[4]= (sha.Message_Digest[1]>>14) & 0x000003FF;
		h_val[5]= (sha.Message_Digest[1]>>4) & 0x000003FF;
		h_val[6]= (((sha.Message_Digest[1]) & 0x0000000F) << 6)+ ((sha.Message_Digest[2]>>26) & 0x0000003F );
		h_val[7]= (sha.Message_Digest[2]>>16) & 0x000003FF;
		h_val[8]= (sha.Message_Digest[2]>>6) & 0x000003FF;
		h_val[9]= (((sha.Message_Digest[2]) & 0x0000003F) << 4)+ ((sha.Message_Digest[3]>>28) & 0x0000000F );
		h_val[10]= (sha.Message_Digest[3]>>18) & 0x000003FF;
		h_val[11]= (sha.Message_Digest[3]>>8) & 0x000003FF;
		h_val[12]= (((sha.Message_Digest[3]) & 0x000000FF) << 2)+ ((sha.Message_Digest[4]>>30) & 0x00000003 );
		h_val[13]= (sha.Message_Digest[4]>>20) & 0x000003FF;
		h_val[14]= (sha.Message_Digest[4]>>10) & 0x000003FF;
		h_val[15]= (sha.Message_Digest[4]) & 0x000003FF;
		
		//f_sign=fopen("hors_signature_cpu","w");
	#ifdef PRINTF
		for(i=0;i<16;i++) {
			printf("%s\n",s_val[h_val[i]-1]);
			//fprintf(f_sign,"%s\n",s_val[h_val[i]-1]);
		}
		//fclose(f_sign);
	#endif
	}
	gettimeofday(&e_time,NULL);

	return timeval_diff(NULL,&e_time,&s_time);
}



long long hors_verify_cpu(char *message_files[]) {

    SHA1Context sha;
    unsigned temp;
    int i,j, result=0, times;
	FILE *fp,*f_key,*f_sign;
	char message[FILESIZE];
	int h_val[16];
	struct timeval s_time,e_time;
	char  s_val[1024][41];
	char buf[41];
	unsigned signature[16];

	if (!(fp = fopen(message_files[1],"r"))) {
		perror("Error in opening file \n");
		exit(0);
	}
	for(i=0;i<FILESIZE;i++)
	{
		message[i]=fgetc(fp);
	}
	fclose(fp);


	f_key=fopen("hors_public_key_cpu","r");
	fscanf(f_key,"%s\n",s_val[0]);
	for (i=0;i<1024;i++)
	{
		fscanf(f_key,"%s\n",s_val[i]);
	}
	fclose(f_key);

	f_sign=fopen("hors_signature_cpu","r");
	for(i=0; i<16; i++)
	{
		fscanf(f_sign,"%s\n",buf);
		signature[i]=atol(buf);
	}
	fclose(f_sign);

	gettimeofday(&s_time,NULL);
	
	for(times=0; times<NO_OF_MESSAGES; times++) {
		
		SHA1Reset_cpu(&sha);
		SHA1Input_cpu(&sha, (char *)message,FILESIZE);

		if (!SHA1Result_cpu(&sha))
		{
			fprintf(stderr, "ERROR-- could not compute message digest\n");
			exit(0);
		}
		
		#ifdef PRINTF
		printf("SHA1 of '%s' = ",message_files[1]);
		for(j = 0; j < 5 ; j++)
		{
				printf("%08X ",sha.Message_Digest[j]);
		}
		printf("\n");
		#endif

		h_val[0] = (sha.Message_Digest[0]>>22) & 0x000003FF;
		h_val[1] = (sha.Message_Digest[0]>>12) & 0x000003FF;
		h_val[2] = (sha.Message_Digest[0]>>2) & 0x000003FF;
		h_val[3] = (((sha.Message_Digest[0]) & 0x00000003) << 8)+ ((sha.Message_Digest[1]>>24) & 0x000000FF );
		h_val[4] = (sha.Message_Digest[1]>>14) & 0x000003FF;
		h_val[5] = (sha.Message_Digest[1]>>4) & 0x000003FF;
		h_val[6] = (((sha.Message_Digest[1]) & 0x0000000F) << 6)+ ((sha.Message_Digest[2]>>26) & 0x0000003F );
		h_val[7] = (sha.Message_Digest[2]>>16) & 0x000003FF;
		h_val[8] = (sha.Message_Digest[2]>>6) & 0x000003FF;
		h_val[9] = (((sha.Message_Digest[2]) & 0x0000003F) << 4)+ ((sha.Message_Digest[3]>>28) & 0x0000000F );
		h_val[10]= (sha.Message_Digest[3]>>18) & 0x000003FF;
		h_val[11]= (sha.Message_Digest[3]>>8) & 0x000003FF;
		h_val[12]= (((sha.Message_Digest[3]) & 0x000000FF) << 2)+ ((sha.Message_Digest[4]>>30) & 0x00000003 );
		h_val[13]= (sha.Message_Digest[4]>>20) & 0x000003FF;
		h_val[14]= (sha.Message_Digest[4]>>10) & 0x000003FF;
		h_val[15]= (sha.Message_Digest[4]) & 0x000003FF;

		
		result=1;
		for (i=0;i<16;i++)
		{

			SHA1Reset_cpu(&sha);
			SHA1Input_cpu(&sha, (char *) &signature[i], 4);
			#ifdef PRINTF
			printf("%s\n",s_val[h_val[i]-1]);
			#endif
			//printf("%s, %ld, haval:%d\n",buf,temp, h_val[i]);
			//printf("%d over result %d\n",i, strcmp(buf,s_val[h_val[i]-1]));
			if (!SHA1Result_cpu(&sha))
			{
				fprintf(stderr, "ERROR-- could not compute message digest\n");
			}
			else
			{
				for(j = 0; j < 5 ; j++)
				{
					sprintf(buf+j*8,"%08X", sha.Message_Digest[j]);
				}
				if(strcmp(buf,s_val[h_val[i]-1])!=0){
					result=0;
					break;
				}
			}

		}
		
		if(result==0)
			printf("Failed  - ");
		else
			printf("Success - ");
	}
	gettimeofday(&e_time,NULL);

	return timeval_diff(NULL,&e_time,&s_time);

}
