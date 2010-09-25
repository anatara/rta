//anatara Arun  Natarajan

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include "rta.h"

long long hmac_sign_gpu(char *message_files[]);
long long hmac_sign_cpu_gpu(char *message_files[]);
long long hmac_sign_cpu(char *message_files[]);
long long hors_gen_public_key_cpu();
long long hors_gen_public_key_gpu();
long long hors_sign_cpu(char *message_files[]);
long long hors_sign_gpu(char *message_files[]);
long long hors_verify_gpu(char *message_files[]);
long long hors_verify_cpu(char *message_files[]);


long long timeval_diff(struct timeval *difference, struct timeval *end_time, struct timeval *start_time)
{
  struct timeval temp_diff;

  if(difference==NULL)
  {
    difference=&temp_diff;
  }

  difference->tv_sec =end_time->tv_sec -start_time->tv_sec ;
  difference->tv_usec=end_time->tv_usec-start_time->tv_usec;

  /* Using while instead of if below makes the code slightly more robust. */

  while(difference->tv_usec<0)
  {
    difference->tv_usec+=1000000;
    difference->tv_sec -=1;
  }

  return 1000000LL*difference->tv_sec+
                   difference->tv_usec;

} /* timeval_diff() */



int main(int argc, char *argv[])
{
	
	printf("\nTest Parameters:\n");
	printf("-----------------\n");
	printf("Message Length  : %d bytes\n",FILESIZE);
	printf("No of Messages  : %d \n",NO_OF_MESSAGES);
	printf("No of Receivers : %d \n",RECEIVERS);

	printf("\n");
	
	printf("HMAC\n");
	printf("----\n");
	printf("MAC Genratation\n");
	printf("    Time Taken on CPU : %lld microsec\n",hmac_sign_cpu(argv));
	printf("    Time Taken on GPU : %lld microsec\n",hmac_sign_gpu(argv));
	printf("Time Taken on CPU-GPU : %lld microsec ",hmac_sign_cpu_gpu(argv));
	printf("-- Message hashed once on CPU and HMAC performed on the Hash on GPU\n\n");	

	printf("HORS\n");
	printf("----\n");
//	printf("Generation of public Key\n");
//	printf("Time Taken on CPU : %lld microsec\n",hors_gen_public_key_cpu());
//	printf("Time Taken on GPU : %lld microsec\n",hors_gen_public_key_gpu());
	
	printf("\n");
	printf("Signing\n");
	printf("Time Taken on CPU : %lld microsec\n",hors_sign_cpu(argv));
	printf("Time Taken on GPU : %lld microsec -- This is just one Hash Operation, Better do it on CPU\n",hors_sign_gpu(argv));
	
	printf("\n");
	printf("Verification\n");
	printf("Time Taken on CPU : %lld microsec\n",hors_verify_cpu(argv));
	printf("Time Taken on GPU : %lld microsec\n",hors_verify_gpu(argv));
	printf("\n");

	return 1;
}
