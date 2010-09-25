//anatara Arun  Natarajan
#include <unistd.h>
#include <stdio.h>
#include <cuda.h>
#include <cutil.h>
#include <stdlib.h>
#include <sys/time.h>
#include "rta.h"
#include <sstream>
#include <iostream>




#define SHA1CircularShift(bits,word) \
                ((((word) << (bits)) & 0xFFFFFFFF) | \
                ((word) >> (32-(bits))))


typedef struct sha1calc {
     unsigned    temp;              
     unsigned    W[80];         
     unsigned    A, B, C, D, E;
}sha1calc;

__device__  void SHA1Reset(SHA1Context *context)
{
    context->Length_Low             = 0;
    context->Length_High            = 0;
    context->Message_Block_Index    = 0;

    context->Message_Digest[0]      = 0x67452301;
    context->Message_Digest[1]      = 0xEFCDAB89;
    context->Message_Digest[2]      = 0x98BADCFE;
    context->Message_Digest[3]      = 0x10325476;
    context->Message_Digest[4]      = 0xC3D2E1F0;

    context->Computed   = 0;
    context->Corrupted  = 0;
}

__device__  void SHA1ProcessMessageBlock(SHA1Context *context, int tix)
{
    const unsigned K[] =            /* Constants defined in SHA-1   */      
    {
        0x5A827999,
        0x6ED9EBA1,
        0x8F1BBCDC,
        0xCA62C1D6
    };
     int         t;                  /* Loop counter                 */
	__shared__ sha1calc scalc[RECEIVERS];

    /*
     *  Initialize the first 16 words in the array W
     */
    for(t = 0; t < 16; t++)
    {
        scalc[tix].W[t] = ((unsigned) context->Message_Block[t * 4]) << 24;
        scalc[tix].W[t] |= ((unsigned) context->Message_Block[t * 4 + 1]) << 16;
        scalc[tix].W[t] |= ((unsigned) context->Message_Block[t * 4 + 2]) << 8;
        scalc[tix].W[t] |= ((unsigned) context->Message_Block[t * 4 + 3]);
    }

    for(t = 16; t < 80; t++)
    {
       scalc[tix].W[t] = SHA1CircularShift(1,scalc[tix].W[t-3] ^ scalc[tix].W[t-8] ^ scalc[tix].W[t-14] ^ scalc[tix].W[t-16]);
    }

    scalc[tix].A = context->Message_Digest[0];
    scalc[tix].B = context->Message_Digest[1];
    scalc[tix].C = context->Message_Digest[2];
    scalc[tix].D = context->Message_Digest[3];
    scalc[tix].E = context->Message_Digest[4];

    for(t = 0; t < 20; t++)
    {
        scalc[tix].temp =  SHA1CircularShift(5,scalc[tix].A) +
                ((scalc[tix].B & scalc[tix].C) | ((~scalc[tix].B) & scalc[tix].D)) + scalc[tix].E + scalc[tix].W[t] + K[0];
        scalc[tix].temp &= 0xFFFFFFFF;
        scalc[tix].E = scalc[tix].D;
        scalc[tix].D = scalc[tix].C;
        scalc[tix].C = SHA1CircularShift(30,scalc[tix].B);
        scalc[tix].B = scalc[tix].A;
        scalc[tix].A = scalc[tix].temp;
    }

    for(t = 20; t < 40; t++)
    {
        scalc[tix].temp = SHA1CircularShift(5,scalc[tix].A) + (scalc[tix].B ^ scalc[tix].C ^ scalc[tix].D) + scalc[tix].E + scalc[tix].W[t] + K[1];
        scalc[tix].temp &= 0xFFFFFFFF;
        scalc[tix].E = scalc[tix].D;
        scalc[tix].D = scalc[tix].C;
        scalc[tix].C = SHA1CircularShift(30,scalc[tix].B);
        scalc[tix].B = scalc[tix].A;
        scalc[tix].A = scalc[tix].temp;
    }

    for(t = 40; t < 60; t++)
    {
        scalc[tix].temp = SHA1CircularShift(5,scalc[tix].A) +
               ((scalc[tix].B & scalc[tix].C) | (scalc[tix].B & scalc[tix].D) | (scalc[tix].C & scalc[tix].D)) + scalc[tix].E + scalc[tix].W[t] + K[2];
        scalc[tix].temp &= 0xFFFFFFFF;
        scalc[tix].E = scalc[tix].D;
        scalc[tix].D = scalc[tix].C;
        scalc[tix].C = SHA1CircularShift(30,scalc[tix].B);
        scalc[tix].B = scalc[tix].A;
        scalc[tix].A = scalc[tix].temp;
    }

    for(t = 60; t < 80; t++)
    {
        scalc[tix].temp = SHA1CircularShift(5,scalc[tix].A) + (scalc[tix].B ^ scalc[tix].C ^ scalc[tix].D) + scalc[tix].E + scalc[tix].W[t] + K[3];
        scalc[tix].temp &= 0xFFFFFFFF;
        scalc[tix].E = scalc[tix].D;
        scalc[tix].D = scalc[tix].C;
        scalc[tix].C = SHA1CircularShift(30,scalc[tix].B);
        scalc[tix].B = scalc[tix].A;
        scalc[tix].A = scalc[tix].temp;
    }

    context->Message_Digest[0] =
                        (context->Message_Digest[0] + scalc[tix].A) & 0xFFFFFFFF;
    context->Message_Digest[1] =
                        (context->Message_Digest[1] + scalc[tix].B) & 0xFFFFFFFF;
    context->Message_Digest[2] =
                        (context->Message_Digest[2] + scalc[tix].C) & 0xFFFFFFFF;
    context->Message_Digest[3] =
                        (context->Message_Digest[3] + scalc[tix].D) & 0xFFFFFFFF;
    context->Message_Digest[4] =
                        (context->Message_Digest[4] + scalc[tix].E) & 0xFFFFFFFF;

    context->Message_Block_Index = 0;
}

__device__  void SHA1Input(SHA1Context *context, char *message_array, unsigned length, int tix)
{
    if (!length)
    {
        return;
    }

    if (context->Computed || context->Corrupted)
    {
        context->Corrupted = 1;
        return;
    }

    while(length-- && !context->Corrupted)
    {
        context->Message_Block[context->Message_Block_Index++] =
                                                (*message_array & 0xFF);

        context->Length_Low += 8;
        /* Force it to 32 bits */
        context->Length_Low &= 0xFFFFFFFF;
        if (context->Length_Low == 0)
        {
            context->Length_High++;
            /* Force it to 32 bits */
            context->Length_High &= 0xFFFFFFFF;
            if (context->Length_High == 0)
            {
                /* Message is too long */
                context->Corrupted = 1;
            }
        }

        if (context->Message_Block_Index == 64)
        {
            SHA1ProcessMessageBlock(context, tix);
        }

        message_array++;
    }
}

__device__  void SHA1PadMessage(SHA1Context *context, int tix)
{
    /*
     *  Check to see if the current message block is too small to hold
     *  the initial padding bits and length.  If so, we will pad the
     *  block, process it, and then continue padding into a second
     *  block.
     */
    if (context->Message_Block_Index > 55)
    {
        context->Message_Block[context->Message_Block_Index++] = 0x80;
        while(context->Message_Block_Index < 64)
        {
            context->Message_Block[context->Message_Block_Index++] = 0;
        }

        SHA1ProcessMessageBlock(context, tix);

        while(context->Message_Block_Index < 56)
        {
            context->Message_Block[context->Message_Block_Index++] = 0;
        }
    }
    else
    {
        context->Message_Block[context->Message_Block_Index++] = 0x80;
        while(context->Message_Block_Index < 56)
        {
            context->Message_Block[context->Message_Block_Index++] = 0;
        }
    }

    /*
     *  Store the message length as the last 8 octets
     */
    context->Message_Block[56] = (context->Length_High >> 24) & 0xFF;
    context->Message_Block[57] = (context->Length_High >> 16) & 0xFF;
    context->Message_Block[58] = (context->Length_High >> 8) & 0xFF;
    context->Message_Block[59] = (context->Length_High) & 0xFF;
    context->Message_Block[60] = (context->Length_Low >> 24) & 0xFF;
    context->Message_Block[61] = (context->Length_Low >> 16) & 0xFF;
    context->Message_Block[62] = (context->Length_Low >> 8) & 0xFF;
    context->Message_Block[63] = (context->Length_Low) & 0xFF;

    SHA1ProcessMessageBlock(context, tix);
}

__device__  int SHA1Result(SHA1Context *context, int tix)
{

    if (context->Corrupted)
    {
        return 0;
    }

    if (!context->Computed)
    {
        SHA1PadMessage(context, tix);
        context->Computed = 1;
    }

    return 1;
}


__global__ void hmacsetup(char * cu_shared_key_i, char * cu_shared_key_o){
	//return;
	int j,tix=threadIdx.x;
		tix=blockIdx.x*blockDim.x + threadIdx.x;

	if (tix<=RECEIVERS) {	
		for(j=0;j<64;j++) {
			*(((char *)cu_shared_key_i)+(tix*65+j))^= 0x36;
			*(((char *)cu_shared_key_o)+(tix*65+j))^= 0x5c;
		}
	}
	return;
}


__global__ void hmaccompute(char *cu_message, char * cu_shared_key_i, char * cu_shared_key_o, unsigned *md, int size){


	__shared__ SHA1Context sha[RECEIVERS];       
	int tix=threadIdx.x,j;
	tix=blockIdx.x*blockDim.x + threadIdx.x;
	unsigned temp[5];
/*	__shared__ char message[RECEIVERS][FILESIZE];
	
	int i;

	for(i=0; i<FILESIZE; i++) {
			message[tix][i]=cu_message[i];
	}
	*/
			
		SHA1Reset(&sha[tix]);  
		SHA1Input(&sha[tix], (char *)(cu_shared_key_i)+(tix*65), 64, tix);
		SHA1Input(&sha[tix], cu_message,size, tix);
		SHA1Result(&sha[tix], tix);

		for(j=0; j<5; j++) {
			temp[j]=sha[tix].Message_Digest[j];
		}
		SHA1Reset(&sha[tix]);
		SHA1Input(&sha[tix], (char *)(cu_shared_key_o)+(tix*65), 64, tix);
		SHA1Input(&sha[tix], (char *)temp,20, tix);
		SHA1Result(&sha[tix], tix);	

		for(j=0; j<5; j++) {
			*((unsigned *)(md)+((tix*5)+j))=sha[tix].Message_Digest[j];
		}		
		*((unsigned *)(md)+((tix*5)+4))=tix;
	
	//  __syncthreads();
}


long long hmac_sign_gpu(char *message_files[])
{
    FILE *f_key, *fp;                
    int i, times;
	unsigned char message[FILESIZE+1];
	char *cu_message, *cu_shared_key_i, *cu_shared_key_o;
	unsigned *cu_md,*md;
	char  s_val[RECEIVERS][65];
	
	struct timeval s_time,e_time;
	
	// create the cuda timer
	unsigned int timer=0;
	//CUT_SAFE_CALL(cutCreateTimer(&timer));
	
	md=(unsigned *)malloc(4*RECEIVERS*5);
	
	
	f_key=fopen("shared_key","r");
	
	for (i=0;i<RECEIVERS;i++)
	{
		fscanf(f_key,"%s\n",s_val[i]);
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
	printf("\nRunning test on GPU:\n");
	printf("----------------------\n");
	printf("Message Length  : %d bytes\n",FILESIZE);
	printf("No of Messages  : %d \n",NO_OF_MESSAGES);
	printf("No of Receivers : %d \n",RECEIVERS);
	printf("\n");
*/
	cudaMalloc( (void **) &cu_shared_key_i, RECEIVERS*65);	
	cudaMalloc( (void **) &cu_shared_key_o, RECEIVERS*65);	
	cudaMemcpy( (void *) cu_shared_key_i, (void *) s_val, RECEIVERS*65, cudaMemcpyHostToDevice );
	cudaMemcpy( (void *) cu_shared_key_o, (void *) s_val, RECEIVERS*65, cudaMemcpyHostToDevice );

	hmacsetup <<<1,RECEIVERS>>>(cu_shared_key_i, cu_shared_key_o);
	
	cudaMalloc( (void **) &cu_message, FILESIZE);
	cudaMalloc( (void **) &cu_md, (4*RECEIVERS*5));
	
	cudaThreadSynchronize();
	
	gettimeofday(&s_time,NULL);
	//CUT_SAFE_CALL(cutStartTimer(timer));

	for(times=0; times<NO_OF_MESSAGES; times++) {
	
		CUDA_SAFE_CALL(cudaMemcpy( (void *) cu_message, (void *) message, FILESIZE, cudaMemcpyHostToDevice ));

		hmaccompute <<<1,RECEIVERS>>>(cu_message, cu_shared_key_i, cu_shared_key_o, cu_md,FILESIZE);
		
		CUDA_SAFE_CALL(cudaMemcpy( (void *) md, (void *) cu_md, 4*RECEIVERS*5, cudaMemcpyDeviceToHost ));

		cudaThreadSynchronize();

		#ifdef PRINTF
		for(i=0; i<RECEIVERS; i++)
			printf( "%08X %08X %08X %08X %08X\n",md[0+i*5],md[1+i*5],md[ 2 +i *5],md[3 +i*5],md[4+ i *5]);
		printf("\n");
		#endif
		
	}	
	//CUT_SAFE_CALL(cutStopTimer(timer));
	gettimeofday(&e_time,NULL);

	//printf("GPU : Time counted on CPU :  %lld microseconds\n", timeval_diff(NULL,&e_time,&s_time));		
	//printf("GPU : Time counted on GPU :  %.0f microseconds\n",(cutGetTimerValue(timer))*1000);

	cudaFree(cu_md);
	cudaFree(cu_message);

	return timeval_diff(NULL,&e_time,&s_time);
}


long long hmac_sign_cpu_gpu(char *message_files[])
{
    SHA1Context sha;
    FILE *f_key, *fp;                
    int i, times;
	unsigned char message[FILESIZE+1];
	char *cu_message, *cu_shared_key_i, *cu_shared_key_o;
	unsigned *cu_md,*md;
	char  s_val[RECEIVERS][65];
	
	struct timeval s_time,e_time;
	
	// create the cuda timer
	unsigned int timer=0;
	CUT_SAFE_CALL(cutCreateTimer(&timer));
	
	md=(unsigned *)malloc(4*RECEIVERS*5);
	
	
	f_key=fopen("shared_key","r");
	
	for (i=0;i<RECEIVERS;i++)
	{
		fscanf(f_key,"%s\n",s_val[i]);
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


	cudaMalloc( (void **) &cu_shared_key_i, RECEIVERS*65);	
	cudaMalloc( (void **) &cu_shared_key_o, RECEIVERS*65);	
	cudaMemcpy( (void *) cu_shared_key_i, (void *) s_val, RECEIVERS*65, cudaMemcpyHostToDevice );
	cudaMemcpy( (void *) cu_shared_key_o, (void *) s_val, RECEIVERS*65, cudaMemcpyHostToDevice );

	hmacsetup <<<1,RECEIVERS>>>(cu_shared_key_i, cu_shared_key_o);

	cudaMalloc( (void **) &cu_md, (4*RECEIVERS*5));
	cudaThreadSynchronize();
	cudaMalloc( (void **) &cu_message, 20);
	
	gettimeofday(&s_time,NULL);
	CUT_SAFE_CALL(cutStartTimer(timer));

	for(times=0; times<NO_OF_MESSAGES; times++) {

		SHA1Reset_cpu(&sha);
		SHA1Input_cpu(&sha, (char *)message,FILESIZE);
		if (!SHA1Result_cpu(&sha))
		{
			fprintf(stderr,"sha: could not compute message digest for %s\n", message_files[1]);
		}
		else
		{
			for(i=0;i<5;i++) {
				*(((unsigned *)message)+i)=sha.Message_Digest[0];
			}
		}
	
		CUDA_SAFE_CALL(cudaMemcpy( (void *) cu_message, (void *) message, 20, cudaMemcpyHostToDevice ));

		hmaccompute <<<1,RECEIVERS>>>(cu_message, cu_shared_key_i, cu_shared_key_o, cu_md, 20);
		
		CUDA_SAFE_CALL(cudaMemcpy( (void *) md, (void *) cu_md, 4*RECEIVERS*5, cudaMemcpyDeviceToHost ));

		cudaThreadSynchronize();

		#ifdef PRINTF
		for(i=0; i<RECEIVERS; i++)
			printf( "%08X %08X %08X %08X %08X\n",md[0+i*5],md[1+i*5],md[ 2 +i *5],md[3 +i*5],md[4+ i *5]);
		printf("\n");
		#endif
		
	}	
	CUT_SAFE_CALL(cutStopTimer(timer));
	gettimeofday(&e_time,NULL);

	//printf("GPU : Time counted on CPU :  %lld microseconds\n", timeval_diff(NULL,&e_time,&s_time));		
	//printf("GPU : Time counted on GPU :  %.0f microseconds\n",(cutGetTimerValue(timer))*1000);

	cudaFree(cu_md);
	cudaFree(cu_message);

	return timeval_diff(NULL,&e_time,&s_time);
}



__global__ void horse_public_key_compute(char *cu_public, char *cu_private) {

	SHA1Context sha;       
	
	int tix=threadIdx.x,j;
	tix=blockIdx.x*blockDim.x + threadIdx.x;
	
		SHA1Reset(&sha);  
		SHA1Input(&sha, (char *)(cu_private)+(tix*4), 4, tix);
		SHA1Result(&sha, tix);

		for(j=0; j<5; j++) {
			*((unsigned *)(cu_public)+((tix*5)+j))=sha.Message_Digest[j];
		}		
	//	*((unsigned *)(cu_public)+((tix*5)+4))=tix;
	
	//  __syncthreads();*/
}


long long hors_gen_public_key_gpu(){

	int i;
	FILE *f_private, *f_public;
	char buf[20];
	struct timeval s_time,e_time;
	unsigned *private_key;
	unsigned *md;
	char *cu_public, *cu_private;
	
	md=(unsigned *)malloc(4*1024*5);
	private_key=(unsigned *)malloc(4*1024);

	
	f_private=fopen("hors_private_key","r");
	if (f_private == NULL)
	{
		perror("Hors private Key - Error");
		exit(0);
	}

	f_public=fopen("hors_public_key_gpu","w");
	if (f_public == NULL)
	{
		perror("Hors Public Key - Error");
		exit(0);
	}

	gettimeofday(&s_time,NULL);

	cudaMalloc( (void **) &cu_public, (4*1024*5));
	cudaMalloc( (void **) &cu_private, (4*1024));


	fscanf(f_private,"%s\n",buf);
	fprintf(f_public,"%s\n",buf);
	for (i=0;i<1024;i++)
	{
		fscanf(f_private,"%s\n",buf);
		private_key[i]=atol(buf);
		//printf("%ld\n", private_key[i]);
	}
	
	CUDA_SAFE_CALL(cudaMemcpy( (void *) cu_private, (void *) private_key, 1024 * sizeof(unsigned), cudaMemcpyHostToDevice ));

	horse_public_key_compute <<<2,512>>>(cu_public, cu_private);

	CUDA_SAFE_CALL(cudaMemcpy( (void *) md, (void *) cu_public, 4*1024*5, cudaMemcpyDeviceToHost));

	for(i=0; i<1024; i++)
		fprintf( f_public, "%08X%08X%08X%08X%08X\n",md[0+i*5],md[1+i*5],md[ 2 +i *5],md[3 +i*5],md[4+ i *5]);

	gettimeofday(&e_time,NULL);

	fclose(f_private);
	fclose(f_public);
	return timeval_diff(NULL,&e_time,&s_time);
}


__global__ void horse_sign(char *cu_md, char * cu_h_val) {


	int tix=threadIdx.x,j;
	tix=blockIdx.x*blockDim.x + threadIdx.x;

	switch(tix){
		case 0:
			*((int *)(cu_h_val)+tix)=(*(unsigned *)(cu_md)+0 )>>22 & 0x000003FF;
			break;
		case 1:
			*((int *)(cu_h_val)+tix)=(*(unsigned *)(cu_md)+0 )>>12 & 0x000003FF;
			break;
		case 2:
			*((int *)(cu_h_val)+tix)=(*(unsigned *)(cu_md)+0 )>>2 & 0x000003FF;
			break;
		case 3:
			*((int *)(cu_h_val)+tix)=(((*(unsigned *)(cu_md)+0 ) & 0x00000003)<<8) + ((*((unsigned *)(cu_md)+1) )>>24 & 0x000000FF);
			break;
		case 4:
			*((int *)(cu_h_val)+tix)=*((unsigned *)(cu_md)+1 )>>14 & 0x000003FF;
			break;
		case 5:
			*((int *)(cu_h_val)+tix)=*((unsigned *)(cu_md)+1 )>>4 & 0x000003FF;
			break;
		case 6:
			*((int *)(cu_h_val)+tix)=((*((unsigned *)(cu_md)+1)  & 0x0000000F)<<6 )+ (*((unsigned *)(cu_md)+2 )>>26 & 0x0000003F);
			break;
		case 7:
			*((int *)(cu_h_val)+tix)=*((unsigned *)(cu_md)+2 )>>16 & 0x000003FF;
			break;
		case 8:
			*((int *)(cu_h_val)+tix)=*((unsigned *)(cu_md)+2 )>>6 & 0x000003FF;
			break;
		case 9:
			*((int *)(cu_h_val)+tix)=((*((unsigned *)(cu_md)+2)  & 0x0000000F)<<4 )+ (*((unsigned *)(cu_md)+3 )>>28 & 0x0000000F);
			break;
		case 10:
			*((int *)(cu_h_val)+tix)=*((unsigned *)(cu_md)+3 )>>18 & 0x000003FF;
			break;		
		case 11:
			*((int *)(cu_h_val)+tix)=*((unsigned *)(cu_md)+3 )>>8 & 0x000003FF;
			break;
		case 12:
			*((int *)(cu_h_val)+tix)=((*((unsigned *)(cu_md)+3)  & 0x000000FF)<<2 )+ (*((unsigned *)(cu_md)+4 )>>30 & 0x00000003);
			break;
		case 13:
			*((int *)(cu_h_val)+tix)=*((unsigned *)(cu_md)+4 )>>20 & 0x000003FF;
			break;		
		case 14:
			*((int *)(cu_h_val)+tix)=*((unsigned *)(cu_md)+4 )>>10 & 0x000003FF;
			break;
		case 15:
			*((int *)(cu_h_val)+tix)=*((unsigned *)(cu_md)+4 )>>0 & 0x000003FF;
			break;
		default:
			break;
	}
}


long long hors_sign_gpu(char *message_files[]) {

    SHA1Context sha;
    int i, times;
	FILE *fp,*f_key,*f_sign;
	char message[FILESIZE];
	int h_val[16];
	char *cu_md, *cu_h_val;
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

		cudaMalloc( (void **) &cu_md, (4*5));
		cudaMalloc( (void **) &cu_h_val, (16*sizeof(int)));
		CUDA_SAFE_CALL(cudaMemcpy( (void *) cu_md, (void *) sha.Message_Digest, 5 * sizeof(unsigned), cudaMemcpyHostToDevice ));

		horse_sign<<<1,16>>>(cu_md,cu_h_val);

		CUDA_SAFE_CALL(cudaMemcpy( (void *) h_val, (void *) cu_h_val, (16*sizeof(int)), cudaMemcpyDeviceToHost));

		fclose(f_key);
		
	//	f_sign=fopen("hors_signature_gpu","w");
	#ifdef PRINTF
		for(i=0;i<16;i++) {
			printf("%s\n",s_val[h_val[i]-1]);
		//	fprintf(f_sign,"%s\n",s_val[h_val[i]-1]);
		}
	//	fclose(f_sign);
	#endif
	}
	gettimeofday(&e_time,NULL);

	return timeval_diff(NULL,&e_time,&s_time);
}


__global__ void horse_verify(int * cu_result, char * cu_public_val, char * cu_sign, unsigned *cu_md) {

	__shared__ SHA1Context sha[16];

	int tix=threadIdx.x,j;
	tix=blockIdx.x*blockDim.x + threadIdx.x;
	*cu_result=1;
	__syncthreads();
	
	SHA1Reset(&sha[tix]);  
	SHA1Input(&sha[tix], (char *)((unsigned *)(cu_sign)+(tix)), 4, tix);
	SHA1Result(&sha[tix], tix);

//	for(j=0; j<5; j++) {
//			*((unsigned *)(cu_md)+((tix*5)+j))=sha[tix].Message_Digest[j];
//	}	
//	*((unsigned *)(cu_md)+((tix*5)+4))=tix;
//	*((unsigned *)(cu_md)+((tix*5)+3))=*(((unsigned *)cu_sign) + tix);
	if(*((unsigned *)(cu_public_val+(tix*5*4))+0)!=sha[tix].Message_Digest[0]
			|| *((unsigned *)(cu_public_val+(tix*5*4))+1)!=sha[tix].Message_Digest[1]
			|| *((unsigned *)(cu_public_val+(tix*5*4))+2)!=sha[tix].Message_Digest[2]
			|| *((unsigned *)(cu_public_val+(tix*5*4))+3)!=sha[tix].Message_Digest[3]
			|| *((unsigned *)(cu_public_val+(tix*5*4))+4)!=sha[tix].Message_Digest[4]) {
				
		*cu_result=-1;
	}
}


long long hors_verify_gpu(char *message_files[]) {

	std::stringstream ss;
    SHA1Context sha;
    int i,j, result=0, times;
	FILE *fp,*f_key,*f_sign;
	char message[FILESIZE];
	int h_val[16];
	struct timeval s_time,e_time;
	char  s_val[1024][41];
	unsigned public_val[16][5];
	char buf[41];
	unsigned signature[16];
	char *cu_sign, *cu_public_val;
	int *cu_result;
	
	unsigned *cu_md,*md;
	md=(unsigned *)malloc(4*16*5);

	if (!(fp = fopen(message_files[1],"r"))) {
		perror("Error in opening file \n");
		exit(0);
	}
	for(i=0;i<FILESIZE;i++)
	{
		message[i]=fgetc(fp);
	}
	fclose(fp);


	f_key=fopen("hors_public_key_gpu","r");
	fscanf(f_key,"%s\n",s_val[0]);
	for (i=0;i<1024;i++)
	{
		fscanf(f_key,"%s\n",s_val[i]);
	}
	fclose(f_key);


	f_sign=fopen("hors_signature_gpu","r");
	for (i=0;i<16;i++)
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

		for(i=0; i<16; i++) {
			#ifdef PRINTF
			puts(s_val[h_val[i]-1]);
			#endif
			strcpy(buf,s_val[h_val[i]-1]);
			public_val[i][4] = strtoul( buf+32, NULL, 16 ); 
			buf[32]='\0';
			public_val[i][3] = strtoul( buf+24, NULL, 16 ); 
			buf[24]='\0';
			public_val[i][2] = strtoul( buf+16, NULL, 16 ); 
			buf[16]='\0';
			public_val[i][1] = strtoul( buf+8, NULL, 16 ); 
			buf[8]='\0';
			public_val[i][0] = strtoul( buf, NULL, 16 ); 
		}
		
		cudaMalloc( (void **) &cu_md, (4*16*5));

		
		cudaMalloc( (void **) &cu_result, sizeof(int));
		cudaMalloc( (void **) &cu_public_val, 16 * 5 * sizeof(unsigned));
		cudaMalloc( (void **) &cu_sign, sizeof(unsigned)*16);
		CUDA_SAFE_CALL(cudaMemcpy( (void *) cu_sign, (void *) signature, 16 * sizeof(unsigned), cudaMemcpyHostToDevice ));
		CUDA_SAFE_CALL(cudaMemcpy( (void *) cu_public_val, (void *) public_val, 16 * 5 * sizeof(unsigned), cudaMemcpyHostToDevice ));

		horse_verify<<<1,16>>>(cu_result, cu_public_val, cu_sign,cu_md);

		CUDA_SAFE_CALL(cudaMemcpy( (void *) &result, (void *) cu_result, sizeof(int), cudaMemcpyDeviceToHost));
		CUDA_SAFE_CALL(cudaMemcpy( (void *) md, (void *) cu_md, 4*16*5, cudaMemcpyDeviceToHost ));

		#ifdef PRINTF
		printf("\n");
		for(i=0; i<16; i++)
			printf( "%08X %08X %08X %0ld %08X\n",md[0+i*5],md[1+i*5],md[ 2 +i *5],md[3 +i*5],md[4+ i *5]);
		printf("\n");
		#endif
		
		#ifdef PRINTF
		printf("Result %d\n",result);
		#endif
		if(result!=-1)
			printf("Success - ");
		else
			printf("Failed  - ");
	}
	gettimeofday(&e_time,NULL);

	return timeval_diff(NULL,&e_time,&s_time);

}





