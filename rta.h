

#define RECEIVERS 35
#define NO_OF_MESSAGES 1
#define FILESIZE 1024
//#define PRINTF 1

typedef struct SHA1Context
{
    unsigned Message_Digest[5]; /* Message Digest (output)          */

    unsigned Length_Low;        /* Message length in bits           */
    unsigned Length_High;       /* Message length in bits           */

    unsigned char Message_Block[64]; /* 512-bit message blocks      */
    int Message_Block_Index;    /* Index into message block array   */

    int Computed;               /* Is the digest computed?          */
    int Corrupted;              /* Is the message digest corruped?  */
    
	//sha1calc scalc;
    
    
} SHA1Context;


long long timeval_diff(struct timeval *difference, struct timeval *end_time, struct timeval *start_time);

void SHA1Reset_cpu(SHA1Context *context);
void SHA1Input_cpu(SHA1Context *context, char *message_array, unsigned length);
int SHA1Result_cpu(SHA1Context *context);



