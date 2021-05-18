#include <cstdio>
#include <iostream>
#include <random>
#include <chrono>
#include <fstream>
#include <cuda.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>



 
/*************************** HEADER FILES ***************************/
#include <stdlib.h>
#include <memory.h>


//#define USE_SHA1 1


//#define CUDA_HASH 1
//#define OCL_HASH 0

typedef unsigned char BYTE;
typedef unsigned int  WORD;
typedef unsigned long long LONG;



////////////////////////////////////////////////////////////////////////////
//I decided not to implement SHA1 from scratch, but borrowed from //////////
//Scroll down to find where the beginning of my code is marked//////////////
////////////////////////////////////////////////////////////////////////////
//#define SHA1_BLOCK_SIZE 20              // SHA1 outputs a 20 byte digest


typedef struct {
	BYTE data[64];
	WORD datalen;
	unsigned long long bitlen;
	WORD state[5];
	WORD k[4];
} CUDA_SHA1_CTX;


#ifndef ROTLEFT
#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#endif


__device__  __forceinline__ void cuda_sha1_transform(CUDA_SHA1_CTX *ctx, const BYTE data[])
{
	WORD a, b, c, d, e, i, j, t, m[80];

	for (i = 0, j = 0; i < 16; ++i, j += 4)
		m[i] = (data[j] << 24) + (data[j + 1] << 16) + (data[j + 2] << 8) + (data[j + 3]);
	for ( ; i < 80; ++i) {
		m[i] = (m[i - 3] ^ m[i - 8] ^ m[i - 14] ^ m[i - 16]);
		m[i] = (m[i] << 1) | (m[i] >> 31);
	}

	a = ctx->state[0];
	b = ctx->state[1];
	c = ctx->state[2];
	d = ctx->state[3];
	e = ctx->state[4];

	for (i = 0; i < 20; ++i) {
		t = ROTLEFT(a, 5) + ((b & c) ^ (~b & d)) + e + ctx->k[0] + m[i];
		e = d;
		d = c;
		c = ROTLEFT(b, 30);
		b = a;
		a = t;
	}
	for ( ; i < 40; ++i) {
		t = ROTLEFT(a, 5) + (b ^ c ^ d) + e + ctx->k[1] + m[i];
		e = d;
		d = c;
		c = ROTLEFT(b, 30);
		b = a;
		a = t;
	}
	for ( ; i < 60; ++i) {
		t = ROTLEFT(a, 5) + ((b & c) ^ (b & d) ^ (c & d))  + e + ctx->k[2] + m[i];
		e = d;
		d = c;
		c = ROTLEFT(b, 30);
		b = a;
		a = t;
	}
	for ( ; i < 80; ++i) {
		t = ROTLEFT(a, 5) + (b ^ c ^ d) + e + ctx->k[3] + m[i];
		e = d;
		d = c;
		c = ROTLEFT(b, 30);
		b = a;
		a = t;
	}

	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
}

__device__ void cuda_sha1_init(CUDA_SHA1_CTX *ctx)
{
	ctx->datalen = 0;
	ctx->bitlen = 0;
	ctx->state[0] = 0x67452301;
	ctx->state[1] = 0xEFCDAB89;
	ctx->state[2] = 0x98BADCFE;
	ctx->state[3] = 0x10325476;
	ctx->state[4] = 0xc3d2e1f0;
	ctx->k[0] = 0x5a827999;
	ctx->k[1] = 0x6ed9eba1;
	ctx->k[2] = 0x8f1bbcdc;
	ctx->k[3] = 0xca62c1d6;
}

__device__ void cuda_sha1_update(CUDA_SHA1_CTX *ctx, const BYTE data[], size_t len)
{
	size_t i;

	for (i = 0; i < len; ++i) {
		ctx->data[ctx->datalen] = data[i];
		ctx->datalen++;
		if (ctx->datalen == 64) {
			cuda_sha1_transform(ctx, ctx->data);
			ctx->bitlen += 512;
			ctx->datalen = 0;
		}
	}
}

__device__ void cuda_sha1_final(CUDA_SHA1_CTX *ctx, BYTE hash[])
{
	WORD i;

	i = ctx->datalen;

	// Pad whatever data is left in the buffer.
	if (ctx->datalen < 56) {
		ctx->data[i++] = 0x80;
		while (i < 56)
			ctx->data[i++] = 0x00;
	}
	else {
		ctx->data[i++] = 0x80;
		while (i < 64)
			ctx->data[i++] = 0x00;
		cuda_sha1_transform(ctx, ctx->data);
		memset(ctx->data, 0, 56);
	}

	ctx->bitlen += ctx->datalen * 8;
	ctx->data[63] = ctx->bitlen;
	ctx->data[62] = ctx->bitlen >> 8;
	ctx->data[61] = ctx->bitlen >> 16;
	ctx->data[60] = ctx->bitlen >> 24;
	ctx->data[59] = ctx->bitlen >> 32;
	ctx->data[58] = ctx->bitlen >> 40;
	ctx->data[57] = ctx->bitlen >> 48;
	ctx->data[56] = ctx->bitlen >> 56;
	cuda_sha1_transform(ctx, ctx->data);

	for (i = 0; i < 4; ++i) {
		hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
	}
}

__device__ void kernel_sha1_hash(BYTE* indata, WORD inlen, BYTE* outdata)
{

	BYTE* in = indata;
	BYTE* out = outdata;
	CUDA_SHA1_CTX ctx;
	cuda_sha1_init(&ctx);
	cuda_sha1_update(&ctx, in, inlen);
	cuda_sha1_final(&ctx, out);

}




//////////////////////////////////////////////////////////////////////////////////////
//THE REST IS MY CODE//
//////////////////////////////////////////////////////////////////////////////////////


__device__ void HMAC_SHA1(unsigned char *message, unsigned int message_length, unsigned char *K, unsigned int K_len, unsigned char *out){
	
	unsigned char whole[84]; //right_side is 120bit/20 byte and opad is 64 bytes
	unsigned char *right_side = (unsigned char*)malloc(64+message_length);
	
	for(int i=0; i<64; i++){
	
		if(i<K_len){
			//ipad[i] = K[i]^0x36;
			right_side[i]=K[i]^0x36;
			whole[i] = K[i]^0x5c;
		}
		else{
			right_side[i]=0x36;
			whole[i] = 0x5c;
		}
	}
	
	memcpy(right_side+64,message,message_length);
	kernel_sha1_hash(right_side, 64+message_length, whole+64);
	free(right_side);
	kernel_sha1_hash(whole, 84, out);


}

__device__ void PBKDF2(unsigned char *password, unsigned int password_len, unsigned char *SSID, unsigned int SSID_len, unsigned int iters, unsigned int key_len, unsigned char *out){

	
	unsigned char *T_chain = (unsigned char *)malloc(((key_len+160-1)/160)*20);
	memset(T_chain, 0, ((key_len+160-1)/160)*20);
	for(unsigned int i=0; i<(key_len+160-1)/160; i++){
		unsigned char U_prime[20];
		for(unsigned int c=0; c<iters; c++){
			if(c==0){
				unsigned char *SSID_2 = (unsigned char *)malloc(SSID_len + 4);
				memcpy(SSID_2,SSID,SSID_len);

				SSID_2[SSID_len] = ((i+1) >> 24) & 0xFF;
				SSID_2[SSID_len+1] = ((i+1) >> 16) & 0xFF;
				SSID_2[SSID_len+2] = ((i+1) >> 8) & 0xFF;
				SSID_2[SSID_len+3] = (i+1) & 0xFF;

				HMAC_SHA1(SSID_2, SSID_len+4, password, password_len, U_prime);
				free(SSID_2);
			}
			else{
				HMAC_SHA1(U_prime, 20, password, password_len, U_prime);
			}
			for(unsigned int bytes=0; bytes<20; bytes++){
				T_chain[i*20 + bytes] = T_chain[i*20+bytes]^ U_prime[bytes];
			}
		}

	}
	memcpy(out, T_chain, key_len/8);
	free(T_chain);


}


__device__ bool eq_checker(unsigned char *str1, unsigned char *str2, unsigned int str_len){
	for(unsigned int i=0; i<str_len; i++){
		if(str1[i]!=str2[i]){
			return false;	
		}
	}
	return true;
}


__device__ bool PMKID(unsigned char *password, unsigned int password_len, unsigned int SSID_len, unsigned char *PMK_info){
	unsigned char PMK[32];
	
	PBKDF2(password, password_len, PMK_info+20+16, SSID_len, 4096, 256, PMK);
	HMAC_SHA1(PMK_info,20,PMK,32,PMK);
	return eq_checker(PMK,PMK_info+20,16);

	
}

__global__ void El1t3Hax0r(unsigned char *true_PMKID, unsigned char *password, unsigned int password_len, unsigned int buff_pop, unsigned char *SSID, unsigned int SSID_len, unsigned char *PMK_info, unsigned char *out, bool *found){
	int tid = threadIdx.x;
	int bid = blockIdx.x;
	int tpb = blockDim.x;
	int global_tid = tpb*bid+tid;
	extern __shared__ unsigned char shPMK_info[];

	if(tid == 0){	
		memcpy(shPMK_info,PMK_info,20);
	}
	if(tid==1){
		memcpy(shPMK_info+20,true_PMKID,16);
	}
	if(tid==2){
		memcpy(shPMK_info+20+16,SSID,SSID_len);
	}
	__syncthreads();

	

	if(global_tid<(buff_pop/(password_len+1))){
		unsigned char local_password[8];
		memcpy(local_password, password+(global_tid*(password_len+1)),8);

		if(PMKID(local_password, password_len, SSID_len, shPMK_info)){
			memcpy(out,local_password,password_len);	
			*found = true;
		}
	}
}



int main(int argc, char *argv[]){
	//cudaThreadSetLimit(cudaLimitMallocHeapSize, 128*1024*1024);
	cudaEvent_t start;
	cudaEvent_t stop;
	cudaEventCreate(&start);
	cudaEventCreate(&stop);

	unsigned int threads_per_block = std::stoi(argv[1]); //read in threads per block
	char *password_file = argv[2]; // read in name of password file, either generated_big.txt or generated_small.txt
	size_t buff_size = std::stoi(argv[3]); //how much of the file to read in at once in bytes

	unsigned char out[8] = {'\0'};
	unsigned char PMKID[] = {0x1a, 0x24, 0x31, 0x51, 0x78, 0x04, 0x69, 0x53, 0xda, 0xfe, 0xd3, 0xd6, 0xe6, 0x29, 0x5b, 0xb7};
	unsigned char SSID[] = "The Roost2.4GHz";
	unsigned int SSID_len = strlen((char *)SSID);
	unsigned char AP_MAC[] = {0x36, 0x96, 0x01, 0x44, 0x4d, 0xe9};
	unsigned char S_MAC[] = {0x9c, 0x4e, 0x36, 0xb5, 0x43, 0xf8};

	unsigned char PMK_info[20];
	unsigned char PMK_name[] = "PMK Name";
		
	memcpy(PMK_info,PMK_name,8);
	memcpy(PMK_info+8, AP_MAC, 6);
	memcpy(PMK_info+14, S_MAC, 6);
	
	bool *found, *dFound;
	cudaHostAlloc(&found,sizeof(bool),cudaHostAllocDefault);
	cudaMalloc((bool **)&dFound,sizeof(bool));
	*found = false;
	cudaMemcpy(dFound,found,sizeof(bool), cudaMemcpyHostToDevice);

	//reading in file in chunks
	//char *buff = new char[buff_size];
	char *buff;
	cudaMallocHost((void**)&buff, buff_size);
	std::ifstream fin(password_file);
	
	unsigned char *dTrue_PMKID,*dSSID,*dPMK_info, *dOut;
	cudaMalloc((unsigned char**)&dTrue_PMKID, 16);
	cudaMalloc((unsigned char**)&dSSID, sizeof(unsigned char)*SSID_len);
	//cudaMalloc((unsigned char**)&dS_MAC, sizeof(unsigned char)*6);
	//cudaMalloc((unsigned char**)&dAP_MAC, sizeof(unsigned char)*6);
	cudaMalloc((unsigned char**)&dPMK_info, sizeof(unsigned char)*20);
	cudaMalloc((unsigned char**)&dOut, sizeof(unsigned char)*9);

	unsigned char *dPassword;
	cudaMalloc((unsigned char**)&dPassword,buff_size);

	cudaMemcpy(dTrue_PMKID,PMKID,16,cudaMemcpyHostToDevice);
	cudaMemcpy(dPassword,buff,buff_size,cudaMemcpyHostToDevice);
	cudaMemcpy(dSSID,SSID,sizeof(unsigned char)*SSID_len,cudaMemcpyHostToDevice);
	//cudaMemcpy(dS_MAC,S_MAC,sizeof(unsigned char)*6,cudaMemcpyHostToDevice);
	//cudaMemcpy(dAP_MAC,AP_MAC,sizeof(unsigned char)*6,cudaMemcpyHostToDevice);
	cudaMemcpy(dPMK_info,PMK_info,sizeof(unsigned char)*20,cudaMemcpyHostToDevice);
	
	float ms=0;
	while(fin){
		// Try to read next chunk of data
		fin.read(buff, buff_size);

		// Get the number of bytes actually read
		size_t count = fin.gcount();
		// If nothing has been read, break
		if (count<9) //not a full password so we break 
			break;
		//Do what you need with the buffer
		//Here we need to call the function to generate PMKIDs against each password in buff

		cudaMemcpy(dPassword,buff,count,cudaMemcpyHostToDevice);

		cudaEventRecord(start);
		El1t3Hax0r<<<((count/9)+threads_per_block-1)/threads_per_block,threads_per_block, (20+16+SSID_len)*sizeof(unsigned char)>>>(dTrue_PMKID,dPassword,8,count,dSSID,SSID_len,dPMK_info,dOut,dFound);
		cudaDeviceSynchronize();
		cudaEventRecord(stop);        
		cudaEventSynchronize(stop);
		float ms_temp;
		cudaEventElapsedTime(&ms_temp,start,stop);
		ms += ms_temp;
		
		cudaMemcpy(found,dFound,sizeof(bool), cudaMemcpyDeviceToHost);
		if(*found){
			cudaMemcpy(out,dOut,8,cudaMemcpyDeviceToHost);
			break;
		}
	}

	cudaFree(dTrue_PMKID);		
	cudaFree(dPassword);
	cudaFree(dSSID);
	//cudaFree(dS_MAC);
	//cudaFree(dAP_MAC);
	cudaFree(dPMK_info);
	cudaFree(dOut);
	cudaFree(dFound);
	cudaFree(buff);

	printf("The password is: ");
	for(int i=0; i<8; i++){
		printf("%c", out[i]);
	}
	printf("\n");
	printf("Total time taken on GPU: %f\n", ms);

	return 0;
}
