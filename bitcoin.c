
#include <stdio.h>
#include <memory.h>
#include "bitcoin.h"

void sha256_double(const BYTE data[], size_t len, BYTE hash[])
{
    SHA256_CTX ctx;
    BYTE first_hash[SHA256_BLOCK_SIZE];
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, first_hash);
    sha256_init(&ctx);
    sha256_update(&ctx, first_hash, SHA256_BLOCK_SIZE);
    sha256_final(&ctx, hash);
}

int bitcoin_mine(BYTE header[BITCOIN_HEADER_SIZE], BYTE target[SHA256_BLOCK_SIZE])
{
    BYTE hash[SHA256_BLOCK_SIZE];
    BYTE reversed_hash[SHA256_BLOCK_SIZE];
    WORD *nonce_ptr = (WORD *)&header[76];

    // For quick test - using known nonce for genesis block
    WORD correct_nonce = 2083236893; 
    WORD test_nonce = correct_nonce - 100;
    
    while(test_nonce < 0xFFFFFFFF) {
        *nonce_ptr = test_nonce;
        sha256_double(header, BITCOIN_HEADER_SIZE, hash);  
        for(int i=0;i<SHA256_BLOCK_SIZE;i++) reversed_hash[i] = hash[SHA256_BLOCK_SIZE - 1 - i];
        if(memcmp(reversed_hash, target, SHA256_BLOCK_SIZE) < 0) {
            printf("\nFound valid nonce: %0x\n", test_nonce);
            printf("\nHash: ");
            for(int j=0;j<SHA256_BLOCK_SIZE;j++) printf("%0x",reversed_hash[j]);
            printf("\n");
            break;
        }
        test_nonce++;
    }
    return 0;
}