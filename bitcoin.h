
#ifndef BITCOIN_H
#define BITCOIN_H

#include "sha256.h"

#define BITCOIN_HEADER_SIZE 80

void sha256_double(const BYTE data[], size_t len, BYTE hash[]);
int bitcoin_mine(BYTE header[BITCOIN_HEADER_SIZE], BYTE target[SHA256_BLOCK_SIZE]);

#endif