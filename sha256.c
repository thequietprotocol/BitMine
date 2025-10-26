#include <stdio.h>
#include <memory.h>
#include "sha256.h"

void sha256_init(SHA256_CTX *ctx)
{
    ctx -> datalen = 0;
    ctx -> bitlen = 0;
    ctx -> H[0] = H0[0];
    ctx -> H[1] = H0[1];
    ctx -> H[2] = H0[2];
    ctx -> H[3] = H0[3];
    ctx -> H[4] = H0[4];
    ctx -> H[5] = H0[5];
    ctx -> H[6] = H0[6];
    ctx -> H[7] = H0[7];
}

void sha256_transform(SHA256_CTX *ctx, BYTE data[])
{
    WORD a,b,c,d,e,f,g,h;
    WORD T1,T2;
    WORD W[64];
    WORD t,j;
    // Message Schedule
    // Remember x86 is little endian and SHA256 is big endian
    for(t=0, j=0; t<16; t++, j += 4)
        W[t] = (data[j] << 24) | (data[j+1] << 16) | (data[j+2] << 8) | (data[j+3]);
    for(; t<64; t++)
        W[t] = SIG1(W[t-2]) + W[t-7] + SIG0(W[t-15]) + W[t-16];
    
    a = ctx -> H[0];
    b = ctx -> H[1];
    c = ctx -> H[2];
    d = ctx -> H[3];
    e = ctx -> H[4];
    f = ctx -> H[5];
    g = ctx -> H[6];
    h = ctx -> H[7];

    for(t=0; t<64; t++) {
        T1 = h + EP1(e) + CH(e,f,g) + K[t] + W[t];
        T2 = EP0(a) + MAJ(a,b,c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }

    ctx -> H[0] += a;
    ctx -> H[1] += b;
    ctx -> H[2] += c;
    ctx -> H[3] += d;
    ctx -> H[4] += e;
    ctx -> H[5] += f;
    ctx -> H[6] += g;
    ctx -> H[7] += h;
}

void sha256_update(SHA256_CTX *ctx, const BYTE data[], size_t len)
{
    WORD i;
    for(i = 0; i < len; i++) {
        ctx->data[ctx->datalen++] = data[i];
        if(ctx->datalen == 64){
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

void sha256_final(SHA256_CTX *ctx, BYTE hash[])
{
    // Process remaining bits in ctx->data that isn't a complete 512 block yet
    WORD i = ctx -> datalen;
    if(ctx -> datalen < 56) { //Less than 448 bits
        ctx -> data[i++] = 0x80; //1000_0000
        while (i < 56) ctx -> data[i++] = 0x00; //Append 0s till 448 bits
    }
    else { //If >= 448 bits and less than 512 bits
        ctx -> data[i++] = 0x80;
        while(i<64) ctx->data[i++] = 0x00;
        sha256_transform(ctx, ctx->data);
        memset(ctx -> data, 0, 56);
    }
    ctx -> bitlen += ctx -> datalen * 8;
    /*Append message length as last 64 bits and process it as another block
    Remember x86 is little endian and SHA256 is big endian*/

    ctx -> data[63] = ctx -> bitlen;
    ctx -> data[62] = ctx -> bitlen >> 8;
    ctx -> data[61] = ctx -> bitlen >> 16;
    ctx -> data[60] = ctx -> bitlen >> 24;
    ctx -> data[59] = ctx -> bitlen >> 32;
    ctx -> data[58] = ctx -> bitlen >> 40;
    ctx -> data[57] = ctx -> bitlen >> 48;
    ctx -> data[56] = ctx -> bitlen >> 56;
    sha256_transform(ctx, ctx->data);

    for(i=0; i<8; i++){
        hash[i*4 + 0] = (ctx -> H[i] >> 24) & 0xff;
        hash[i*4 + 1] = (ctx -> H[i] >> 16) & 0xff;
        hash[i*4 + 2] = (ctx -> H[i] >> 8)  & 0xff;
        hash[i*4 + 3] = (ctx -> H[i]) & 0xff;
    }
}

