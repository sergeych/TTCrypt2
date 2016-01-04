#ifndef __rigndael_h
#define __rigndael_h

typedef unsigned int word32;
typedef unsigned int uint;
typedef unsigned char byte;

#define ERR_SIZE	1
#define OK			0

typedef struct rijndael_instance {
	int Nk,Nb,Nr;
	byte fi[24],ri[24];
	word32 fkey[120];
	word32 rkey[120];
} RI;

#ifdef __cplusplus
extern "C" {
#endif

extern void rj256_encrypt(RI * rinst, byte * buff);
extern void rj256_decrypt(RI * rinst, byte * buff);
extern int rj256_set_key(RI * rinst, byte * key);

#ifdef __cplusplus
}
#endif

#endif