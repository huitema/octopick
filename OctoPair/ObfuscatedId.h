#pragma once


void Base64Encode(unsigned char * data, int data_len, char * base64_text);
int base64_howlong(int data_length);

/*
* Compute binary obfuscated ID from nonce and key
*/
int CreateObfuscatedBinaryId(unsigned char * nonce, int nonce_len, unsigned char * key, int key_len,
    unsigned char * id, int id_len);
/*
* Compute the Base64 ID.
* ID_len is the length of the binary ID.
* base64_id is a text buffer large enough to hold the ID and the trailing zero.
*/
int CreateObfuscatedBase64Id(unsigned char * nonce, int nonce_len, unsigned char * key, int key_len,
    int id_len, char * base64_id);
/*
* Compute binary obfuscated ID from time based nonce and key,
* using 24 + 48 bits = 9 octets binary, 12 chars text.
*/
int CreateDnssdPrivacyId(unsigned int current_time, unsigned char * key, int key_len, char * id);