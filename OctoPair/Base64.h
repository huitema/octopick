#pragma once


void Base64Encode(unsigned char * data, int data_len, char * base64_text);

int base64_howlong(int data_length);

int base64_to_hash(char * base64_text);