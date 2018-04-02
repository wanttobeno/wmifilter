#ifndef BASE_64_H__
#define BASE_64_H__ 1

char* base64_encode(const char* data, int data_len); 
char *base64_decode(const char* data, int data_len); 
char find_pos(char ch); 

#endif // BASE_64_H__