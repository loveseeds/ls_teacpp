#include "ls_teacpp.h"

#include <string.h>

namespace ls
{

// Encrypt two numbers at a time
void base_encrypt (uint32_t* v, uint32_t* k) {  
    uint32_t v0=v[0], v1=v[1], sum=0, i;           /* set up */  
    uint32_t delta=0x9e3779b9;                     /* a key schedule constant */  
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */  
    for (i=0; i < 32; i++) {                       /* basic cycle start */  
        sum += delta;  
        v0 += ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);  
        v1 += ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);  
    }                                              /* end cycle */  
    v[0]=v0; v[1]=v1;  
}

// Decrypt two numbers at a time
void base_decrypt (uint32_t* v, uint32_t* k) {  
    uint32_t v0=v[0], v1=v[1], sum=0xC6EF3720, i;  /* set up */  
    uint32_t delta=0x9e3779b9;                     /* a key schedule constant */  
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */  
    for (i=0; i<32; i++) {                         /* basic cycle start */  
        v1 -= ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);  
        v0 -= ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);  
        sum -= delta;  
    }                                              /* end cycle */  
    v[0]=v0; v[1]=v1;  
}

// Encrypt/Decrypt length is 16 bytes
#define TEA_KEY_LENGTH  (16)

bool _tea_encrypt_decrypt(const void* in_buffer, const uint32_t in_length, const char* key, void* out_buffer, uint32_t* out_length, void(*_tea_algo_handle)(uint32_t* v, uint32_t* k))
{
    if(in_buffer == NULL || out_buffer == NULL || key == NULL || \
       out_length == NULL || _tea_algo_handle == NULL)
    {
        return false;
    }

    if(strlen(key) != TEA_KEY_LENGTH)
    {
        return false;
    }

    uint32_t tea_length = (in_length%8) ? (in_length/8+1)<<3 : in_length;   // resize input data len
    uint32_t op_data[2]={0}, op_key[4]={0};

    char* p_in_buffer = (char*)out_buffer;              // use same buffer, to save memory
    char* p_out_buffer = (char*)out_buffer;

    memset(p_out_buffer, 0, tea_length);                // file zero
    memcpy(p_in_buffer, in_buffer, in_length);          // copy input data

    memcpy(op_key, key, strlen(key));                   // copy key

    for(uint32_t i=0; i<tea_length/8; i++)
    {
        memcpy(op_data, &p_in_buffer[i*8], 8);     
        _tea_algo_handle(op_data, op_key);              // encrypt or decrypt
        memcpy(&p_out_buffer[i*8], op_data, 8);         // out encrypt or ecrypt result
    }

    *out_length = tea_length;

    return true;
}

bool _tea_encrypt(const void* in_buffer, const uint32_t in_length, const char* key, void* out_buffer, uint32_t* out_length)
{
    return _tea_encrypt_decrypt(in_buffer, in_length, key, out_buffer, out_length, base_encrypt);
}

bool _tea_decrypt(const void* in_buffer, const uint32_t in_length, const char* key, void* out_buffer, uint32_t* out_length)
{
    return _tea_encrypt_decrypt(in_buffer, in_length, key, out_buffer, out_length, base_decrypt);
}

bool tea_encrypt(const uint8_t* from_buffer, const uint32_t from_length, const char* key, uint8_t* to_buffer, uint32_t* to_length)
{
    return _tea_encrypt(from_buffer, from_length, key, to_buffer, to_length);
}

bool tea_decrypt(const uint8_t* from_buffer, const uint32_t from_length, const char* key, uint8_t* to_buffer, uint32_t* to_length)
{
    return _tea_decrypt(from_buffer, from_length, key, to_buffer, to_length);
}

bool tea_encrypt(std::string from_buffer, std::string key, uint8_t* to_buffer, uint32_t* to_length)
{
    return _tea_encrypt(from_buffer.c_str(), from_buffer.length(), key.c_str(), to_buffer, to_length);
}

bool tea_decrypt(std::string from_buffer, std::string key, uint8_t* to_buffer, uint32_t* to_length)
{
    return _tea_decrypt(from_buffer.c_str(), from_buffer.length(), key.c_str(), to_buffer, to_length);
}

} // namespace ls
