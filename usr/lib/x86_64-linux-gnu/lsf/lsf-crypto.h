#pragma once

/******************************************************************************
* DEFINE
******************************************************************************/
#define LSF_RSA_PUBLICKEY_TYPE  0
#define LSF_RSA_PRIVATEKEY_TYPE  1

#define LSF_CRYPTO_SUCCESS  0
#define LSF_CRYPTO_FAIL     1

#define LSF_ERR     0
#define LSF_INFO    1

#ifdef LSF_DEBUG
#define GLOG(lvl, fmt, args...) fprintf(lvl==LSF_ERR?stderr:stdout, "[%s][%s:%d] " fmt,\
                                        lvl==LSF_ERR?"ERROR":"INFO", \
                                        __func__ ,__LINE__, ##args)
#define GPRINT(fmt, args...)   printf(fmt, ##args)
#else
#define GLOG(lv, fmt, args...) 
#define GPRINT(fmt, args...) 
#endif //LSF_DEBUG

#define LSF_FREE(v) if(v)free(v)

#define LSF_CRYPTO_ERRMSG_LEN       256

/******************************************************************************
* TYPE
******************************************************************************/
typedef struct _lsf_error_t {
    char message[LSF_CRYPTO_ERRMSG_LEN];    

} lsf_error_t;

/******************************************************************************
* DECLARE
******************************************************************************/
#ifdef __cplusplus
extern "C"
{
#endif

int 
lsf_encrypt_MC_RSAOAEP_SHA256(
                        const unsigned char *public_key, 
                        unsigned int public_key_len,
                        const unsigned char *plain_text, 
                        unsigned char **encrypted_text, 
                        unsigned int *encrypted_text_len,
                        lsf_error_t **error
                        );


int 
lsf_decrypt_MC_RSAOAEP_SHA256(
                        const unsigned char *private_key, 
                        unsigned int private_key_len,
                        const unsigned char *encrypted_text, 
                        unsigned int encrypted_text_len, 
                        unsigned char **plain_text, 
                        unsigned int *plain_text_len,
                        lsf_error_t **error
                        );

int
lsf_encrypt_MC_ARIA_CBC_PKCS5(
                        unsigned char *key,
                        unsigned char *iv,
                        unsigned char *plain_text,
                        unsigned char **encrypted_text,
                        unsigned int *encrypted_text_len,
                        lsf_error_t **error
                        );

int
lsf_decrypt_MC_ARIA_CBC_PKCS5(
                        unsigned char *key,
                        unsigned char *iv,
                        unsigned char *encrypted_text,
                        unsigned int encrypted_text_len,
                        unsigned char **plain_text,
                        unsigned int *plain_text_len,
                        lsf_error_t **error
                        );

int 
lsf_read_key_MC_RSA_PKCS1(
            const char *key_path, 
            int key_type, 
            unsigned char **decoded_key,
            size_t *decoded_key_len,
            lsf_error_t **error
            );

int
lsf_base64_encode(
                const char *src,
                size_t len,
                unsigned char **dst,
                size_t *out_len,
                lsf_error_t **error
                );

int
lsf_base64_decode(
                const char *src,
                size_t len,
                unsigned char **dst,
                size_t *out_len,
                lsf_error_t **error
                );

void 
lsf_print_hex(unsigned char *data, unsigned int datalen);

#ifdef __cplusplus
};
#endif
