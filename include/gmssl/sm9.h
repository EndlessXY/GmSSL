/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */
// 头文件保护
#ifndef GMSSL_SM9_H
#define GMSSL_SM9_H
// 依赖的头文件
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <gmssl/sm3.h>
#include <gmssl/sm2.h>
#include <gmssl/sm9_z256.h>
// C++兼容性, 这部分代码确保如果此头文件被一个C++编译器包含，编译器将按C语言的方式处理其内容。
#ifdef __cplusplus
extern "C" {
#endif


// 这个函数声明了一个哈希函数，用于生成哈希值h1，根据输入的身份标识符id和标识符hid。
int sm9_z256_hash1(sm9_z256_t h1, const char *id, size_t idlen, uint8_t hid);
// 常量和宏定义
/* private key extract algorithms */
#define SM9_HID_SIGN		0x01
#define SM9_HID_EXCH		0x02
#define SM9_HID_ENC		0x03

#define SM9_HASH1_PREFIX	0x01
#define SM9_HASH2_PREFIX	0x02
// 这些函数用于处理对象标识符（OID）和算法参数的编码和解码。
const char *sm9_oid_name(int oid);
int sm9_oid_from_name(const char *name);
int sm9_oid_to_der(int oid, uint8_t **out, size_t *outlen);
int sm9_oid_from_der(int *oid, const uint8_t **in, size_t *inlen);
int sm9_algor_to_der(int alg, int params, uint8_t **out, size_t *outlen);
int sm9_algor_from_der(int *alg, int *params, const uint8_t **in, size_t *inlen);

// 这些宏定义了PEM格式的SM9密钥和公钥的标签。
#define PEM_SM9_SIGN_MASTER_KEY		"ENCRYPTED SM9 SIGN MASTER KEY"
#define PEM_SM9_SIGN_MASTER_PUBLIC_KEY	"SM9 SIGN MASTER PUBLIC KEY"
#define PEM_SM9_SIGN_PRIVATE_KEY	"ENCRYPTED SM9 SIGN PRIVATE KEY"
#define PEM_SM9_ENC_MASTER_KEY		"ENCRYPTED SM9 ENC MASTER KEY"
#define PEM_SM9_ENC_MASTER_PUBLIC_KEY	"SM9 ENC MASTER PUBLIC KEY"
#define PEM_SM9_ENC_PRIVATE_KEY		"ENCRYPTED SM9 ENC PRIVATE KEY"

// 这个宏定义了SM9身份标识符的最大长度。
#define SM9_MAX_ID_SIZE		(SM2_MAX_ID_SIZE)

/*
SM9SignMasterKey ::= SEQUENCE {
	ks	INTEGER,
	Ppubs	BIT STRING -- uncompressed octets of twisted point }

SM9SignMasterPublicKey ::= SEQUENCE {
	Ppubs   BIT STRING -- uncompressed octets of twisted point }

SM9SignPrivateKey ::= SEQUENCE {
	ds	BIT STRING, -- uncompressed octets of ECPoint
	Ppubs	BIT STRING -- uncompressed octets of twisted point }
*/
// SM9签名相关的结构体
typedef struct {
	SM9_Z256_TWIST_POINT Ppubs; // Ppubs = ks * P2
	sm9_z256_t ks;
} SM9_SIGN_MASTER_KEY; // SM9签名主密钥

typedef struct {
	SM9_Z256_TWIST_POINT Ppubs;
	SM9_Z256_POINT ds;
} SM9_SIGN_KEY; // SM9签名密钥

int sm9_sign_master_key_generate(SM9_SIGN_MASTER_KEY *master);  // 生成SM9签名主密钥
int sm9_sign_master_key_extract_key(SM9_SIGN_MASTER_KEY *master, const char *id, size_t idlen, SM9_SIGN_KEY *key);  // 从SM9签名主密钥中提取密钥

// algorthm,parameters = sm9,sm9sign
#define SM9_SIGN_MASTER_KEY_MAX_SIZE 171
int sm9_sign_master_key_to_der(const SM9_SIGN_MASTER_KEY *msk, uint8_t **out, size_t *outlen);  // 将SM9签名主密钥编码为DER格式
int sm9_sign_master_key_from_der(SM9_SIGN_MASTER_KEY *msk, const uint8_t **in, size_t *inlen);  // 从DER格式解码SM9签名主密钥
int sm9_sign_master_key_info_encrypt_to_der(const SM9_SIGN_MASTER_KEY *msk, const char *pass, uint8_t **out, size_t *outlen);  // 将SM9签名主密钥加密为DER格式
int sm9_sign_master_key_info_decrypt_from_der(SM9_SIGN_MASTER_KEY *msk, const char *pass, const uint8_t **in, size_t *inlen);  // 从DER格式解密SM9签名主密钥
int sm9_sign_master_key_info_encrypt_to_pem(const SM9_SIGN_MASTER_KEY *msk, const char *pass, FILE *fp);  // 将SM9签名主密钥加密为PEM格式, 然后将结果写入文件
int sm9_sign_master_key_info_decrypt_from_pem(SM9_SIGN_MASTER_KEY *msk, const char *pass, FILE *fp);  // 从PEM格式解密SM9签名主密钥
int sm9_sign_master_key_print(FILE *fp, int fmt, int ind, const char *label, const SM9_SIGN_MASTER_KEY *msk);  // 打印SM9签名主密钥

#define SM9_SIGN_MASTER_PUBLIC_KEY_SIZE 136
int sm9_sign_master_public_key_to_der(const SM9_SIGN_MASTER_KEY *mpk, uint8_t **out, size_t *outlen);  // 将SM9签名主公钥编码为DER格式
int sm9_sign_master_public_key_from_der(SM9_SIGN_MASTER_KEY *mpk, const uint8_t **in, size_t *inlen);  // 从DER格式解码SM9签名主公钥
int sm9_sign_master_public_key_to_pem(const SM9_SIGN_MASTER_KEY *mpk, FILE *fp); // 将SM9签名主公钥编码为PEM格式, 然后将结果写入文件
int sm9_sign_master_public_key_from_pem(SM9_SIGN_MASTER_KEY *mpk, FILE *fp); // 从PEM格式解码SM9签名主公钥
int sm9_sign_master_public_key_print(FILE *fp, int fmt, int ind, const char *label, const SM9_SIGN_MASTER_KEY *mpk); // 打印SM9签名主公钥

// algorithm,parameters = sm9sign,<null>
#define SM9_SIGN_KEY_SIZE 204
int sm9_sign_key_to_der(const SM9_SIGN_KEY *key, uint8_t **out, size_t *outlen); // 将SM9签名密钥编码为DER格式
int sm9_sign_key_from_der(SM9_SIGN_KEY *key, const uint8_t **in, size_t *inlen); // 从DER格式解码SM9签名密钥
int sm9_sign_key_info_encrypt_to_der(const SM9_SIGN_KEY *key, const char *pass, uint8_t **out, size_t *outlen); // 将SM9签名密钥加密为DER格式
int sm9_sign_key_info_decrypt_from_der(SM9_SIGN_KEY *key, const char *pass, const uint8_t **in, size_t *inlen); // 从DER格式解密SM9签名密钥
int sm9_sign_key_info_encrypt_to_pem(const SM9_SIGN_KEY *key, const char *pass, FILE *fp); // 将SM9签名密钥加密为PEM格式, 然后将结果写入文件
int sm9_sign_key_info_decrypt_from_pem(SM9_SIGN_KEY *key, const char *pass, FILE *fp); // 从PEM格式解密SM9签名密钥
int sm9_sign_key_print(FILE *fp, int fmt, int ind, const char *label, const SM9_SIGN_KEY *key); // 打印SM9签名密钥

/*
from GM/T 0080-2020 SM9 Cryptographic Alagorithm Application Specification
SM9Signature ::= SEQUENCE {
	h	OCTET STRING,
	S	BIT STRING -- uncompressed octets of ECPoint }
*/
typedef struct {
	sm9_z256_t h;
	SM9_Z256_POINT S;
} SM9_SIGNATURE;  // SM9签名 一个哈希值 h 和一个椭圆曲线点 S

int sm9_do_sign(const SM9_SIGN_KEY *key, const SM3_CTX *sm3_ctx, SM9_SIGNATURE *sig); // SM9签名
int sm9_do_verify(const SM9_SIGN_MASTER_KEY *mpk, const char *id, size_t idlen, const SM3_CTX *sm3_ctx, const SM9_SIGNATURE *sig); // SM9签名验证

#define SM9_SIGNATURE_SIZE 104
int sm9_signature_to_der(const SM9_SIGNATURE *sig, uint8_t **out, size_t *outlen); // 将SM9签名编码为DER格式
int sm9_signature_from_der(SM9_SIGNATURE *sig, const uint8_t **in, size_t *inlen); // 从DER格式解码SM9签名
int sm9_signature_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *sig, size_t siglen); // 打印SM9签名

typedef struct {
	SM3_CTX sm3_ctx;
} SM9_SIGN_CTX;  // SM9签名上下文，类似于哈希

int sm9_sign_init(SM9_SIGN_CTX *ctx);  // 初始化SM9签名上下文
int sm9_sign_update(SM9_SIGN_CTX *ctx, const uint8_t *data, size_t datalen);  // 更新SM9签名上下文
int sm9_sign_finish(SM9_SIGN_CTX *ctx, const SM9_SIGN_KEY *key, uint8_t *sig, size_t *siglen);  // 完成SM9签名
int sm9_verify_init(SM9_SIGN_CTX *ctx); // 初始化SM9签名验证上下文
int sm9_verify_update(SM9_SIGN_CTX *ctx, const uint8_t *data, size_t datalen); // 更新SM9签名验证上下文
int sm9_verify_finish(SM9_SIGN_CTX *ctx, const uint8_t *sig, size_t siglen,
	const SM9_SIGN_MASTER_KEY *mpk, const char *id, size_t idlen);  // 完成SM9签名验证



/*
SM9EncMasterKey ::= SEQUENCE {
	de	INTEGER,
	Ppube	BIT STRING -- uncompressed octets of ECPoint }

SM9EncMasterPublicKey ::= SEQUENCE {
	Ppube	BIT STRING -- uncompressed octets of ECPoint }

SM9EncPrivateKey ::= SEQUENCE {
	de	BIT STRING, -- uncompressed octets of twisted point
	Ppube	BIT STRING -- uncompressed octets of ECPoint }
*/

typedef struct {
	SM9_Z256_POINT Ppube; // Ppube = ke * P1
	sm9_z256_t ke;
} SM9_ENC_MASTER_KEY; // SM9加密主密钥

typedef struct {
	SM9_Z256_POINT Ppube;
	SM9_Z256_TWIST_POINT de;
} SM9_ENC_KEY; // SM9加密密钥

int sm9_enc_master_key_generate(SM9_ENC_MASTER_KEY *master); // 生成SM9加密主密钥
int sm9_enc_master_key_extract_key(SM9_ENC_MASTER_KEY *master, const char *id, size_t idlen, SM9_ENC_KEY *key); // 从SM9加密主密钥中提取密钥

// algorithm,parameters = sm9,sm9encrypt
#define SM9_ENC_MASTER_KEY_MAX_SIZE 105
int sm9_enc_master_key_to_der(const SM9_ENC_MASTER_KEY *msk, uint8_t **out, size_t *outlen);  // 将SM9加密主密钥编码为DER格式
int sm9_enc_master_key_from_der(SM9_ENC_MASTER_KEY *msk, const uint8_t **in, size_t *inlen);  // 从DER格式解码SM9加密主密钥
int sm9_enc_master_key_info_encrypt_to_der(const SM9_ENC_MASTER_KEY *msk, const char *pass, uint8_t **out, size_t *outlen);  // 将SM9加密主密钥加密为DER格式
int sm9_enc_master_key_info_decrypt_from_der(SM9_ENC_MASTER_KEY *msk, const char *pass, const uint8_t **in, size_t *inlen);  // 从DER格式解密SM9加密主密钥
int sm9_enc_master_key_info_encrypt_to_pem(const SM9_ENC_MASTER_KEY *msk, const char *pass, FILE *fp);  // 将SM9加密主密钥加密为PEM格式, 然后将结果写入文件
int sm9_enc_master_key_info_decrypt_from_pem(SM9_ENC_MASTER_KEY *msk, const char *pass, FILE *fp);  // 从PEM格式解密SM9加密主密钥
int sm9_enc_master_key_print(FILE *fp, int fmt, int ind, const char *label, const SM9_ENC_MASTER_KEY *msk);  // 打印SM9加密主密钥

#define SM9_ENC_MASTER_PUBLIC_KEY_SIZE 70
int sm9_enc_master_public_key_to_der(const SM9_ENC_MASTER_KEY *mpk, uint8_t **out, size_t *outlen);  // 将SM9加密主公钥编码为DER格式
int sm9_enc_master_public_key_from_der(SM9_ENC_MASTER_KEY *mpk, const uint8_t **in, size_t *inlen);  // 从DER格式解码SM9加密主公钥
int sm9_enc_master_public_key_to_pem(const SM9_ENC_MASTER_KEY *mpk, FILE *fp); // 将SM9加密主公钥编码为PEM格式, 然后将结果写入文件
int sm9_enc_master_public_key_from_pem(SM9_ENC_MASTER_KEY *mpk, FILE *fp); // 从PEM格式解码SM9加密主公钥
int sm9_enc_master_public_key_print(FILE *fp, int fmt, int ind, const char *label, const SM9_ENC_MASTER_KEY *mpk);  // 打印SM9加密主公钥

// algorithm,parameters = sm9encrypt,<null>
#define SM9_ENC_KEY_SIZE 204
int sm9_enc_key_to_der(const SM9_ENC_KEY *key, uint8_t **out, size_t *outlen); // 将SM9加密密钥编码为DER格式
int sm9_enc_key_from_der(SM9_ENC_KEY *key, const uint8_t **in, size_t *inlen); // 从DER格式解码SM9加密密钥
int sm9_enc_key_info_encrypt_to_der(const SM9_ENC_KEY *key, const char *pass, uint8_t **out, size_t *outlen); // 将SM9加密密钥加密为DER格式
int sm9_enc_key_info_decrypt_from_der(SM9_ENC_KEY *key, const char *pass, const uint8_t **in, size_t *inlen); // 从DER格式解密SM9加密密钥
int sm9_enc_key_info_encrypt_to_pem(const SM9_ENC_KEY *key, const char *pass, FILE *fp); // 将SM9加密密钥加密为PEM格式, 然后将结果写入文件
int sm9_enc_key_info_decrypt_from_pem(SM9_ENC_KEY *key, const char *pass, FILE *fp); // 从PEM格式解密SM9加密密钥
int sm9_enc_key_print(FILE *fp, int fmt, int ind, const char *label, const SM9_ENC_KEY *key); // 打印SM9加密密钥

#define SM9_MAX_PRIVATE_KEY_SIZE (SM9_SIGN_KEY_SIZE) // MAX(SIGN_MASTER_KEY, SIGN_KEY, ENC_MASTER_KEY, ENC_KEY) = 204
#define SM9_MAX_PRIVATE_KEY_INFO_SIZE 512
#define SM9_MAX_ENCED_PRIVATE_KEY_INFO_SIZE 1024

/*
from GM/T 0080-2020 SM9 Cryptographic Alagorithm Application Specification
SM9Cipher ::= SEQUENCE {
	EnType		INTEGER, -- 0 for XOR
	C1		BIT STRING, -- uncompressed octets of ECPoint
	C3		OCTET STRING, -- 32 bytes HMAC-SM3 tag
	CipherText	OCTET STRING }
*/

int sm9_kem_encrypt(const SM9_ENC_MASTER_KEY *mpk, const char *id, size_t idlen, size_t klen, uint8_t *kbuf, SM9_Z256_POINT *C); // SM9密钥封装加密
int sm9_kem_decrypt(const SM9_ENC_KEY *key, const char *id, size_t idlen, const SM9_Z256_POINT *C, size_t klen, uint8_t *kbuf); // SM9密钥封装解密
int sm9_do_encrypt(const SM9_ENC_MASTER_KEY *mpk, const char *id, size_t idlen,
	const uint8_t *in, size_t inlen, SM9_Z256_POINT *C1, uint8_t *c2, uint8_t c3[SM3_HMAC_SIZE]); // SM9加密
int sm9_do_decrypt(const SM9_ENC_KEY *key, const char *id, size_t idlen,
	const SM9_Z256_POINT *C1, const uint8_t *c2, size_t c2len, const uint8_t c3[SM3_HMAC_SIZE], uint8_t *out); // SM9解密

#define SM9_MAX_PLAINTEXT_SIZE 255
#define SM9_MAX_CIPHERTEXT_SIZE 367 // calculated in test_sm9_ciphertext()
int sm9_ciphertext_to_der(const SM9_Z256_POINT *C1, const uint8_t *c2, size_t c2len,
	const uint8_t c3[SM3_HMAC_SIZE], uint8_t **out, size_t *outlen); // 将SM9密文编码为DER格式
int sm9_ciphertext_from_der(SM9_Z256_POINT *C1, const uint8_t **c2, size_t *c2len,
	const uint8_t **c3, const uint8_t **in, size_t *inlen); // 从DER格式解码SM9密文
int sm9_ciphertext_print(FILE *fp, int fmt, int ind, const char *label, const uint8_t *a, size_t alen); // 打印SM9密文
int sm9_encrypt(const SM9_ENC_MASTER_KEY *mpk, const char *id, size_t idlen,
	const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);  // SM9加密
int sm9_decrypt(const SM9_ENC_KEY *key, const char *id, size_t idlen,
	const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen); // SM9解密


// SM9 Key Exchange (To be continued)
#define SM9_EXCH_MASTER_KEY SM9_ENC_MASTER_KEY
#define SM9_EXCH_KEY SM9_ENC_KEY
#define sm9_exch_master_key_generate(msk) sm9_enc_master_key_generate(msk)
int sm9_exch_master_key_extract_key(SM9_EXCH_MASTER_KEY *master, const char *id, size_t idlen, SM9_EXCH_KEY *key); // 从SM9密钥交换主密钥中提取密钥

int sm9_exch_step_1A(const SM9_EXCH_MASTER_KEY *mpk, const char *idB, size_t idBlen, SM9_Z256_POINT *RA, sm9_z256_t rA); // SM9密钥交换第一步 A
int sm9_exch_step_1B(const SM9_EXCH_MASTER_KEY *mpk, const char *idA, size_t idAlen, const char *idB, size_t idBlen,
	const SM9_EXCH_KEY *key, const SM9_Z256_POINT *RA, SM9_Z256_POINT *RB, uint8_t *sk, size_t klen); // SM9密钥交换第一步 B
int sm9_exch_step_2A(const SM9_EXCH_MASTER_KEY *mpk, const char *idA, size_t idAlen, const char *idB, size_t idBlen,
	const SM9_EXCH_KEY *key, const sm9_z256_t rA, const SM9_Z256_POINT *RA, const SM9_Z256_POINT *RB, uint8_t *sk, size_t klen); // SM9密钥交换第二步 B
int sm9_exch_step_2B(); // SM9密钥交换第二步 B


#ifdef  __cplusplus
}
#endif
#endif
