/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <gmssl/mem.h>
#include <gmssl/sm3.h>
#include <gmssl/sm9.h>
#include <gmssl/asn1.h>
#include <gmssl/error.h>


int sm9_kem_encrypt(const SM9_ENC_MASTER_KEY *mpk, const char *id, size_t idlen,
	size_t klen, uint8_t *kbuf, SM9_Z256_POINT *C)
{
	sm9_z256_t r;
	sm9_z256_fp12_t w;
	uint8_t wbuf[32 * 12];
	uint8_t cbuf[65];
	SM3_KDF_CTX kdf_ctx;

	// A1: Q = H1(ID||hid,N) * P1 + Ppube
	sm9_z256_hash1(r, id, idlen, SM9_HID_ENC);
	sm9_z256_point_mul(C, r, sm9_z256_generator());
	sm9_z256_point_add(C, C, &mpk->Ppube);

	do {
		// A2: rand r in [1, N-1]
		if (sm9_z256_rand_range(r, sm9_z256_order()) != 1) {
			error_print();
			return -1;
		}

		// A3: C1 = r * Q
		sm9_z256_point_mul(C, r, C);
		sm9_z256_point_to_uncompressed_octets(C, cbuf);

		// A4: g = e(Ppube, P2)
		sm9_z256_pairing(w, sm9_z256_twist_generator(), &mpk->Ppube);

		// A5: w = g^r
		sm9_z256_fp12_pow(w, w, r);
		sm9_z256_fp12_to_bytes(w, wbuf);

		// A6: K = KDF(C || w || ID_B, klen), if K == 0, goto A2
		sm3_kdf_init(&kdf_ctx, klen);
		sm3_kdf_update(&kdf_ctx, cbuf + 1, 64);
		sm3_kdf_update(&kdf_ctx, wbuf, sizeof(wbuf));
		sm3_kdf_update(&kdf_ctx, (uint8_t *)id, idlen);
		sm3_kdf_finish(&kdf_ctx, kbuf);

	} while (mem_is_zero(kbuf, klen) == 1);

	gmssl_secure_clear(&r, sizeof(r));
	gmssl_secure_clear(&w, sizeof(w));
	gmssl_secure_clear(wbuf, sizeof(wbuf));
	gmssl_secure_clear(&kdf_ctx, sizeof(kdf_ctx));

	// A7: output (K, C)
	return 1;
}

int sm9_kem_decrypt(const SM9_ENC_KEY *key, const char *id, size_t idlen, const SM9_Z256_POINT *C,
	size_t klen, uint8_t *kbuf)
{
	sm9_z256_fp12_t w;
	uint8_t wbuf[32 * 12];
	uint8_t cbuf[65];
	SM3_KDF_CTX kdf_ctx;

	// B1: check C in G1
	sm9_z256_point_to_uncompressed_octets(C, cbuf);

	// B2: w = e(C, de);
	sm9_z256_pairing(w, &key->de, C);
	sm9_z256_fp12_to_bytes(w, wbuf);

	// B3: K = KDF(C || w || ID, klen)
	sm3_kdf_init(&kdf_ctx, klen);
	sm3_kdf_update(&kdf_ctx, cbuf + 1, 64);
	sm3_kdf_update(&kdf_ctx, wbuf, sizeof(wbuf));
	sm3_kdf_update(&kdf_ctx, (uint8_t *)id, idlen);
	sm3_kdf_finish(&kdf_ctx, kbuf);

	if (mem_is_zero(kbuf, klen)) {
		error_print();
		return -1;
	}

	gmssl_secure_clear(&w, sizeof(w));
	gmssl_secure_clear(wbuf, sizeof(wbuf));
	gmssl_secure_clear(&kdf_ctx, sizeof(kdf_ctx));

	// B4: output K
	return 1;
}

// mpk：指向 SM9 加密主公钥的指针。
// id：表示用户身份的字符串。
// idlen：用户身份字符串的长度。
// in：要加密的明文数据。
// inlen：明文数据的长度。
// C1：用于存储加密过程中生成的点 C1。
// c2：用于存储加密后的密文数据。
// c3：用于存储 HMAC 校验值。
int sm9_do_encrypt(const SM9_ENC_MASTER_KEY *mpk, const char *id, size_t idlen,
	const uint8_t *in, size_t inlen,
	SM9_Z256_POINT *C1, uint8_t *c2, uint8_t c3[SM3_HMAC_SIZE])
{
	SM3_HMAC_CTX hmac_ctx; // HMAC 上下文结构体，用于计算 HMAC 校验值。
	uint8_t K[SM9_MAX_PLAINTEXT_SIZE + 32]; // 密钥缓冲区，用于存储 KEM（密钥封装机制）生成的密钥数据。

	if (sm9_kem_encrypt(mpk, id, idlen, sizeof(K), K, C1) != 1) { // 调用 sm9_kem_encrypt 函数，执行密钥封装机制生成密钥 K 和点 C1。
		error_print();
		return -1;
	}
	gmssl_memxor(c2, K, in, inlen); // 使用 K 中的前 inlen 个字节与明文 in 进行按位异或（XOR）操作，生成密文 c2。

	//sm3_hmac(K + inlen, 32, c2, inlen, c3);
	sm3_hmac_init(&hmac_ctx, K + inlen, SM3_HMAC_SIZE); // 初始化 HMAC 上下文。
	sm3_hmac_update(&hmac_ctx, c2, inlen); // 更新 HMAC 上下文，处理数据。
	sm3_hmac_finish(&hmac_ctx, c3); // 完成 HMAC 计算，生成校验值。
	gmssl_secure_clear(&hmac_ctx, sizeof(hmac_ctx)); // 安全清除 HMAC 上下文中的敏感数据。
	return 1;
}
// key: SM9 解密密钥
// id: 用户 ID
// idlen: 用户 ID 的长度
// C1: 密文的一部分，椭圆曲线上的一个点
// c2: 密文的另一部分
// c2len: 密文 c2 的长度
// c3: 密文的 HMAC 校验码
// out: 输出缓冲区，用于存放解密后的明文
int sm9_do_decrypt(const SM9_ENC_KEY *key, const char *id, size_t idlen,
	const SM9_Z256_POINT *C1, const uint8_t *c2, size_t c2len, const uint8_t c3[SM3_HMAC_SIZE],
	uint8_t *out)
{
	SM3_HMAC_CTX hmac_ctx;
	uint8_t k[SM9_MAX_PLAINTEXT_SIZE + SM3_HMAC_SIZE];
	uint8_t mac[SM3_HMAC_SIZE];

	if (c2len > SM9_MAX_PLAINTEXT_SIZE) { // 确保密文长度不超过允许的最大值。
		error_print();
		return -1;
	}

	if (sm9_kem_decrypt(key, id, idlen, C1, sizeof(k), k) != 1) { // 解密 KEM（密钥封装机制）生成的密钥 K。
		error_print();
		return -1;
	}
	//sm3_hmac(k + c2len, SM3_HMAC_SIZE, c2, c2len, mac);
    // 使用 sm3_hmac 计算 c2 的 HMAC 校验码并存储在 mac 中。这里使用 k 的后半部分作为 HMAC 的密钥。
	sm3_hmac_init(&hmac_ctx, k + c2len, SM3_HMAC_SIZE);
	sm3_hmac_update(&hmac_ctx, c2, c2len);
	sm3_hmac_finish(&hmac_ctx, mac);
	gmssl_secure_clear(&hmac_ctx, sizeof(hmac_ctx));

	if (gmssl_secure_memcmp(c3, mac, sizeof(mac)) != 0) { // 比较计算得到的 HMAC 和密文中的 HMAC 如果 HMAC 校验码不匹配，则返回错误。
		error_print();
		return -1;
	}
	gmssl_memxor(out, k, c2, c2len); // 使用密钥 k 和密文 c2 进行异或操作，得到解密后的明文存储在 out 中。
	return 1;
}

#define SM9_ENC_TYPE_XOR	0
#define SM9_ENC_TYPE_ECB	1
#define SM9_ENC_TYPE_CBC	2
#define SM9_ENC_TYPE_OFB	4
#define SM9_ENC_TYPE_CFB	8

/*
SM9Cipher ::= SEQUENCE {
	EnType		INTEGER, -- 0 for XOR
	C1		BIT STRING, -- uncompressed octets of ECPoint
	C3		OCTET STRING, -- 32 bytes HMAC-SM3 tag
	CipherText	OCTET STRING,
}
*/
int sm9_ciphertext_to_der(const SM9_Z256_POINT *C1, const uint8_t *c2, size_t c2len,
	const uint8_t c3[SM3_HMAC_SIZE], uint8_t **out, size_t *outlen)
{
	int en_type = SM9_ENC_TYPE_XOR;
	uint8_t c1[65];
	size_t len = 0;

	if (sm9_z256_point_to_uncompressed_octets(C1, c1) != 1) {
		error_print();
		return -1;
	}
	if (asn1_int_to_der(en_type, NULL, &len) != 1
		|| asn1_bit_octets_to_der(c1, sizeof(c1), NULL, &len) != 1
		|| asn1_octet_string_to_der(c3, SM3_HMAC_SIZE, NULL, &len) != 1
		|| asn1_octet_string_to_der(c2, c2len, NULL, &len) != 1 // 计算各个字段的 DER 编码长度并累加到 len 中。这里的 out 参数传递为 NULL，表示只是计算长度，而不进行实际编码。
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_int_to_der(en_type, out, outlen) != 1
		|| asn1_bit_octets_to_der(c1, sizeof(c1), out, outlen) != 1
		|| asn1_octet_string_to_der(c3, SM3_HMAC_SIZE, out, outlen) != 1
		|| asn1_octet_string_to_der(c2, c2len, out, outlen) != 1) {  // 按照 DER 编码格式将各个字段编码到输出缓冲区 out 中，并更新 outlen 的值。
		error_print();
		return -1;
	}
	return 1;
}

int sm9_ciphertext_from_der(SM9_Z256_POINT *C1, const uint8_t **c2, size_t *c2len,
	const uint8_t **c3, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;
	int en_type;
	const uint8_t *c1;
	size_t c1len;
	size_t c3len;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_int_from_der(&en_type, &d, &dlen) != 1
		|| asn1_bit_octets_from_der(&c1, &c1len, &d, &dlen) != 1
		|| asn1_octet_string_from_der(c3, &c3len, &d, &dlen) != 1
		|| asn1_octet_string_from_der(c2, c2len, &d, &dlen) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	if (en_type != SM9_ENC_TYPE_XOR) {
		error_print();
		return -1;
	}
	if (c1len != 65) {
		error_print();
		return -1;
	}
	if (c3len != SM3_HMAC_SIZE) {
		error_print();
		return -1;
	}
	if (sm9_z256_point_from_uncompressed_octets(C1, c1) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

// mpk：指向 SM9 加密主公钥的指针。
// id：表示用户身份的字符串。
// idlen：用户身份字符串的长度。
// in：要加密的明文数据。
// inlen：明文数据的长度。
// out：用于存储加密后的输出数据。
// outlen：存储加密后输出数据的长度。
int sm9_encrypt(const SM9_ENC_MASTER_KEY *mpk, const char *id, size_t idlen,
	const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen)
{
    // 定义了临时变量 C1、c2 和 c3，分别用于存储加密过程中生成的 C1 点、加密后的明文数据和 HMAC 校验值。
	SM9_Z256_POINT C1;
	uint8_t c2[SM9_MAX_PLAINTEXT_SIZE];
	uint8_t c3[SM3_HMAC_SIZE];

	if (inlen > SM9_MAX_PLAINTEXT_SIZE) { // 检查输入数据的长度是否超过了 SM9 规定的最大明文长度。如果超过，则返回错误。 255
		error_print();
		return -1;
	}

	if (sm9_do_encrypt(mpk, id, idlen, in, inlen, &C1, c2, c3) != 1) { // 进行实际的加密操作。如果加密失败，打印错误信息并返回错误。
		error_print();
		return -1;
	}
	*outlen = 0; // 初始化输出数据长度为 0
    // 调用 sm9_ciphertext_to_der 函数，将加密后的数据（包括 C1、c2 和 c3）编码为 DER 格式，并存储在 out 中。
	if (sm9_ciphertext_to_der(&C1, c2, inlen, c3, &out, outlen) != 1) { // FIXME: when out == NULL	
		error_print();
		return -1;
	}
	return 1;
}

// key：指向用于解密的 SM9 密钥。
// id：标识符。
// idlen：标识符的长度。
// in：输入的加密数据。
// inlen：输入数据的长度。
// out：解密后的输出缓冲区。
// outlen：指向输出缓冲区长度的指针。
int sm9_decrypt(const SM9_ENC_KEY *key, const char *id, size_t idlen,
	const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen)
{
	SM9_Z256_POINT C1; // 存储解密过程中使用的点 C1。
	const uint8_t *c2; // 存储解密后得到的密文数据。
	size_t c2len; // 密文数据的长度。
	const uint8_t *c3; // 存储解密后得到的 HMAC 校验值。

	if (sm9_ciphertext_from_der(&C1, &c2, &c2len, &c3, &in, &inlen) != 1 // 从 DER 编码的输入数据中提取点 C1、密文数据 c2、密文数据长度 c2len 和 HMAC 校验值 c3。
		|| asn1_length_is_zero(inlen) != 1) { // 检查剩余的输入数据长度是否为零。
		error_print();
		return -1;
	}
	*outlen = c2len; // 将密文数据的长度赋值给 outlen。
	if (!out) { // 如果 out 为 NULL，只返回长度信息。只需要知道解密后的数据长度
		return 1;
	}
	if (sm9_do_decrypt(key, id, idlen, &C1, c2, c2len, c3, out) != 1) {
		error_print();
		return -1;
	}
	return 1;
}
