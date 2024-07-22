/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/socket.h>
#include <gmssl/error.h>


#ifdef WIN32 // Windows
int tls_socket_lib_init(void) // 初始化 Windows 套接字库
{
	WORD wVersion = MAKEWORD(2, 2); // 定义 Windows 套接字库版本
	WSADATA wsaData; // 定义 Windows 套接字库数据
	int err; // 定义错误码

	if ((err = WSAStartup(wVersion, &wsaData)) != 0) { // 初始化 Windows 套接字库
		fprintf(stderr, "WSAStartup() return error %d\n", err); // 打印错误信息
		error_print(); // 打印错误信息
		return -1; // 返回错误
	}
	return 1;
}

int tls_socket_lib_cleanup(void) // 清理 Windows 套接字库
{
	if (WSACleanup() != 0) { // 清理 Windows 套接字库
		fprintf(stderr, "WSACleanup() return error %d\n", WSAGetLastError()); // 打印错误信息
		error_print(); // 打印错误信息
		return -1;
	}
	return 1;
}

int tls_socket_create(tls_socket_t *sock, int af, int type, int protocol) // 创建一个套接字
{
	if (!sock) { // 如果套接字为空
		error_print(); // 打印错误信息
		return -1;
	}
	// INVALID_SOCKET == -1
	if ((*sock = socket(af, type, protocol)) == INVALID_SOCKET) { // 创建一个套接字
		fprintf(stderr, "%s %d: socket error: %d\n", __FILE__, __LINE__, WSAGetLastError()); // 打印错误信息
		error_print();
		return -1;
	}
	return 1;
}

int tls_socket_connect(tls_socket_t sock, const struct sockaddr_in *addr) // 连接到指定地址的套接字
{
	int addr_len = (int)sizeof(struct sockaddr_in); // 地址长度
	if (connect(sock, (const struct sockaddr *)addr, addr_len) == SOCKET_ERROR) { // 连接到指定地址的套接字
		fprintf(stderr, "%s %d: socket error: %d\n", __FILE__, __LINE__, WSAGetLastError());
		error_print();
		return -1;
	}
	return 1;
}

int tls_socket_bind(tls_socket_t sock, const struct sockaddr_in *addr) // 绑定套接字到指定地址
{
	int addr_len = (int)sizeof(struct sockaddr_in); // 地址长度
	if (bind(sock, (const struct sockaddr *)addr, addr_len) == SOCKET_ERROR) { // 绑定套接字到指定地址
		fprintf(stderr, "%s %d: socket bind error: %u\n", __FILE__, __LINE__, WSAGetLastError());
		error_print();
		return -1;
	}
	return 1;
}

int tls_socket_listen(tls_socket_t sock, int backlog) // 将套接字设为监听状态
{
	if (listen(sock, backlog) == SOCKET_ERROR) { // 将套接字设为监听状态
		fprintf(stderr, "%s %d: socket listen error: %u\n", __FILE__, __LINE__, WSAGetLastError());
		error_print();
		return -1;
	}
	return 1;
}

int tls_socket_accept(tls_socket_t sock, struct sockaddr_in *addr, tls_socket_t *conn_sock) // 接受一个新的连接
{
	int addr_len = (int)sizeof(struct sockaddr_in); // 地址长度
	if ((*conn_sock = accept(sock, (struct sockaddr *)addr, &addr_len)) == INVALID_SOCKET) { // 接受一个新的连接
		fprintf(stderr, "%s %d: accept error: %u\n", __FILE__, __LINE__, WSAGetLastError());
		error_print();
		return -1;
	}
	return 1;
}

#else // POSIX

int tls_socket_lib_init(void)
{
	return 1;
}

int tls_socket_lib_cleanup(void)
{
	return 1;
}

int tls_socket_create(tls_socket_t *sock, int af, int type, int protocol)
{
	if (!sock) {
		error_print();
		return -1;
	}
	if ((*sock = socket(af, type, protocol)) == -1) {
		fprintf(stderr, "%s %d: socket error: %s\n", __FILE__, __LINE__, strerror(errno));
		error_print();
		return -1;
	}
	return 1;
}

int tls_socket_connect(tls_socket_t sock, const struct sockaddr_in *addr)
{
	socklen_t addr_len = sizeof(struct sockaddr_in);
	if (connect(sock, (const struct sockaddr *)addr, addr_len) == -1) {
		fprintf(stderr, "%s %d: socket error: %s\n", __FILE__, __LINE__, strerror(errno));
		error_print();
		return -1;
	}
	return 1;
}

int tls_socket_bind(tls_socket_t sock, const struct sockaddr_in *addr)
{
	socklen_t addr_len = (socklen_t)sizeof(struct sockaddr_in);
	if (bind(sock, (const struct sockaddr *)addr, addr_len) == -1) {
		fprintf(stderr, "%s %d: socket bind error: %s\n", __FILE__, __LINE__, strerror(errno));
		error_print();
		return -1;
	}
	return 1;
}

int tls_socket_listen(tls_socket_t sock, int backlog)
{
	if (listen(sock, backlog) == -1) {
		fprintf(stderr, "%s %d: socket listen error: %s\n", __FILE__, __LINE__, strerror(errno));
		error_print();
		return -1;
	}
	return 1;
}

int tls_socket_accept(tls_socket_t sock, struct sockaddr_in *addr, tls_socket_t *conn_sock)
{
	socklen_t addr_len = (socklen_t)sizeof(struct sockaddr_in);
	if ((*conn_sock = accept(sock, (struct sockaddr *)addr, &addr_len)) == -1) {
		fprintf(stderr, "%s %d: accept: %s\n", __FILE__, __LINE__, strerror(errno));
		error_print();
		return -1;
	}
	return 1;
}
#endif
