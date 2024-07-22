/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#ifndef GMSSL_SOCKET_H
#define GMSSL_SOCKET_H

#include <string.h> // 用于字符串操作
#include <stdint.h> // 用于定义标准整数类型
#include <errno.h> // 用于定义错误码

#ifdef __cplusplus // 如果是 C++ 编译器，确保这些函数按照 C 语言的方式进行链接，以防止 C++ 名字改编
extern "C" {
#endif



#ifdef WIN32 // 如果是 Windows 系统，包含 Windows 网络套接字库
#pragma comment (lib, "Ws2_32.lib") // 链接 Windows 网络套接字库
#pragma comment (lib, "Mswsock.lib") // 链接 Windows 网络套接字库
#pragma comment (lib, "AdvApi32.lib") // 链接 Windows 网络套接字库

#include <winsock2.h> // Windows 网络套接字库

typedef SOCKET tls_socket_t;  // 定义套接字类型
typedef int tls_ret_t; // 定义套接字返回值类型
typedef int tls_socklen_t; // 定义套接字长度类型


#define tls_socket_send(sock,buf,len,flags)	send(sock,buf,(int)(len),flags) // 定义了一些宏，将 POSIX 风格的套接字函数映射到 Windows API 函数。
#define tls_socket_recv(sock,buf,len,flags)	recv(sock,buf,(int)(len),flags)
#define tls_socket_close(sock)			closesocket(sock)
#define tls_socket_wait()			Sleep(1)

#else // 如果不是 Windows 系统，包含 POSIX 网络套接字库

#include <fcntl.h> // 用于文件控制
#include <netdb.h> // 用于网络数据库操作
#include <arpa/inet.h> // 用于定义互联网操作
#include <sys/types.h> // 用于定义系统调用
#include <sys/socket.h> // 用于定义套接字操作
#include <netinet/in.h> // 用于定义互联网操作
#include <unistd.h> // 用于定义 POSIX 系统调用

typedef int tls_socket_t; // 定义套接字类型
typedef ssize_t tls_ret_t; // 定义套接字返回值类型
typedef socklen_t tls_socklen_t; // 定义套接字长度类型


#define tls_socket_send(sock,buf,len,flags)	send(sock,buf,len,flags) // 数据的发送
#define tls_socket_recv(sock,buf,len,flags)	recv(sock,buf,len,flags) // 数据的接收
#define tls_socket_close(sock)			close(sock) // 关闭套接字
#define tls_socket_wait()			usleep(1000) // 等待 1 毫秒

#endif

int tls_socket_lib_init(void); // 初始化套接字库
int tls_socket_lib_cleanup(void); // 清理套接字库
int tls_socket_create(tls_socket_t *sock, int af, int type, int protocl); // 创建套接字
int tls_socket_connect(tls_socket_t sock, const struct sockaddr_in *addr); // 连接套接字
int tls_socket_bind(tls_socket_t sock, const struct sockaddr_in *addr); // 绑定套接字到指定的地址
int tls_socket_listen(tls_socket_t sock, int backlog); // 将套接字设为监听状态，准备接受连接。
int tls_socket_accept(tls_socket_t sock, struct sockaddr_in *addr, tls_socket_t *conn_sock); // 接受连接请求


#ifdef __cplusplus
}
#endif
#endif
