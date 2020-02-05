#pragma once
#ifndef SOCKET_SRV_H
#define SOCKET_SRV_H

#include <stdio.h>
#include <string.h>    //strlen
#include <stdlib.h>    //strlen
#include <sys/socket.h>
#include <arpa/inet.h> //inet_addr
#include <unistd.h>    //write
#include <pthread.h> //for threading , link with lpthread
#include <netinet/in.h> //defines AF_INET


#include "cache_domains.h"

void *connection_handler(void *socket_desc);
void *socket_server(void *arg);
void send_message(int logtype, const char *message);

#endif
