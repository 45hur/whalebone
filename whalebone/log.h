#pragma once

#ifndef LOG_H
#define LOG_H

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "thread_shared.h"

#define C_MOD_MUTEX_GLOBAL "mutex.whalebone.kres.module\0"
#define C_MOD_MUTEX_LOCAL "mutex.whalebone.kres.%lx"
#define C_MOD_LOGFILE "/var/log/whalebone/whalebone.log\0"
#define C_MOD_LOGDEBUG "/var/log/whalebone/debug.log\0"
#define C_MOD_LOGAUDIT "/var/log/whalebone/content.log\0"

int logging;
char localmutex[100];

void debugLog(const char *format, ...);
void fileLog(const char *format, ...);
void contentLog(const char *format, ...);
void logEnqueue(int logtype, const char *message);
void *log_proc(void *arg);

#endif