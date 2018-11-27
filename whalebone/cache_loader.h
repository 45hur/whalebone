#pragma once
#ifndef CACHE_LOADER_H
#define CACHE_LOADER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crc64.h"
#include "thread_shared.h"

char **split(char *line, char sep, int fields);
int parse_addr(struct ip_addr *sa, const char *addr);
int countchar(char separator, char *string);
int loader_loaddomains();
int loader_loadranges();
int loader_loadpolicy();
int loader_loadcustom();
int loader_init();

#endif