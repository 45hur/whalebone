#pragma once

#ifndef FILELOADER_H
#define FILELOADER_H

#include "thread_shared.h"
#include "program.h"

void load_file(char *filename);
void load_lmdb(char *filename);

#endif