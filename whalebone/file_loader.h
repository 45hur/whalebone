#pragma once

#ifndef FILELOADER_H
#define FILELOADER_H

#include "thread_shared.h"
#include "program.h"

void load_lmdb(MDB_env *env, char *filename);
void load_lmdbs(char *path);

#endif