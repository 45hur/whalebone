#include <string.h>

#include "crc64.h"
#include "file_loader.h"
#include "ipranger.h"
#include "thread_shared.h"
#include "log.h"
#include "program.h"

void load_lmdb(char *filename)
{
	debugLog("\"method\":\"load_lmdb\",\"message\":\"started loading file\",\"dir\":\"%s\"", filename);

	MDB_env *newenv = NULL;
	if ((newenv = iprg_init_DB_env(newenv, filename, true)) == NULL)
	{
		debugLog("\"method\":\"load_lmdb\",\"message\":\"unable to init domain LMDB\"");
	}
	else
	{
		MDB_env *old = env_domains;
		env_domains = newenv;

		debugLog("\"method\":\"load_lmdb\",\"message\":\"unloading old domain LMDB\"");
		iprg_close_DB_env(old);
		old = NULL;
	}
}