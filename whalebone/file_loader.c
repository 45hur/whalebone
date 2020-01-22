#include <string.h>

#include "crc64.h"
#include "file_loader.h"
#include "ipranger.h"
#include "thread_shared.h"
#include "log.h"
#include "program.h"

void load_lmdb(MDB_env *env, char *filename)
{
	debugLog("\"method\":\"load_lmdb\",\"message\":\"started loading file\",\"dir\":\"%s\"", filename);

	MDB_env *env_new = NULL;
	if ((env_new = iprg_init_DB_env(env_new, filename, true)) == NULL)
	{
		debugLog("\"method\":\"load_lmdb\",\"message\":\"unable to init LMDB\"");
	}
	else
	{
		MDB_env *old = env;
		env = env_new;

		debugLog("\"method\":\"load_lmdb\",\"message\":\"unloading old  LMDB\"");
		iprg_close_DB_env(old);
		old = NULL;
	}
}