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

		if (old != NULL)
		{
			debugLog("\"method\":\"load_lmdb\",\"message\":\"unloading old LMDB\"");
			iprg_close_DB_env(old);
			old = NULL;
		}
	}
}

void load_lmdbs(char *path)
{
	debugLog("\"method\":\"load_lmdbs\",\"message\":\"started loading files\",\"dir\":\"%s\"", path);

	char customlist[260] = { 0 };
	char domains[260] = { 0 };
	char policies[260] = { 0 };
	char ranges[260] = { 0 };
	sprintf(customlist, "%s/custom_lists", path);
	sprintf(domains, "%s/domains", path);
	sprintf(policies, "%s/policies", path);
	sprintf(ranges, "%s/ipranges", path);

	MDB_env *new_customlists = NULL;
	MDB_env *new_domains = NULL;
	MDB_env *new_policies = NULL;
	MDB_env *new_ranges = NULL;
	if ((new_customlists = iprg_init_DB_env(new_customlists, customlist, true)) == NULL
 		|| (new_domains = iprg_init_DB_env(new_domains, domains, true)) == NULL
		|| (new_policies = iprg_init_DB_env(new_policies, policies, true)) == NULL
		|| (new_ranges = iprg_init_DB_env(new_ranges, ranges, true)) == NULL
	)
	{
		debugLog("\"method\":\"load_lmdbs\",\"customlist\":\"%s\"", customlist);
		debugLog("\"method\":\"load_lmdbs\",\"domains\":\"%s\"", domains);
		debugLog("\"method\":\"load_lmdbs\",\"policies\":\"%s\"", policies);
		debugLog("\"method\":\"load_lmdbs\",\"ranges\":\"%s\"", ranges);

		iprg_close_DB_env(new_customlists);
		iprg_close_DB_env(new_domains);
		iprg_close_DB_env(new_policies);
		iprg_close_DB_env(new_ranges);

		debugLog("\"method\":\"load_lmdbs\",\"message\":\"unable to init LMDB %xl %xl %xl %xl\"", new_customlists, new_domains, new_policies, new_ranges);
	}
	else
	{
		MDB_env *old_customlists = env_customlists;
		MDB_env *old_domains = env_domains;
		MDB_env *old_policies = env_policies;
		MDB_env *old_ranges = env_ranges;
		env_customlists = new_customlists;
		env_domains = new_domains;
		env_policies = new_policies;
		env_ranges = new_ranges;

		usleep(1000000);

		if (old_customlists != NULL)
		{
			debugLog("\"method\":\"load_lmdbs\",\"message\":\"unloading old old_customlists LMDB\"");
			iprg_close_DB_env(old_customlists);
		}
		if (old_domains != NULL)
		{
			debugLog("\"method\":\"load_lmdbs\",\"message\":\"unloading old old_domains LMDB\"");
			iprg_close_DB_env(old_domains);
		}
		if (old_policies != NULL)
		{
			debugLog("\"method\":\"load_lmdbs\",\"message\":\"unloading old old_policies LMDB\"");
			iprg_close_DB_env(old_policies);
		}
		if (old_ranges != NULL)
		{
			debugLog("\"method\":\"load_lmdbs\",\"message\":\"unloading old env_ranges LMDB\"");
			iprg_close_DB_env(old_ranges);
		}		
	}
	if (env_radius == NULL && (env_radius = iprg_init_DB_env(env_radius, "/var/whalebone/lmdb/radius", true)) == NULL)
	{
		debugLog("\"method\":\"create\",\"message\":\"unable to init radius LMDB\"");
	}
	if (env_matrix == NULL && (env_matrix = iprg_init_DB_env(env_matrix, "/var/whalebone/lmdb/matrix", true)) == NULL)
	{
		debugLog("\"method\":\"create\",\"message\":\"unable to init matrix LMDB\"");
	}	
}

void load_newest_lmdb()
{
	FILE * file; 
	file = fopen("/var/whalebone/lmdb/dir.dat", "rb"); 
	if (!file) 
	{ 
		debugLog("\"method\":\"%s\",\"error\":\"unable to open dir.dat file\"", __func__); 
		return; 
	} 

	fseek(file, 0L, SEEK_END);
	int sz = ftell(file);
	fseek(file, 0L, SEEK_SET);
	char path[260] = { 0 };
	if (sz >= 260)
	{
		debugLog("\"method\":\"%s\",\"error\":\"dir.dat file is bigger than expected\"", __func__); 
		return;
	}

	int read_result = 0;
	if ((read_result = fread(path, sz, 1, file)) > 0) 
	{ 
		debugLog("\"method\":\"%s\",\"load\":\"%s\"", __func__, path); 
		load_lmdbs(path);
	}
	else
	{
		debugLog("\"method\":\"%s\",\"error\":\"unable to read dir.dat content\"", __func__); 
	}
}