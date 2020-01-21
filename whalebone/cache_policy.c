#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>      
#include <unistd.h>

#include "log.h"
#include "cache_policy.h"

int cache_policy_contains(MDB_env *env, char *identity, lmdbpolicy *item)
{
	MDB_dbi dbi;
	MDB_txn *txn = NULL;
	MDB_cursor *cursor = NULL;
	MDB_val key_r, data_r;

	if (identity == NULL || strlen(identity) == 0)
	{
		return 0;
	}

	int rc = 0;
	if ((rc = mdb_txn_begin(env, NULL, MDB_RDONLY, &txn)) != 0)
	{
		return 0;
	}
	if ((rc = mdb_dbi_open(txn, "policy", MDB_DUPSORT, &dbi)) != 0)
	{
		return 0;
	}
	if ((rc = mdb_cursor_open(txn, dbi, &cursor)) != 0)
	{
		return 0;	
	}

	debugLog("\"method\":\"cache_policy_contains\",\"get\":\"%s\"", identity);
	key_r.mv_size = strlen(identity);
	key_r.mv_data = identity;
	data_r.mv_size = 0;
	data_r.mv_data = NULL;
	while ((rc = mdb_cursor_get(cursor, &key_r, &data_r, MDB_SET_KEY)) == 0)
	{
		memcpy(item, data_r.mv_data, data_r.mv_size);
		debugLog("\"method\":\"cache_policy_contains\",\"audit_accuracy\":\"%d\"", item->audit_accuracy);

		mdb_cursor_close(cursor);
		mdb_txn_abort(txn);
		mdb_dbi_close(env, dbi);

		return 1;
	}
	
	
	mdb_cursor_close(cursor);
	mdb_txn_abort(txn);
	mdb_dbi_close(env, dbi);

	return 0;
}