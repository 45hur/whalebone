#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>      
#include <unistd.h>

#include "log.h"
#include "cache_matrix.h"

int cache_matrix_contains(MDB_env *env, lmdbmatrixkey *key, lmdbmatrixvalue *item)
{
	MDB_dbi dbi;
	MDB_txn *txn = NULL;
	MDB_cursor *cursor = NULL;
	MDB_val key_r, data_r;

	int rc = 0;
	if ((rc = mdb_txn_begin(env, NULL, MDB_RDONLY, &txn)) != 0)
	{
        debugLog("\"method\":\"cache_matrix_contains\",\"error\":\"%s\"", mdb_strerror(rc));
		return 0;
	}
	if ((rc = mdb_dbi_open(txn, "matrix", MDB_DUPSORT, &dbi)) != 0)
	{
        debugLog("\"method\":\"cache_matrix_contains\",\"error\":\"%s\"", mdb_strerror(rc));
		return 0;
	}
	if ((rc = mdb_cursor_open(txn, dbi, &cursor)) != 0)
	{
        debugLog("\"method\":\"cache_matrix_contains\",\"error\":\"%s\"", mdb_strerror(rc));
		return 0;	
	}

	debugLog("\"method\":\"cache_matrix_contains\",\"message\":\"get %d %d %d %d %d %d\"", key->accuracyAudit, key->accuracyBlock, key->content, key->advertisement, key->legal, key->whitelist, key->blacklist);
	key_r.mv_size = sizeof(lmdbmatrixkey);
	key_r.mv_data = key;
	data_r.mv_size = 0;
	data_r.mv_data = NULL;
	while ((rc = mdb_cursor_get(cursor, &key_r, &data_r, MDB_SET_KEY)) == 0)
	{
		memcpy(&item, &data_r.mv_data, data_r.mv_size);
		debugLog("\"method\":\"cache_matrix_contains\",\"action\":\"%d\"", item->action);
        debugLog("\"method\":\"cache_matrix_contains\",\"answer\":\"%s\"", item->answer);

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