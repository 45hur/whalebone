#include <string.h>

#include "log.h"
#include "cache_domains.h"

int cache_domain_contains(MDB_env *env, unsigned long long value, lmdbdomain *item)
{
	MDB_dbi dbi;
	MDB_txn *txn = NULL;
	MDB_cursor *cursor = NULL;
	MDB_val key_r, data_r;

	int rc = 0;
	if ((rc = mdb_txn_begin(env, NULL, MDB_RDONLY, &txn)) != 0)
	{
		return 0;
	}
	if ((rc = mdb_dbi_open(txn, "domain", MDB_DUPSORT, &dbi)) != 0)
	{
		return 0;
	}
	if ((rc = mdb_cursor_open(txn, dbi, &cursor)) != 0)
	{
		return 0;	
	}

	debugLog("\"method\":\"cache_domain_contains\",\"message\":\"get %ull\"", value);
	key_r.mv_size = sizeof(unsigned long long);
	key_r.mv_data = &value;
	data_r.mv_size = 0;
	data_r.mv_data = NULL;
	while ((rc = mdb_cursor_get(cursor, &key_r, &data_r, MDB_SET_KEY)) == 0)
	{
		memcpy(item, data_r.mv_data, data_r.mv_size);
		// debugLog("\"method\":\"cache_domain_contains\",\"size\":\"%x %x %x %X %x\"", ((char *)data_r.mv_data)[0]
		// , ((char *)data_r.mv_data)[1]
		// , ((char *)data_r.mv_data)[2]
		// , ((char *)data_r.mv_data)[3]
		// , ((char *)data_r.mv_data)[4]);		
		// debugLog("\"method\":\"cache_domain_contains\",\"accu\":\"%d\"", item->accuracy);
		// debugLog("\"method\":\"cache_domain_contains\",\"threatTypes\":\"%x\"", item->threatTypes);
		// debugLog("\"method\":\"cache_domain_contains\",\"TT_C_AND_C\":\"%d\"", item->threatTypes & TT_C_AND_C == item->threatTypes);
		// debugLog("\"method\":\"cache_domain_contains\",\"TT_MALWARE\":\"%d\"", item->threatTypes & TT_MALWARE == item->threatTypes);

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