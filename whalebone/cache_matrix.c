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
        debugLog("\"method\":\"cache_matrix_contains\",\"mdb_txn_begin\":\"%s\"", mdb_strerror(rc));
		return 0;
	}
	if ((rc = mdb_dbi_open(txn, "matrix", MDB_DUPSORT, &dbi)) != 0)
	{
        debugLog("\"method\":\"cache_matrix_contains\",\"mdb_dbi_open\":\"%s\"", mdb_strerror(rc));
		return 0;
	}
	if ((rc = mdb_cursor_open(txn, dbi, &cursor)) != 0)
	{
        debugLog("\"method\":\"cache_matrix_contains\",\"mdb_cursor_open\":\"%s\"", mdb_strerror(rc));
		return 0;	
	}

	debugLog("\"method\":\"cache_matrix_contains\",\"message\":\"get %d %d %d %d %d %d %d %d\"", key->accuracyAudit, key->accuracyBlock, key->content, key->advertisement, key->legal, key->whitelist, key->blacklist, key->bypass);
	key_r.mv_size = sizeof(lmdbmatrixkey);
	key_r.mv_data = key;
	data_r.mv_size = 0;
	data_r.mv_data = NULL;
	while ((rc = mdb_cursor_get(cursor, &key_r, &data_r, MDB_SET_KEY)) == 0)
	{
		memcpy(item, data_r.mv_data, data_r.mv_size);
		// debugLog("\"method\":\"cache_matrix_contains\",\"action\":\"%d\"", item->action);
        // debugLog("\"method\":\"cache_matrix_contains\",\"answer\":\"%s\"", item->answer);

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

void cache_matrix_calculate(lmdbdomain *domain, lmdbpolicy *policy, lmdbcustomlist *customlist, lmdbmatrixkey *key)
{
	debugLog("\"method\":\"cache_matrix_calculate\",\"domain->threatTypes\":\"%d\",\"policy->threatTypes\":\"%d\",\"domain->threatTypes & policy->threatTypes\":\"%d\"", domain->threatTypes, policy->threatTypes, domain->threatTypes & policy->threatTypes);
	key->accuracyAudit = (domain->accuracy >= policy->audit_accuracy && domain->threatTypes & policy->threatTypes == policy->threatTypes) ? 1 : 0;
	key->accuracyBlock = (domain->accuracy >= policy->block_accuracy && domain->threatTypes & policy->threatTypes == policy->threatTypes) ? 1 : 0;
	key->content = (domain->contentTypes & policy->contentTypes == policy->contentTypes) ? 1 : 0;
	key->advertisement = (key->content && (
		domain->contentTypes & CT_ADVERTISEMENT
		|| domain->contentTypes & CT_TRACKING)) ? 1 : 0; 
	key->legal = (key->content && (
		domain->legalTypes & LT_MFCR
		|| domain->legalTypes & LT_MFSK
		|| domain->legalTypes & LT_MFBG
		|| domain->legalTypes & LT_MFAT)) ? 1 : 0;
	key->whitelist = (customlist->customlisttypes & CL_WHITELIST) ? 1 : 0;
	key->blacklist = (customlist->customlisttypes & CL_BLACKLIST) ? 1 : 0;
	key->bypass = (customlist->customlisttypes & CL_BYPASS) ? 1 : 0;
}