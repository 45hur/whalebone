#pragma once

#ifndef CACHE_DOMAINS_H
#define CACHE_DOMAINS_H

#include <stdio.h>
#include <stdlib.h>
#include <math.h>      
#include <unistd.h>
#include <lmdb.h>

struct lmdbdomain 
{
	unsigned char accuracy : 8;
	unsigned long threatTypes : 32;
	unsigned short legalTypes : 16;
	unsigned long long contentTypes : 64;
};
typedef struct lmdbdomain lmdbdomain;

enum
{
	CT_NONE = 0,
	CT_PORN = 0x01,
	CT_GAMBLING = 0x02,
	CT_AUDIO_VIDEO = 0x04,
	CT_ADVERTISEMENT = 0x08,
	CT_GAMES = 0x10,
	CT_DRUGS = 0x20,
	CT_WEAPONS = 0x40,
	CT_SOCIAL_NETWORKS = 0x80,
	CT_TRACKING = 0x100,
	CT_RACISM = 0x200,
	CT_FAKENEWS = 0x400,
	CT_VIOLENCE = 0x800,
	CT_CHAT = 0x1000,
	CT_TERRORISM = 0x2000,
	CT_CRYPTOMINING = 0x4000
} ContentTypes;

enum
{
	LT_NONE = 0,
	LT_MFCR = 0x01,
	LT_MFSK = 0x02,
	LT_MFBG = 0x04,
	LT_MFAT = 0x08
} LegalTypes;

enum
{
	TT_NONE = 0,
	TT_C_AND_C = 0x01,
	TT_MALWARE = 0x02,
	TT_PHISHING = 0x04,
	TT_BLACKLIST = 0x08,
	TT_EXPLOIT = 0x10,
	TT_SPAM = 0x20,
	TT_COMPROMISED = 0x40,
	TT_CRYPTOMINER = 0x80
} ThreatTypes;

int cache_domain_contains(MDB_env *env, unsigned long long value, lmdbdomain *item);

#endif