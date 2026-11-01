/*
 * dpma-rs - Open source Digium Phone Module for Asterisk
 *
 * astobj2 glue: objects, containers of named objects, iterators, and the
 * global object holder used for objects handed to C callers.
 *
 * Core Asterisk headers only (compiled into every module).
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "asterisk.h"

#include <ctype.h>
#include <string.h>

#include "asterisk/astobj2.h"
#include "asterisk/utils.h"

/* ------------------------------------------------------------------ */
/* Objects                                                            */
/* ------------------------------------------------------------------ */

void *dpma_glue_ao2_alloc(size_t size, ao2_destructor_fn destructor, int nolock)
{
	return ao2_alloc_options(size, destructor,
		nolock ? AO2_ALLOC_OPT_LOCK_NOLOCK : AO2_ALLOC_OPT_LOCK_MUTEX);
}

int dpma_glue_ao2_ref(void *obj, int delta)
{
	return ao2_ref(obj, delta);
}

int dpma_glue_ao2_lock(void *obj)
{
	return ao2_lock(obj);
}

int dpma_glue_ao2_unlock(void *obj)
{
	return ao2_unlock(obj);
}

/* ------------------------------------------------------------------ */
/* Containers of objects that start with a NUL-terminated name        */
/* ------------------------------------------------------------------ */

/*
 * The hash and compare functions of the original module's phone, line,
 * and other containers: the key is the name at the start of the object,
 * hashed with a case-insensitive djb2 and compared with strcasecmp
 * (strncasecmp for OBJ_SEARCH_PARTIAL_KEY).
 */
static int name_hash(const void *obj, const int flags)
{
	const unsigned char *s = obj;
	unsigned int hash = 5381;

	switch (flags & OBJ_SEARCH_MASK) {
	case OBJ_SEARCH_OBJECT:
	case OBJ_SEARCH_KEY:
		break;
	default:
		return 0;
	}
	if (!*s) {
		return 5381;
	}
	for (; *s; s++) {
		hash = hash * 33 ^ (unsigned char) tolower(*s);
	}
	return hash & 0x7fffffff;
}

static int name_cmp(void *obj, void *arg, int flags)
{
	const char *name = obj;
	const char *key = arg;

	switch (flags & OBJ_SEARCH_MASK) {
	case OBJ_SEARCH_OBJECT:
	case OBJ_SEARCH_KEY:
		return strcasecmp(name, key) ? 0 : CMP_MATCH;
	case OBJ_SEARCH_PARTIAL_KEY:
		return strncasecmp(name, key, strlen(key)) ? 0 : CMP_MATCH;
	default:
		return CMP_MATCH;
	}
}

struct ao2_container *dpma_glue_ao2_named_container(int buckets)
{
	return ao2_container_alloc_hash(AO2_ALLOC_OPT_LOCK_MUTEX, 0, buckets,
		name_hash, NULL, name_cmp);
}

int dpma_glue_ao2_link(struct ao2_container *c, void *obj)
{
	return ao2_link(c, obj);
}

void dpma_glue_ao2_unlink(struct ao2_container *c, void *obj)
{
	ao2_unlink(c, obj);
}

void *dpma_glue_ao2_find_key(struct ao2_container *c, const char *key)
{
	return ao2_find(c, key, OBJ_SEARCH_KEY);
}

/* ------------------------------------------------------------------ */
/* Iterators                                                          */
/* ------------------------------------------------------------------ */

struct ao2_iterator *dpma_glue_ao2_iterator_new(struct ao2_container *c)
{
	struct ao2_iterator *it = ast_malloc(sizeof(*it));

	if (it) {
		*it = ao2_iterator_init(c, 0);
	}
	return it;
}

/* Returns the next object with a reference, or NULL at the end. */
void *dpma_glue_ao2_iterator_next(struct ao2_iterator *it)
{
	return ao2_iterator_next(it);
}

void dpma_glue_ao2_iterator_free(struct ao2_iterator *it)
{
	if (it) {
		ao2_iterator_destroy(it);
		ast_free(it);
	}
}
