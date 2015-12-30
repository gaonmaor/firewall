/**
 * hash_table.c                     
 * Made by:        Maor Gaon 301308821                                 
 * Created:        1/8/2009                                  
 * Last Modified:  11/3/2014                                 
 */

#include "fw_common.h"
#include "tcp_conn_handler.h"
#include "connection_table.h"
#include "hash_table.h"

hash_table_t
hash_table_create(void)
{ 
	hash_table_t new_hash;
	new_hash = (hash_table_t)hash_malloc(
		MAX_HASH_ELEMENTS * sizeof(struct hash_node_t *));
	if(new_hash) {
		memset(new_hash, 0, MAX_HASH_ELEMENTS * 
			sizeof(struct hash_node_t *));
	}
	return new_hash;
}

void
hash_table_destroy(hash_table_t hash)
{
	hash_table_destroy_free(hash, 0);
}

void
hash_table_clear(hash_table_t hash)
{
	hash_table_clear_free(hash, 0);
}

void
hash_table_destroy_free(hash_table_t hash, data_destroy_func destroy)
{
	hash_table_clear_free(hash, destroy);
	if(hash) {
		hash_free(hash);
	}
}

void
hash_table_clear_free(hash_table_t hash, data_destroy_func destroy)
{
	unsigned int        hash_code;
   	struct hash_node_t* cur_hash;
	struct hash_node_t* next_hash;
	if(hash) {
		for(hash_code = 0; hash_code < MAX_HASH_ELEMENTS; 
			++hash_code) {
			for(cur_hash = hash[hash_code]; cur_hash; 
				cur_hash = next_hash) {
				next_hash = cur_hash->next;
				if(destroy) {
					destroy(cur_hash->key, cur_hash->data);
				}
				hash_free(cur_hash);
			}
			hash[hash_code] = 0;
		}
	}
}

unsigned int
_get_hash_code(const hash_key_t key)
{
	return (unsigned int)key % MAX_HASH_ELEMENTS;
}

/** Allocate new hash node.
 *  Parameters:
 *    key  - The node key.
 *    data - The node data.
 *  Returns: the allocated node or zero if out of memory.
 */
static struct hash_node_t*
hash_table_get_new_node(hash_key_t key, hash_data_t data)
{
	struct hash_node_t* new_hash = 0;
	new_hash = (struct hash_node_t*)(hash_malloc(sizeof(
		struct hash_node_t)));
	if (!new_hash) {
		goto CLEANUP;
	}
	memset(new_hash, 0, sizeof(struct hash_node_t));
	new_hash->key  = key;
	new_hash->data = data;
CLEANUP:
	return new_hash;
}

int
hash_table_set(hash_table_t hash, hash_key_t key, hash_data_t data)
{
	int rv = 1;
	struct hash_node_t* new_hash;
	struct hash_node_t* pre_hash;
	struct hash_node_t* cur_hash;
	int                 hash_code;
	hash_code = get_hash_code(key);
	if (!hash[hash_code]) {
		new_hash = hash_table_get_new_node(key, data);
		if(!new_hash) {
			goto CLEANUP;
		}
		hash[hash_code] = new_hash;
		hash[hash_code]->pre  = 0;
		hash[hash_code]->next = 0;
		rv = 1;
		goto CLEANUP;
	}	
	/* Find the end of the list.
	 *  (stop if a node with the same key is exist.) */
	pre_hash = hash[hash_code];
	for(cur_hash = pre_hash->next; cur_hash; cur_hash = cur_hash->next) {
		/* If there is a node with the same key. */
		if(hash_cmp(cur_hash->key, key)) {
			cur_hash->data = data;
			rv = 1;
			goto CLEANUP;
		}
		pre_hash = cur_hash;
	}
	/* Add the new hase_node. */
	new_hash = hash_table_get_new_node(key, data);
	if(!new_hash) {
		rv = 0;
		goto CLEANUP;
	}
	pre_hash->next = new_hash;
	new_hash->pre = pre_hash;
CLEANUP:
	return rv;
}

hash_data_t
hash_table_get(hash_table_t hash, const hash_key_t key)
{
    unsigned int          hash_code;
    struct   hash_node_t* cur_hash;
    hash_data_t           data = 0;
    hash_code = get_hash_code(key);
    if (!hash[hash_code]) {
		goto CLEANUP;
    }
	for (cur_hash = hash[hash_code]; cur_hash; cur_hash = cur_hash->next) {
		if (hash_cmp(cur_hash->key, key)) {
			data = cur_hash->data;
			goto CLEANUP;
		}
	}
CLEANUP:
	return data;
}

int
hash_table_remove(hash_table_t hash, const hash_key_t key)
{
	return hash_table_remove_destroy(hash, key, 0);
}

int
hash_table_remove_destroy(hash_table_t hash, const hash_key_t key,
		data_destroy_func destroy)
{
	int                   rv = 0;
	unsigned int          hash_code;
	struct   hash_node_t* cur_hash;
	hash_code = get_hash_code(key);
	if (!hash[hash_code]) {
		goto CLEANUP;
	}
	for (cur_hash = hash[hash_code]; cur_hash;cur_hash = cur_hash->next) {
		if (hash_cmp(cur_hash->key, key)) {
			if(cur_hash->pre) {
				cur_hash->pre->next = cur_hash->next;
			}
			if(cur_hash->next) {
				cur_hash->next->pre = cur_hash->pre;
			}
			if(cur_hash == hash[hash_code]) {
				hash[hash_code] = cur_hash->next;
			}
			if(cur_hash->data) {
				destroy(cur_hash->key, cur_hash->data);
			}
			hash_free(cur_hash);
			rv = 1;
			goto CLEANUP;
		}
	}
CLEANUP:
	return rv;
}

int
hash_table_contains(hash_table_t hash, const hash_key_t key)
{
    unsigned int        hash_code;
    struct hash_node_t* cur_hash;
    int                 rv = 0;
    hash_code = get_hash_code(key);
    if (!hash || !hash[hash_code]) {
		goto CLEANUP;
    }
	for (cur_hash = hash[hash_code]; cur_hash; cur_hash = cur_hash->next) {
		if (hash_cmp(cur_hash->key, key)) {
			rv = 1;	
			goto CLEANUP;
		}
	}
CLEANUP:
	return rv;
}
