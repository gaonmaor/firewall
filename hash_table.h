/**
 * hash_table.h
 * Made by:        Maor Gaon 301308821                                
 * Created:        1/8/2009
 */

#ifndef _HASH_TABLE_
#define _HASH_TABLE_

/** Define the max hash if greater hash is requested.
 */
extern const unsigned long MAX_HASH_ELEMENTS;

/** Default functionality - could be change if defined before the include 
    for has_table.h */
#ifndef hash_data_t
#define hash_data_t void*
#endif
#ifndef hash_key_t
#define hash_key_t int
#endif
#ifndef get_hash_code
#define get_hash_code _get_hash_code
#endif
#ifndef hash_cmp
#define hash_cmp(a, b) a == b
#endif
#ifndef hash_malloc
void* malloc (int size);
#define hash_malloc malloc
#endif
#ifndef hash_free
void free (void* ptr);
#define hash_free free
#endif

/**
 * Free the hash_data.
 * Remark: (hash_data must be a pointer.)
 * Parameters:
 *   The key to destroy.
 *   The data to destroy.
 */
typedef void (*data_destroy_func)(hash_key_t, hash_data_t);

struct hash_node_t {
   struct hash_node_t* next;
   struct hash_node_t* pre;
   hash_key_t          key;
   hash_data_t         data;
};

typedef struct hash_node_t** hash_table_t;

/** Create a new hash_table.
 *  Returns: The instance of the new hash_table.
 */
hash_table_t
hash_table_create(void);

/** destroy the hash.
 * Parameters:
 *   hash - The hash to destroy.
 */
void
hash_table_destroy(hash_table_t hash);

/** Clear all of hash elements.
 * Parameters:
 *   hash - The hash to destroy.
 */
void
hash_table_clear(hash_table_t hash);

/** Destroy the hash.
 * Parameters:
 *   hash    - The hash to destroy.
 *   destroy - The function to destroy the elements.
 */
void
hash_table_destroy_free(hash_table_t hash, data_destroy_func destroy);

/** Clear all of hash elements.
 * Parameters:
 *   hash    - The hash to destroy.
 *   destroy - The function to destroy the elements.
 */
void
hash_table_clear_free(hash_table_t hash, data_destroy_func destroy);

/** Gets the hash code for the key.
 * Remark: this is the default implementation.
 * Parameters:
 *   key - The key need to be added.
 * Returns: The location in the array. 
 *           (A number between 0 to MAX_HASH_ELEMENTS)
 */
unsigned int
_get_hash_code(const hash_key_t key);

/** Add a data with a key to the hashtable.
 * Parameters:
 *   hash  - The hash_table.
 *   key   - The key of the data. (The label)
 *   value - The data. (The address)
 * Returns: 1 for success, 0 for failure - out of memory.
 */
int
hash_table_set(hash_table_t hash, hash_key_t key, hash_data_t data);

/** This function return the data for the given key. 
 * Parameters:
 *   hash - The hash_table.
 *   key  - The key fir the data.
 * Returns: The data or NULL if not found.
 */
hash_data_t
hash_table_get(hash_table_t hash, const hash_key_t key);

/** This function remove the data located by the given key.
 * Parameters:
 *   hash - The hash_table.
 *   key  - The key for locating the data.
 * Returns: 1 if removed else 0.
 */
int
hash_table_remove(hash_table_t hash, const hash_key_t key);

/** This function remove the data located by the given key.
 * Parameters:
 *   hash    - The hash_table.
 *   key     - The key for locating the data.
 *   destroy - The function used for freeing the data.
 * Returns: 1 if removed else 0.
 */
int
hash_table_remove_destroy(hash_table_t hash, const hash_key_t key,
		data_destroy_func destroy);

/** This function checks if there is a node connected to that key.               
 * Parameters:
 *   hash - The hash_table.
 *   key  - The key for locating the data.
 */
int
hash_table_contains(hash_table_t hash, const hash_key_t key);

#endif /* _HASH_TABLE_ */
