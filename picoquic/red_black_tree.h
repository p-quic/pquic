
#ifndef PICOQUIC_RED_BLACK_TREE_H
#define PICOQUIC_RED_BLACK_TREE_H


#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <picoquic.h>

/**
 * Highly inspired from Algorithms, Fourth edition, https://algs4.cs.princeton.edu/33balanced/RedBlackBST.java
 */


#define RBT_MAX_DEPTH 70

#define RED true
#define BLACK false



typedef uint64_t rbt_key;
typedef void * rbt_val;

// BST helper node data type
typedef struct rbt_node {
    rbt_key key;           // key
    rbt_val val;           // associated data
    struct rbt_node *left;
    struct rbt_node *right;  // links to left and right subtrees
    bool   color;     // color of parent link
    int size;          // subtree count
} rbt_node_t;

typedef struct __attribute__((__packed__)) {
    rbt_node_t *root;
} red_black_tree_t;




/**
 * Highly inspired from Algorithms, Fourth edition, https://algs4.cs.princeton.edu/33balanced/RedBlackBST.java
 */

int rbt_init(picoquic_cnx_t *cnx, red_black_tree_t *tree);

/**
 * Returns the number of key-value pairs in this symbol table.
 * @return the number of key-value pairs in this symbol table
 */
int rbt_size(picoquic_cnx_t *cnx, red_black_tree_t *tree);

/**
  * Is this symbol table empty?
  * @return {@code true} if this symbol table is empty and {@code false} otherwise
  */
uint64_t rbt_is_empty(picoquic_cnx_t *cnx, red_black_tree_t *tree);


/***************************************************************************
 *  Standard BST search.
 ***************************************************************************/

/**
 * sets out to the value associated with the given key if it is present in the tree
 * @param key the key
 * @return true if the key was present, false otherwise
 */
uint64_t rbt_get(picoquic_cnx_t *cnx, red_black_tree_t *tree, rbt_key key, rbt_val *out);


/**
 * Does the RBT contain the given key?
 * @param key the key
 * @return {@code true} if this symbol table contains {@code key} and
 *     {@code false} otherwise
 */
uint64_t rbt_contains(picoquic_cnx_t *cnx, red_black_tree_t *tree, rbt_key key);


/***************************************************************************
 *  Red-black tree insertion.
 ***************************************************************************/

/**
 * Inserts the specified key-value pair into the symbol table, overwriting the old
 * value with the new value if the symbol table already contains the specified key.
 *
 * @param key the key
 * @param val the value
 */

void rbt_put(picoquic_cnx_t *cnx, red_black_tree_t *tree, rbt_key key, rbt_val val);



/***************************************************************************
 *  Ordered symbol table methods.
 ***************************************************************************/

/**
 * pre: tree not empty
 * Sets the smallest key and its associated val in the symbol table.
 * @return true if found, false if the tree was empty
 */
uint64_t rbt_min(picoquic_cnx_t *cnx, red_black_tree_t *tree, rbt_key *retkey, rbt_val *retval);
/**
 * pre: tree not empty
 * Returns the smallest key in the symbol table.
 * @return the smallest key in the symbol table
 */
rbt_key rbt_min_key(picoquic_cnx_t *cnx, red_black_tree_t *tree);

/**
 * pre: tree not empty
 * Returns the val of the smallest key in the symbol table.
 * @return the val of the smallest key in the symbol table
 */
rbt_val rbt_min_val(picoquic_cnx_t *cnx, red_black_tree_t *tree);


/**
 * pre: tree not empty
 * Returns the largest key in the symbol table.
 * @return the largest key in the symbol table
 */
rbt_key rbt_max_key(picoquic_cnx_t *cnx, red_black_tree_t *tree);

/**
 * pre: tree not empty
 * Returns the val of the largest key in the symbol table.
 * @return the val of the largest key in the symbol table
 */
rbt_val rbt_max_val(picoquic_cnx_t *cnx, red_black_tree_t *tree);


/***************************************************************************
 *  Red-black tree deletion.
 ***************************************************************************/


/**
 * Removes the smallest key and associated value from the symbol table.
 * returns false if the tree is empty
 */
uint64_t rbt_delete_min(picoquic_cnx_t *cnx, red_black_tree_t *tree);


/**
 * Removes the smallest key and associated value from the symbol table.
 * returns false if the tree is empty
 */
uint64_t rbt_delete_and_get_min(picoquic_cnx_t *cnx, red_black_tree_t *tree, rbt_key *res, rbt_val *val);


/**
 * Removes the largest key and associated value from the symbol table.
 * returns false if the tree is empty
 */
uint64_t rbt_delete_and_get_max(picoquic_cnx_t *cnx, red_black_tree_t *tree, rbt_key *res, rbt_val *val);

/**
 * Removes the largest key and associated value from the symbol table.
 * returns false if the tree is empty
 */
uint64_t rbt_delete_max(picoquic_cnx_t *cnx, red_black_tree_t *tree);


/**
     * @pre: the tree must not be empty
     * Returns the smallest key in the symbol table greater than or equal to {@code key}.
     * @param key the key
     * @return the smallest key in the symbol table greater than or equal to {@code key}
     */
uint64_t rbt_ceiling(picoquic_cnx_t *cnx, red_black_tree_t *tree, rbt_key key, rbt_key *out_key, rbt_val *out_val);

/**
     * @pre: the tree must not be empty
     * Returns the smallest key in the symbol table greater than or equal to {@code key}.
     * @param key the key
     * @return the smallest key in the symbol table greater than or equal to {@code key}
     */
uint64_t rbt_ceiling_key(picoquic_cnx_t *cnx, red_black_tree_t *tree, rbt_key key, rbt_key *out_key);

/**
     * @pre: the tree must not be empty
     * Returns the smallest key in the symbol table greater than or equal to {@code key}.
     * @param key the key
     * @return the smallest key in the symbol table greater than or equal to {@code key}
     */
uint64_t rbt_ceiling_val(picoquic_cnx_t *cnx, red_black_tree_t *tree, rbt_key key, rbt_val *out_val);

/**
 * Removes the specified key and its associated value from this symbol table
 * (if the key is in this symbol table).
 *
 * @param  key the key
 */
void rbt_delete(picoquic_cnx_t *cnx, red_black_tree_t *tree, rbt_key key);




#endif //PICOQUIC_RED_BLACK_TREE_H
