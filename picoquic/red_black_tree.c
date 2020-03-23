

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <picoquic.h>
#include <stdio.h>
#include "red_black_tree.h"
#include "memory.h"
#include "picoquic_internal.h"

/**
 * Highly inspired from Algorithms, Fourth edition, https://algs4.cs.princeton.edu/33balanced/RedBlackBST.java
 */

int rbt_init(picoquic_cnx_t *cnx, red_black_tree_t *tree) {
    memset(tree, 0, sizeof(red_black_tree_t));
    return 0;
}

rbt_node_t *rbt_new_node(picoquic_cnx_t *cnx, rbt_key key, rbt_val val, bool color, int size) {
    rbt_node_t *newnode = my_malloc(cnx, sizeof(rbt_node_t));
    if (!newnode) return NULL;
    memset(newnode, 0, sizeof(rbt_node_t));
    newnode->key = key;
    newnode->val = val;
    newnode->color = color;
    newnode->size = size;
    newnode->left = NULL;
    newnode->right = NULL;
    return newnode;
}

int rbt_destroy_node(picoquic_cnx_t *cnx, rbt_node_t *node) {
    if (!node) return 0;
    my_free(cnx, node);
    return 0;
}


/***************************************************************************
 *  Node helper methods.
 ***************************************************************************/
// is node x red; false if x is null ?
bool is_red(picoquic_cnx_t *cnx, rbt_node_t *x) {
    if (!IS_IN_PLUGIN_MEMORY(cnx->current_plugin, x)) {
        printf("Error: tried to access to node out of plugin memory: %p\n", x);
        return false;
    }
    if (x == NULL) return false;
    return x->color == RED;
}

// number of node in subtree rooted at x; 0 if x is null
int rbt_node_size(picoquic_cnx_t *cnx, rbt_node_t *x) {
    if (!IS_IN_PLUGIN_MEMORY(cnx->current_plugin, x)) {
        printf("Error: tried to access to node out of plugin memory: %p\n", x);
        return 0;
    }
    if (x == NULL) return 0;
    return x->size;
}


/**
 * Returns the number of key-value pairs in this symbol table.
 * @return the number of key-value pairs in this symbol table
 */
int rbt_size(picoquic_cnx_t *cnx, red_black_tree_t *tree) {
    if (!tree)
        return 0;   // should not happen due to the pre
    if (!IS_IN_PLUGIN_MEMORY(cnx->current_plugin, tree)) {
        printf("Error: tried to access to node out of plugin memory: %p\n", tree);
        return 0;
    }
    return rbt_node_size(cnx, tree->root);
}

/**
  * Is this symbol table empty?
  * @return {@code true} if this symbol table is empty and {@code false} otherwise
  */
uint64_t rbt_is_empty(picoquic_cnx_t *cnx, red_black_tree_t *tree) {
    if (!tree)
        return true;   // should not happen due to the pre
    if (!IS_IN_PLUGIN_MEMORY(cnx->current_plugin, tree)) {
        printf("Error: tried to access to node out of plugin memory: %p\n", tree);
        return true;
    }
    return tree->root == NULL;
}

int key_compare(rbt_key a, rbt_key b) {
    if (a < b) return -1;
    if (a > b) return 1;
    return 0;
}



/***************************************************************************
 *  Standard BST search.
 ***************************************************************************/


// value associated with the given key in subtree rooted at x; null if no such key
uint64_t _rbt_get(picoquic_cnx_t *cnx, rbt_node_t *x, rbt_key key, rbt_val *out) {
    while (x != NULL) {
        if (!IS_IN_PLUGIN_MEMORY(cnx->current_plugin, x)) {
            printf("Error: tried to access to node out of plugin memory: %p\n", x);
            return false;
        }
        int cmp = key_compare(key, x->key);
        if      (cmp < 0) x = x->left;
        else if (cmp > 0) x = x->right;
        else               {
            if (out != NULL) {
                *out = x->val;
            }
            return true;
        }
    }
    return false;
}

/**
 * sets out to the value associated with the given key if it is present in the tree
 * @param key the key
 * @return true if the key was present, false otherwise
 */
uint64_t rbt_get(picoquic_cnx_t *cnx, red_black_tree_t *tree, rbt_key key, rbt_val *out) {
    return _rbt_get(cnx, tree->root, key, out);
}


/**
 * Does the RBT contain the given key?
 * @param key the key
 * @return {@code true} if this symbol table contains {@code key} and
 *     {@code false} otherwise
 */
uint64_t rbt_contains(picoquic_cnx_t *cnx, red_black_tree_t *tree, rbt_key key) {
    return rbt_get(cnx, tree, key, NULL);
}



/***************************************************************************
 *  Red-black tree helper functions.
 ***************************************************************************/

// make a left-leaning link lean to the right
rbt_node_t *rbt_rotate_right(picoquic_cnx_t *cnx, rbt_node_t *h) {
    if (!IS_IN_PLUGIN_MEMORY(cnx->current_plugin, h)) {
        printf("Error: tried to access to node out of plugin memory: %p\n", h);
        return NULL;
    }
    // assert (h != null) && isRed(h.left);
    rbt_node_t *x = h->left;
    if (!IS_IN_PLUGIN_MEMORY(cnx->current_plugin, x)) {
        printf("Error: tried to access to node out of plugin memory: %p\n", x);
        return NULL;
    }
    if (!IS_IN_PLUGIN_MEMORY(cnx->current_plugin, x->right)) {
        printf("Error: tried to access to node out of plugin memory: %p\n", x->right);
        return NULL;
    }
    h->left = x->right;
    x->right = h;
    x->color = x->right->color;
    x->right->color = RED;
    x->size = h->size;
    h->size = rbt_node_size(cnx, h->left) + rbt_node_size(cnx, h->right) + 1;
    return x;
}

// make a right-leaning link lean to the left
rbt_node_t *rbt_rotate_left(picoquic_cnx_t *cnx, rbt_node_t *h) {
// assert (h != null) && isRed(h.right);
    if (!IS_IN_PLUGIN_MEMORY(cnx->current_plugin, h)) {
        printf("Error: tried to access to node out of plugin memory: %p\n", h);
        return NULL;
    }
    rbt_node_t *x = h->right;
    if (!IS_IN_PLUGIN_MEMORY(cnx->current_plugin, x)) {
        printf("Error: tried to access to node out of plugin memory: %p\n", x);
        return NULL;
    }
    if (!IS_IN_PLUGIN_MEMORY(cnx->current_plugin, x->left)) {
        printf("Error: tried to access to node out of plugin memory: %p\n", x->left);
        return NULL;
    }
    h->right = x->left;
    x->left = h;
    x->color = x->left->color;
    x->left->color = RED;
    x->size = h->size;
    h->size = rbt_node_size(cnx, h->left) + rbt_node_size(cnx, h->right) + 1;
    return x;
}

// flip the colors of a node and its two children
int rbt_flip_colors(picoquic_cnx_t *cnx, rbt_node_t *h) {
    // h must have opposite color of its two children
    // assert (h != null) && (h.left != null) && (h.right != null);
    // assert (!isRed(h) &&  isRed(h.left) &&  isRed(h.right))
    //    || (isRed(h)  && !isRed(h.left) && !isRed(h.right));
    if (!IS_IN_PLUGIN_MEMORY(cnx->current_plugin, h)) {
        printf("Error: tried to access to node out of plugin memory: %p\n", h);
        return -1;
    }
    if (!IS_IN_PLUGIN_MEMORY(cnx->current_plugin, h->left)) {
        printf("Error: tried to access to node out of plugin memory: %p\n", h->left);
        return -1;
    }
    if (!IS_IN_PLUGIN_MEMORY(cnx->current_plugin, h->right)) {
        printf("Error: tried to access to node out of plugin memory: %p\n", h->right);
        return -1;
    }
    h->color = !h->color;
    h->left->color = !h->left->color;
    h->right->color = !h->right->color;
    return 0;
}

// Assuming that h is red and both h.left and h.left.left
// are black, make h.left or one of its children red.
rbt_node_t *rbt_move_red_left(picoquic_cnx_t *cnx, rbt_node_t *h) {
// assert (h != null);
// assert isRed(h) && !isRed(h.left) && !isRed(h.left.left);

    if (!IS_IN_PLUGIN_MEMORY(cnx->current_plugin, h)) {
        printf("Error: tried to access to node out of plugin memory: %p\n", h);
        return NULL;
    }
    if (!IS_IN_PLUGIN_MEMORY(cnx->current_plugin, h->right)) {
        printf("Error: tried to access to node out of plugin memory: %p\n", h->right);
        return NULL;
    }
    rbt_flip_colors(cnx, h);
    if (is_red(cnx, h->right->left)) {
        h->right = rbt_rotate_right(cnx, h->right);
        h = rbt_rotate_left(cnx, h);
        rbt_flip_colors(cnx, h);
    }
    return h;
}

// Assuming that h is red and both h.right and h.right.left
// are black, make h.right or one of its children red.
rbt_node_t *rbt_move_red_right(picoquic_cnx_t *cnx, rbt_node_t *h) {
// assert (h != null);
// assert isRed(h) && !isRed(h.right) && !isRed(h.right.left);
    if (!IS_IN_PLUGIN_MEMORY(cnx->current_plugin, h)) {
        printf("Error: tried to access to node out of plugin memory: %p\n", h);
        return NULL;
    }
    if (!IS_IN_PLUGIN_MEMORY(cnx->current_plugin, h->left)) {
        printf("Error: tried to access to node out of plugin memory: %p\n", h->left);
        return NULL;
    }
    rbt_flip_colors(cnx, h);
    if (is_red(cnx, h->left->left)) {
        h = rbt_rotate_right(cnx, h);
        rbt_flip_colors(cnx, h);
    }
    return h;
}

// restore red-black tree invariant
rbt_node_t *rbt_balance(picoquic_cnx_t *cnx, rbt_node_t *h) {
// assert (h != null);

    if (!IS_IN_PLUGIN_MEMORY(cnx->current_plugin, h)) {
        printf("Error: tried to access to node out of plugin memory: %p\n", h);
        return NULL;
    }
    if (!IS_IN_PLUGIN_MEMORY(cnx->current_plugin, h->left)) {
        printf("Error: tried to access to node out of plugin memory: %p\n", h->left);
        return NULL;
    }

    if (is_red(cnx, h->right))                      h = rbt_rotate_left(cnx, h);
    if (is_red(cnx, h->left) && is_red(cnx, h->left->left)) h = rbt_rotate_right(cnx, h);
    if (is_red(cnx, h->left) && is_red(cnx, h->right)) rbt_flip_colors(cnx, h);

    h->size = rbt_node_size(cnx, h->left) + rbt_node_size(cnx, h->right) + 1;
    return h;
}




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


// insert the key-value pair in the subtree rooted at h
rbt_node_t *rbt_node_put(picoquic_cnx_t *cnx, rbt_node_t *node, rbt_key key, rbt_val val) {
    if (node == NULL) {
        node = rbt_new_node(cnx, key, val, RED, 1);
        if (!node) {
            printf("Out of memory when creating a new node\n");
            return NULL;
        }
        return node;
    }

    if (!IS_IN_PLUGIN_MEMORY(cnx->current_plugin, node)) {
        printf("Error: tried to access to node out of plugin memory: %p\n", node);
        return NULL;
    }

    if (!IS_IN_PLUGIN_MEMORY(cnx->current_plugin, node->left)) {
        printf("Error: tried to access to node out of plugin memory: %p\n", node->left);
        return NULL;
    }

    int cmp = key_compare(key, node->key);
    if        (cmp < 0) {
        node->left = rbt_node_put(cnx, node->left, key, val);
    } else if (cmp > 0) {
        node->right  = rbt_node_put(cnx, node->right,  key, val);
    } else {
        node->val   = val;
    }

    // fix-up any right-leaning links
    if (is_red(cnx, node->right) && !is_red(cnx, node->left))      node = rbt_rotate_left(cnx, node);
    if (is_red(cnx, node->left)  &&  is_red(cnx, node->left->left)) node = rbt_rotate_right(cnx, node);
    if (is_red(cnx, node->left)  &&  is_red(cnx, node->right)) rbt_flip_colors(cnx, node);
    node->size = rbt_node_size(cnx, node->left) + rbt_node_size(cnx, node->right) + 1;

    // current_node is now the new root of the subtree rooted at node
    return node;
}

void rbt_put(picoquic_cnx_t *cnx, red_black_tree_t *tree, rbt_key key, rbt_val val) {
    if (tree == NULL) {
        return;
    }
    if (!IS_IN_PLUGIN_MEMORY(cnx->current_plugin, tree)) {
        printf("Error: tried to access to node out of plugin memory: %p\n", tree);
        return;
    }
    tree->root = rbt_node_put(cnx, tree->root, key, val);
    tree->root->color = BLACK;
    // assert check();
}










/***************************************************************************
 *  Ordered symbol table methods.
 ***************************************************************************/


// the smallest key in subtree rooted at x; null if no such key
rbt_node_t *rbt_node_min(picoquic_cnx_t *cnx, rbt_node_t *node) {
    rbt_node_t *current_node = node;
    while(current_node) {
        if (!IS_IN_PLUGIN_MEMORY(cnx->current_plugin, current_node)) {
            printf("Error: tried to access to node out of plugin memory: %p\n", current_node);
            return NULL;
        }
        // assert x != null;
        if (current_node->left == NULL) return current_node;
        else                            current_node = current_node->left;
    }
    return NULL;
}

/**
 * pre: tree not empty
 * Sets the smallest key and its associated val in the symbol table.
 * @return true if found, false if the tree was empty
 */
uint64_t rbt_min(picoquic_cnx_t *cnx, red_black_tree_t *tree, rbt_key *retkey, rbt_val *retval) {
    if (tree == NULL) {
        return false;
    }
    if (!IS_IN_PLUGIN_MEMORY(cnx->current_plugin, tree)) {
        printf("Error: tried to access to node out of plugin memory: %p\n", tree);
        return NULL;
    }
    if (rbt_is_empty(cnx, tree)) {
        return false;
    }
    rbt_node_t *min_node = rbt_node_min(cnx, tree->root);
    *retkey = min_node->key;
    *retval = min_node->val;
    return true;
}
/**
 * pre: tree not empty
 * Returns the smallest key in the symbol table.
 * @return the smallest key in the symbol table
 */
rbt_key rbt_min_key(picoquic_cnx_t *cnx, red_black_tree_t *tree) {
    if (!tree)
        return 0;   // should not happen due to the pre
    if (!IS_IN_PLUGIN_MEMORY(cnx->current_plugin, tree)) {
        printf("Error: tried to access to node out of plugin memory: %p\n", tree);
        return 0;
    }
    return rbt_node_min(cnx, tree->root)->key;
}

/**
 * pre: tree not empty
 * Returns the val of the smallest key in the symbol table.
 * @return the val of the smallest key in the symbol table
 */
rbt_val rbt_min_val(picoquic_cnx_t *cnx, red_black_tree_t *tree) {
    if (!tree)
        return 0;   // should not happen due to the pre
    if (!IS_IN_PLUGIN_MEMORY(cnx->current_plugin, tree)) {
        printf("Error: tried to access to node out of plugin memory: %p\n", tree);
        return 0;
    }
    return rbt_node_min(cnx, tree->root)->val;
}

// the largest key in subtree rooted at x; null if no such key
rbt_node_t *rbt_node_max(picoquic_cnx_t *cnx, rbt_node_t *node) {
    rbt_node_t *current_node = node;
    while(current_node) {
        if (!IS_IN_PLUGIN_MEMORY(cnx->current_plugin, current_node)) {
            printf("Error: tried to access to node out of plugin memory: %p\n", current_node);
            return NULL;
        }
        // assert x != null;
        if (current_node->right == NULL) return current_node;
        else                            current_node = current_node->right;
    }
    return NULL;
}

/**
 * pre: tree not empty
 * Returns the largest key in the symbol table.
 * @return the largest key in the symbol table
 */
rbt_key rbt_max_key(picoquic_cnx_t *cnx, red_black_tree_t *tree) {
    if (!tree)
        return 0;   // should not happen due to the pre
    if (!IS_IN_PLUGIN_MEMORY(cnx->current_plugin, tree)) {
        printf("Error: tried to access to node out of plugin memory: %p\n", tree);
        return 0;
    }
    return rbt_node_max(cnx, tree->root)->key;
}

/**
 * pre: tree not empty
 * Returns the val of the largest key in the symbol table.
 * @return the val of the largest key in the symbol table
 */
rbt_val rbt_max_val(picoquic_cnx_t *cnx, red_black_tree_t *tree) {
    if (!tree)
        return 0;   // should not happen due to the pre
    if (!IS_IN_PLUGIN_MEMORY(cnx->current_plugin, tree)) {
        printf("Error: tried to access to node out of plugin memory: %p\n", tree);
        return 0;
    }
    return rbt_node_max(cnx, tree->root)->val;
}


/***************************************************************************
 *  Red-black tree deletion.
 ***************************************************************************/


// delete the key-value pair with the minimum key rooted at h
rbt_node_t *rbt_node_delete_and_get_min(picoquic_cnx_t *cnx, rbt_node_t *node,
                                                                              rbt_key *res, rbt_val *val) {
    if (node == NULL) {
        return NULL;
    }

    if (!IS_IN_PLUGIN_MEMORY(cnx->current_plugin, node)) {
        printf("Error: tried to access to node out of plugin memory: %p\n", node);
        return 0;
    }
    if (node->left == NULL) {   // this is the smallest, let's remove it
        if (res != NULL) {
            *res = node->key;
        }
        if (val != NULL) {
            *val = node->val;
        }
        // destroy the node and release memory
        rbt_destroy_node(cnx, node);
        // !!! if the value is something malloc'd, it will be lost !
        return NULL;
    }

    if (!IS_IN_PLUGIN_MEMORY(cnx->current_plugin, node->left->left)) {
        printf("Error: tried to access to node out of plugin memory: %p\n", node->left->left);
        return 0;
    }

    if (!is_red(cnx, node->left) && !is_red(cnx, node->left->left)) {
        node = rbt_move_red_left(cnx, node);
    }
    node->left = rbt_node_delete_and_get_min(cnx, node->left, res, val);
    return rbt_balance(cnx, node);
}


/**
 * Removes the smallest key and associated value from the symbol table.
 * returns false if the tree is empty
 */
uint64_t rbt_delete_and_get_min(picoquic_cnx_t *cnx, red_black_tree_t *tree, rbt_key *res, rbt_val *val) {
    if (!tree)
        return false;
    if (!IS_IN_PLUGIN_MEMORY(cnx->current_plugin, tree)) {
        printf("Error: tried to access to node out of plugin memory: %p\n", tree);
        return false;
    }
    if (!IS_IN_PLUGIN_MEMORY(cnx->current_plugin, tree->root)) {
        printf("Error: tried to access to node out of plugin memory: %p\n", tree->root);
        return false;
    }
    if (rbt_is_empty(cnx, tree)) {
        return false;
    }
    // if both children of root are black, set root to red
    if (!is_red(cnx, tree->root->left) && !is_red(cnx, tree->root->right))
        tree->root->color = RED;

    tree->root = rbt_node_delete_and_get_min(cnx, tree->root, res, val);
    if (!rbt_is_empty(cnx, tree)) tree->root->color = BLACK;
    return true;
    // assert check();
}

/**
 * Removes the smallest key and associated value from the symbol table.
 * returns false if the tree is empty
 */
inline uint64_t rbt_delete_min(picoquic_cnx_t *cnx, red_black_tree_t *tree) {
    return rbt_delete_and_get_min(cnx, tree, NULL, NULL);
}


// delete the key-value pair with the maximum key rooted at h
rbt_node_t *rbt_node_delete_and_get_max(picoquic_cnx_t *cnx, rbt_node_t *node,
                                         rbt_key *res, rbt_val *val) {
    if (node == NULL) {
        return NULL;
    }

    if (!IS_IN_PLUGIN_MEMORY(cnx->current_plugin, node)) {
        printf("Error: tried to access to node out of plugin memory: %p\n", node);
        return 0;
    }

    if (is_red(cnx, node->left)) {
        node = rbt_rotate_right(cnx, node);
    }
    if (node->right == NULL) {   // this is the largest, let's remove it
        if (res != NULL) {
            *res = node->key;
        }
        if (val != NULL) {
            *val = node->val;
        }
        // destroy the node and release memory
        rbt_destroy_node(cnx, node);
        // !!! if the value is something malloc'd, it will be lost !
        return NULL;
    }

    if (!IS_IN_PLUGIN_MEMORY(cnx->current_plugin, node->right)) {
        printf("Error: tried to access to node out of plugin memory: %p\n", node->right);
        return 0;
    }

    if (!is_red(cnx, node->right) && !is_red(cnx, node->right->left)) {
        node = rbt_move_red_right(cnx, node);
    }
    return rbt_balance(cnx, node);
}

/**
 * Removes the largest key and associated value from the symbol table.
 * returns false if the tree is empty
 */
uint64_t rbt_delete_and_get_max(picoquic_cnx_t *cnx, red_black_tree_t *tree, rbt_key *res, rbt_val *val) {
    if (!tree)
        return false;
    if (!IS_IN_PLUGIN_MEMORY(cnx->current_plugin, tree)) {
        printf("Error: tried to access to node out of plugin memory: %p\n", tree);
        return false;
    }
    if (!IS_IN_PLUGIN_MEMORY(cnx->current_plugin, tree->root)) {
        printf("Error: tried to access to node out of plugin memory: %p\n", tree->root);
        return false;
    }
    if (rbt_is_empty(cnx, tree)) {
        return false;
    }

    // if both children of root are black, set root to red
    if (!is_red(cnx, tree->root->left) && !is_red(cnx, tree->root->right))
        tree->root->color = RED;

    tree->root = rbt_node_delete_and_get_max(cnx, tree->root, res, val);
    if (!rbt_is_empty(cnx, tree)) tree->root->color = BLACK;
    return true;
    // assert check();
}

/**
 * Removes the largest key and associated value from the symbol table.
 * returns false if the tree is empty
 */
uint64_t rbt_delete_max(picoquic_cnx_t *cnx, red_black_tree_t *tree) {
    return rbt_delete_and_get_max(cnx, tree, NULL, NULL);
}

// delete the key-value pair with the given key rooted at h
rbt_node_t *rbt_node_delete(picoquic_cnx_t *cnx, rbt_node_t *node, rbt_key key) {
// assert get(h, key) != null;
    if (node == NULL) {
        return NULL;
    }

    if (!IS_IN_PLUGIN_MEMORY(cnx->current_plugin, node)) {
        printf("Error: tried to access to node out of plugin memory: %p\n", node);
        return 0;
    }

    if (!IS_IN_PLUGIN_MEMORY(cnx->current_plugin, node->left)) {
        printf("Error: tried to access to node out of plugin memory: %p\n", node->left);
        return 0;
    }

    if (key_compare(key, node->key) < 0)  {
        if (!is_red(cnx, node->left) && !is_red(cnx, node->left->left)) {
            node = rbt_move_red_left(cnx, node);
        }
        // search left
        node->left = rbt_node_delete(cnx, node->left, key);
    } else {
        if (is_red(cnx, node->left))
            node = rbt_rotate_right(cnx, node);
        if (key_compare(key, node->key) == 0 && (node->right == NULL)) {  // we found the node and the right child is NULL, let's remove it
            // destroy the node and release memory
            rbt_destroy_node(cnx, node);
            // !!! if the value is something malloc'd, it will be lost !
            return NULL;
        }
        if (!is_red(cnx, node->right) && !is_red(cnx, node->right->left))
            node = rbt_move_red_right(cnx, node);
        if (key_compare(key, node->key) == 0) {
            rbt_node_t *x = rbt_node_min(cnx, node->right);
            node->key = x->key;
            node->val = x->val;
            node->right = rbt_node_delete_and_get_min(cnx, node->right, NULL, NULL);
        }
        else {
            // search right
            node->right = rbt_node_delete(cnx, node->right, key);
        }
    }
    return rbt_balance(cnx, node);
}



// the smallest key in the subtree rooted at x greater than or equal to the given key
rbt_node_t *rbt_node_ceiling(picoquic_cnx_t *cnx, rbt_node_t *node, rbt_key key, rbt_key *out_key, rbt_val *out_val) {

    if (node == NULL) {
        return NULL;
    }

    if (!IS_IN_PLUGIN_MEMORY(cnx->current_plugin, node)) {
        printf("Error: tried to access to node out of plugin memory: %p\n", node);
        return 0;
    }

    int cmp = key_compare(key, node->key);
    if (cmp == 0) {
        return node;
    } else if (cmp > 0) {
        return rbt_node_ceiling(cnx, node->right, key, out_key, out_val);
    }
    rbt_node_t *t = rbt_node_ceiling(cnx, node->left, key, out_key, out_val);
    if (t != NULL) {
        node = t;
    }
    if (out_key) {
        *out_key = node->key;
    }
    if (out_val) {
        *out_val = node->val;
    }
    return node;
}


/**
     * @pre: the tree must not be empty
     * Returns the smallest key in the symbol table greater than or equal to {@code key}.
     * @param key the key
     * @return the smallest key in the symbol table greater than or equal to {@code key}
     */
uint64_t rbt_ceiling(picoquic_cnx_t *cnx, red_black_tree_t *tree, rbt_key key, rbt_key *out_key, rbt_val *out_val) {
    if (!tree)
        return false;
    if (!IS_IN_PLUGIN_MEMORY(cnx->current_plugin, tree)) {
        printf("Error: tried to access to node out of plugin memory: %p\n", tree);
        return false;
    }
    if (rbt_is_empty(cnx, tree))
        return false;
    return rbt_node_ceiling(cnx, tree->root, key, out_key, out_val) != NULL;
}

/**
     * @pre: the tree must not be empty
     * Returns the smallest key in the symbol table greater than or equal to {@code key}.
     * @param key the key
     * @return the smallest key in the symbol table greater than or equal to {@code key}
     */
uint64_t rbt_ceiling_key(picoquic_cnx_t *cnx, red_black_tree_t *tree, rbt_key key, rbt_key *out_key) {
    if (!tree)
        return false;
    if (!IS_IN_PLUGIN_MEMORY(cnx->current_plugin, tree)) {
        printf("Error: tried to access to node out of plugin memory: %p\n", tree);
        return false;
    }
    if (rbt_is_empty(cnx, tree))
        return false;
    return rbt_node_ceiling(cnx, tree->root, key, out_key, NULL);
}
/**
     * @pre: the tree must not be empty
     * Returns the smallest key in the symbol table greater than or equal to {@code key}.
     * @param key the key
     * @return the smallest key in the symbol table greater than or equal to {@code key}
     */
uint64_t rbt_ceiling_val(picoquic_cnx_t *cnx, red_black_tree_t *tree, rbt_key key, rbt_val *out_val) {
    if (!tree)
        return false;
    if (!IS_IN_PLUGIN_MEMORY(cnx->current_plugin, tree)) {
        printf("Error: tried to access to node out of plugin memory: %p\n", tree);
        return false;
    }
    if (rbt_is_empty(cnx, tree))
        return false;
    return rbt_node_ceiling(cnx, tree->root, key, NULL, out_val);
}

/**
 * Removes the specified key and its associated value from this symbol table
 * (if the key is in this symbol table).
 *
 * @param  key the key
 */
void rbt_delete(picoquic_cnx_t *cnx, red_black_tree_t *tree, rbt_key key) {
    if (!tree)
        return;
    if (!IS_IN_PLUGIN_MEMORY(cnx->current_plugin, tree)) {
        printf("Error: tried to access to node out of plugin memory: %p\n", tree);
        return;
    }
    if (!IS_IN_PLUGIN_MEMORY(cnx->current_plugin, tree->root)) {
        printf("Error: tried to access to node out of plugin memory: %p\n", tree->root);
        return;
    }
    if (!rbt_contains(cnx, tree, key)) return;

    // if both children of root are black, set root to red
    if (!is_red(cnx, tree->root->left) && !is_red(cnx, tree->root->right))
        tree->root->color = RED;

    tree->root = rbt_node_delete(cnx, tree->root, key);
    if (!rbt_is_empty(cnx, tree)) tree->root->color = BLACK;
    // assert check();
}


