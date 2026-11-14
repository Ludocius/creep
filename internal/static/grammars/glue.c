// Entry points creep calls in each grammar module. build.sh compiles this
// file, the tree-sitter runtime and one grammar into a WebAssembly module;
// the go command never compiles it (see foreignAllowed in internal/tools/budget).
//
// The module flattens the parse tree into fixed-size records so the host
// reads one buffer and validates every field instead of walking guest
// pointers.
#include <stdint.h>
#include <stdlib.h>

#include "tree_sitter/api.h"

const TSLanguage *CREEP_LANGUAGE(void);

enum { FLAG_NAMED = 1, FLAG_ERROR = 2, FLAG_MISSING = 4, FLAG_EXTRA = 8 };
enum { ERR_LANGUAGE = -1, ERR_PARSE = -2, ERR_NODES = -3, ERR_MEMORY = -4 };

// Keep in sync with recordWords in internal/static/decode.go.
typedef struct {
  uint32_t symbol, field, flags, parent;
  uint32_t start_byte, end_byte, start_row, start_col, end_row, end_col;
} record;

static record *records;
static uint32_t record_len, record_cap;

__attribute__((export_name("creep_alloc"))) void *creep_alloc(uint32_t n) {
  return malloc(n);
}

__attribute__((export_name("creep_records"))) record *creep_records(void) {
  return records;
}

__attribute__((export_name("creep_symbol_count"))) uint32_t creep_symbol_count(void) {
  return ts_language_symbol_count(CREEP_LANGUAGE());
}

__attribute__((export_name("creep_symbol_name"))) const char *creep_symbol_name(uint32_t symbol) {
  return ts_language_symbol_name(CREEP_LANGUAGE(), (TSSymbol)symbol);
}

__attribute__((export_name("creep_field_count"))) uint32_t creep_field_count(void) {
  return ts_language_field_count(CREEP_LANGUAGE());
}

__attribute__((export_name("creep_field_name"))) const char *creep_field_name(uint32_t field) {
  return ts_language_field_name_for_id(CREEP_LANGUAGE(), (TSFieldId)field);
}

static int grow(void) {
  uint32_t cap = record_cap ? record_cap * 2 : 1024;
  record *grown = realloc(records, (size_t)cap * sizeof(record));
  if (!grown) return 0;
  records = grown;
  record_cap = cap;
  return 1;
}

static uint32_t node_flags(TSNode node) {
  return (ts_node_is_named(node) ? FLAG_NAMED : 0) |
         (ts_node_is_error(node) ? FLAG_ERROR : 0) |
         (ts_node_is_missing(node) ? FLAG_MISSING : 0) |
         (ts_node_is_extra(node) ? FLAG_EXTRA : 0);
}

// push appends the cursor's node and returns its index, or a negative error.
static int32_t push(const TSTreeCursor *cursor, uint32_t parent, uint32_t max) {
  if (record_len >= max) return ERR_NODES;
  if (record_len == record_cap && !grow()) return ERR_MEMORY;
  TSNode node = ts_tree_cursor_current_node(cursor);
  TSPoint start = ts_node_start_point(node);
  TSPoint end = ts_node_end_point(node);
  records[record_len] = (record){
      ts_node_symbol(node), ts_tree_cursor_current_field_id(cursor),
      node_flags(node),     parent,
      ts_node_start_byte(node), ts_node_end_byte(node),
      start.row, start.column, end.row, end.column,
  };
  return (int32_t)record_len++;
}

// walk records the tree in preorder without recursion, so nesting depth in
// the scanned file cannot exhaust the guest stack.
static int32_t walk(TSTreeCursor *cursor, uint32_t max) {
  int32_t cur = push(cursor, UINT32_MAX, max);
  while (cur >= 0) {
    if (ts_tree_cursor_goto_first_child(cursor)) {
      cur = push(cursor, (uint32_t)cur, max);
      continue;
    }
    while (!ts_tree_cursor_goto_next_sibling(cursor)) {
      if (!ts_tree_cursor_goto_parent(cursor)) return (int32_t)record_len;
      cur = (int32_t)records[cur].parent;
    }
    cur = push(cursor, records[cur].parent, max);
  }
  return cur;
}

// creep_parse parses len bytes at src and returns the number of records, or
// a negative error. Records are read with creep_records.
__attribute__((export_name("creep_parse"))) int32_t creep_parse(const char *src, uint32_t len, uint32_t max_nodes) {
  record_len = 0;
  TSParser *parser = ts_parser_new();
  if (!ts_parser_set_language(parser, CREEP_LANGUAGE())) {
    ts_parser_delete(parser);
    return ERR_LANGUAGE;
  }
  TSTree *tree = ts_parser_parse_string(parser, NULL, src, len);
  ts_parser_delete(parser);
  if (!tree) return ERR_PARSE;
  TSTreeCursor cursor = ts_tree_cursor_new(ts_tree_root_node(tree));
  int32_t n = walk(&cursor, max_nodes);
  ts_tree_cursor_delete(&cursor);
  ts_tree_delete(tree);
  return n;
}
