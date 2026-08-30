#ifndef TREE_SITTER_API_H_
#define TREE_SITTER_API_H_

#ifdef __cplusplus
#include <utility>
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define TREE_SITTER_LANGUAGE_VERSION 14
#define TREE_SITTER_MIN_COMPATIBLE_LANGUAGE_VERSION 13

typedef uint16_t TSSymbol;
typedef uint16_t TSFieldId;
typedef struct TSLanguage TSLanguage;
typedef struct TSParser TSParser;
typedef struct TSTree TSTree;
typedef struct TSQuery TSQuery;
typedef struct TSQueryCursor TSQueryCursor;

typedef enum {
  TSQuantifierZero,
  TSQuantifierZeroOrOne,
  TSQuantifierZeroOrMore,
  TSQuantifierOne,
  TSQuantifierOneOrMore,
} TSQuantifier;

typedef enum {
  TSQueryErrorNone = 0,
  TSQueryErrorSyntax,
  TSQueryErrorNodeType,
  TSQueryErrorField,
  TSQueryErrorCapture,
  TSQueryErrorStructure,
  TSQueryErrorLanguage,
} TSQueryError;

typedef enum {
  TSQueryPredicateStepTypeDone,
  TSQueryPredicateStepTypeCapture,
  TSQueryPredicateStepTypeString,
} TSQueryPredicateStepType;

typedef struct {
  TSQueryPredicateStepType type;
  uint32_t value_id;
} TSQueryPredicateStep;

typedef enum {
  TSSymbolTypeRegular,
  TSSymbolTypeAnonymous,
  TSSymbolTypeSupertype,
  TSSymbolTypeAuxiliary,
} TSSymbolType;

typedef struct {
  uint32_t row;
  uint32_t column;
} TSPoint;

typedef struct {
  TSPoint start_point;
  TSPoint end_point;
  uint32_t start_byte;
  uint32_t end_byte;
} TSRange;

typedef struct {
  uint32_t context[4];
  const void *id;
  const TSTree *tree;
} TSNode;

typedef struct {
  const void *tree;
  const void *id;
  uint32_t context[3];
} TSTreeCursor;

typedef struct {
  TSNode node;
  uint32_t index;
} TSQueryCapture;

typedef struct {
  uint32_t id;
  uint16_t pattern_index;
  uint16_t capture_count;
  const TSQueryCapture *captures;
} TSQueryMatch;

typedef struct {
  void *payload;
  uint32_t current_byte_offset;
} TSQueryCursorState;

typedef bool (*TSQueryProgressCallback)(TSQueryCursorState *state);

typedef struct {
  void *payload;
  TSQueryProgressCallback progress_callback;
} TSQueryCursorOptions;

typedef struct {
  uint32_t start_byte;
  uint32_t old_end_byte;
  uint32_t new_end_byte;
  TSPoint start_point;
  TSPoint old_end_point;
  TSPoint new_end_point;
} TSInputEdit;

// Parser
TSParser *ts_parser_new(void);
void ts_parser_delete(TSParser *self);
bool ts_parser_set_language(TSParser *self, const TSLanguage *language);
const TSLanguage *ts_parser_language(const TSParser *self);
TSTree *ts_parser_parse_string(TSParser *self, const TSTree *old_tree, const char *string, uint32_t length);
bool ts_parser_set_included_ranges(TSParser *self, const TSRange *ranges, uint32_t count);
void ts_parser_print_dot_graphs(TSParser *self, int file_descriptor);

// Tree
TSTree *ts_tree_copy(const TSTree *self);
void ts_tree_delete(TSTree *self);
TSNode ts_tree_root_node(const TSTree *self);
const TSLanguage *ts_tree_language(const TSTree *self);
void ts_tree_edit(TSTree *self, const TSInputEdit *edit);
TSRange *ts_tree_get_changed_ranges(const TSTree *old_tree, const TSTree *new_tree, uint32_t *length);
void ts_tree_print_dot_graph(const TSTree *self, int file_descriptor);

// Node
const char *ts_node_type(TSNode self);
TSSymbol ts_node_symbol(TSNode self);
uint32_t ts_node_start_byte(TSNode self);
uint32_t ts_node_end_byte(TSNode self);
TSPoint ts_node_start_point(TSNode self);
TSPoint ts_node_end_point(TSNode self);
char *ts_node_string(TSNode self);
bool ts_node_is_null(TSNode self);
bool ts_node_is_named(TSNode self);
bool ts_node_is_missing(TSNode self);
bool ts_node_is_extra(TSNode self);
bool ts_node_has_changes(TSNode self);
bool ts_node_has_error(TSNode self);
bool ts_node_is_error(TSNode self);
void ts_node_edit(TSNode *self, const TSInputEdit *edit);
TSNode ts_node_parent(TSNode self);
TSNode ts_node_child(TSNode self, uint32_t child_index);
const char *ts_node_field_name_for_child(TSNode self, uint32_t child_index);
const char *ts_node_field_name_for_named_child(TSNode self, uint32_t named_child_index);
uint32_t ts_node_child_count(TSNode self);
TSNode ts_node_named_child(TSNode self, uint32_t child_index);
uint32_t ts_node_named_child_count(TSNode self);
TSNode ts_node_child_by_field_name(TSNode self, const char *name, uint32_t name_length);
TSNode ts_node_child_by_field_id(TSNode self, TSFieldId field_id);
TSNode ts_node_next_sibling(TSNode self);
TSNode ts_node_prev_sibling(TSNode self);
TSNode ts_node_next_named_sibling(TSNode self);
TSNode ts_node_prev_named_sibling(TSNode self);
TSNode ts_node_descendant_for_byte_range(TSNode self, uint32_t start, uint32_t end);
TSNode ts_node_named_descendant_for_byte_range(TSNode self, uint32_t start, uint32_t end);
TSNode ts_node_descendant_for_point_range(TSNode self, TSPoint start, TSPoint end);
TSNode ts_node_named_descendant_for_point_range(TSNode self, TSPoint start, TSPoint end);
bool ts_node_eq(TSNode self, TSNode other);
const TSLanguage *ts_node_language(TSNode self);

// Tree Cursor
TSTreeCursor ts_tree_cursor_new(TSNode node);
void ts_tree_cursor_delete(TSTreeCursor *self);
void ts_tree_cursor_reset(TSTreeCursor *self, TSNode node);
void ts_tree_cursor_reset_to(TSTreeCursor *self, const TSTreeCursor *other);
TSNode ts_tree_cursor_current_node(const TSTreeCursor *self);
const char *ts_tree_cursor_current_field_name(const TSTreeCursor *self);
TSFieldId ts_tree_cursor_current_field_id(const TSTreeCursor *self);
bool ts_tree_cursor_goto_parent(TSTreeCursor *self);
bool ts_tree_cursor_goto_next_sibling(TSTreeCursor *self);
bool ts_tree_cursor_goto_previous_sibling(TSTreeCursor *self);
bool ts_tree_cursor_goto_first_child(TSTreeCursor *self);
bool ts_tree_cursor_goto_last_child(TSTreeCursor *self);
uint32_t ts_tree_cursor_current_depth(const TSTreeCursor *self);
int64_t ts_tree_cursor_goto_first_child_for_byte(TSTreeCursor *self, uint32_t byte_offset);
TSTreeCursor ts_tree_cursor_copy(const TSTreeCursor *self);

// Query
TSQuery *ts_query_new(const TSLanguage *language, const char *source, uint32_t source_len, uint32_t *error_offset, TSQueryError *error_type);
void ts_query_delete(TSQuery *self);
uint32_t ts_query_pattern_count(const TSQuery *self);
uint32_t ts_query_capture_count(const TSQuery *self);
uint32_t ts_query_string_count(const TSQuery *self);
const char *ts_query_capture_name_for_id(const TSQuery *self, uint32_t index, uint32_t *length);
const char *ts_query_string_value_for_id(const TSQuery *self, uint32_t index, uint32_t *length);
const TSQueryPredicateStep *ts_query_predicates_for_pattern(const TSQuery *self, uint32_t pattern_index, uint32_t *length);
uint32_t ts_query_start_byte_for_pattern(const TSQuery *self, uint32_t pattern_index);
uint32_t ts_query_end_byte_for_pattern(const TSQuery *self, uint32_t pattern_index);
TSQuantifier ts_query_capture_quantifier_for_id(const TSQuery *self, uint32_t pattern_id, uint32_t capture_id);
void ts_query_disable_capture(TSQuery *self, const char *name, uint32_t length);
void ts_query_disable_pattern(TSQuery *self, uint32_t pattern_index);

// Query Cursor
TSQueryCursor *ts_query_cursor_new(void);
void ts_query_cursor_delete(TSQueryCursor *self);
void ts_query_cursor_exec(TSQueryCursor *self, const TSQuery *query, TSNode node);
void ts_query_cursor_exec_with_options(TSQueryCursor *self, const TSQuery *query, TSNode node, const TSQueryCursorOptions *options);
bool ts_query_cursor_did_exceed_match_limit(const TSQueryCursor *self);
void ts_query_cursor_remove_match(TSQueryCursor *self, uint32_t id);
void ts_query_cursor_set_byte_range(TSQueryCursor *self, uint32_t start_byte, uint32_t end_byte);
void ts_query_cursor_set_point_range(TSQueryCursor *self, TSPoint start_point, TSPoint end_point);
void ts_query_cursor_set_containing_byte_range(TSQueryCursor *self, uint32_t start_byte, uint32_t end_byte);
void ts_query_cursor_set_containing_point_range(TSQueryCursor *self, TSPoint start_point, TSPoint end_point);
void ts_query_cursor_set_max_start_depth(TSQueryCursor *self, uint32_t max_start_depth);
void ts_query_cursor_set_match_limit(TSQueryCursor *self, uint32_t limit);
bool ts_query_cursor_next_match(TSQueryCursor *self, TSQueryMatch *match);
bool ts_query_cursor_next_capture(TSQueryCursor *self, TSQueryMatch *match, uint32_t *capture_index);

// Language
uint32_t ts_language_symbol_count(const TSLanguage *self);
const char *ts_language_symbol_name(const TSLanguage *self, TSSymbol symbol);
TSSymbol ts_language_symbol_for_name(const TSLanguage *self, const char *string, uint32_t length, bool is_named);
TSSymbolType ts_language_symbol_type(const TSLanguage *self, TSSymbol symbol);
uint32_t ts_language_version(const TSLanguage *self);
uint32_t ts_language_abi_version(const TSLanguage *self);
const char *ts_language_name(const TSLanguage *self);
uint32_t ts_language_field_count(const TSLanguage *self);
const char *ts_language_field_name_for_id(const TSLanguage *self, TSFieldId id);
TSFieldId ts_language_field_id_for_name(const TSLanguage *self, const char *name, uint32_t name_length);
const TSSymbol *ts_language_supertypes(const TSLanguage *self, uint32_t *length);
const TSSymbol *ts_language_subtypes(const TSLanguage *self, TSSymbol supertype, uint32_t *length);

// Grammars
const TSLanguage *tree_sitter_cpp(void);
const TSLanguage *tree_sitter_python(void);

#ifdef __cplusplus
}
#endif

#endif
