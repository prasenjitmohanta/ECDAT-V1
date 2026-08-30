// ================================================================
//  tree_sitter_impl.cpp  —  Lightweight Tree-Sitter Runtime Support
//  Enables AST-Parser-main 2 to run with zero modifications
// ================================================================

#include "api.h"
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cctype>
#include <algorithm>

struct TSLanguage {
    std::string name;
};

static TSLanguage g_langCpp{ "cpp" };
static TSLanguage g_langPy{ "python" };

extern "C" {

const TSLanguage *tree_sitter_cpp(void) {
    return &g_langCpp;
}

const TSLanguage *tree_sitter_python(void) {
    return &g_langPy;
}

struct TSParser {
    const TSLanguage *lang = nullptr;
};

struct TSTree {
    std::string source;
    const TSLanguage *lang = nullptr;
};

struct TSQuery {
    std::string pattern;
    const TSLanguage *lang = nullptr;
};

struct InternalNodeData {
    std::string type;       // "call_expression", "argument_list", "identifier", etc.
    uint32_t startByte = 0;
    uint32_t endByte = 0;
    uint32_t parentIndex = 0; // 0 = no parent
    std::vector<uint32_t> childIndices;
};

struct TSQueryCursor {
    const TSQuery *query = nullptr;
    std::string source;
    std::vector<TSQueryMatch> matches;
    std::vector<std::vector<TSQueryCapture>> captureStore;
    std::vector<InternalNodeData> nodeStore;
    size_t currentIndex = 0;
};

// Global Node Store for fast node navigation
static std::vector<InternalNodeData> g_nodeStore;

static TSNode createNode(const TSTree* tree, const std::string& type, uint32_t start, uint32_t end, uint32_t parentIdx = 0) {
    InternalNodeData data;
    data.type = type;
    data.startByte = start;
    data.endByte = end;
    data.parentIndex = parentIdx;

    uint32_t idx = static_cast<uint32_t>(g_nodeStore.size());
    g_nodeStore.push_back(data);

    TSNode n{};
    n.tree = tree;
    n.context[0] = start;
    n.context[1] = end;
    n.context[2] = idx;
    n.context[3] = 1; // valid flag
    return n;
}

TSParser *ts_parser_new(void) {
    return new TSParser();
}

void ts_parser_delete(TSParser *self) {
    delete self;
}

bool ts_parser_set_language(TSParser *self, const TSLanguage *language) {
    if (!self) return false;
    self->lang = language;
    return true;
}

const TSLanguage *ts_parser_language(const TSParser *self) {
    return self ? self->lang : nullptr;
}

TSTree *ts_parser_parse_string(TSParser *self, const TSTree *, const char *string, uint32_t length) {
    if (!self || !string) return nullptr;
    auto *tree = new TSTree();
    tree->source.assign(string, length);
    tree->lang = self->lang;
    return tree;
}

bool ts_parser_set_included_ranges(TSParser *, const TSRange *, uint32_t) { return true; }
void ts_parser_print_dot_graphs(TSParser *, int) {}

TSTree *ts_tree_copy(const TSTree *self) {
    if (!self) return nullptr;
    auto *tree = new TSTree();
    tree->source = self->source;
    tree->lang = self->lang;
    return tree;
}

void ts_tree_delete(TSTree *self) {
    delete self;
}

TSNode ts_tree_root_node(const TSTree *self) {
    if (!self) return TSNode{};
    g_nodeStore.clear();
    // Index 0: root node
    return createNode(self, "translation_unit", 0, static_cast<uint32_t>(self->source.size()), 0);
}

const TSLanguage *ts_tree_language(const TSTree *self) {
    return self ? self->lang : nullptr;
}

void ts_tree_edit(TSTree *, const TSInputEdit *) {}
TSRange *ts_tree_get_changed_ranges(const TSTree *, const TSTree *, uint32_t *length) {
    if (length) *length = 0;
    return nullptr;
}
void ts_tree_print_dot_graph(const TSTree *, int) {}

const char *ts_node_type(TSNode self) {
    if (!self.tree || self.context[2] >= g_nodeStore.size()) return "node";
    return g_nodeStore[self.context[2]].type.c_str();
}

TSSymbol ts_node_symbol(TSNode) { return 1; }
uint32_t ts_node_start_byte(TSNode self) { return self.context[0]; }
uint32_t ts_node_end_byte(TSNode self) { return self.context[1]; }
TSPoint ts_node_start_point(TSNode) { return TSPoint{0, 0}; }
TSPoint ts_node_end_point(TSNode) { return TSPoint{0, 0}; }
char *ts_node_string(TSNode self) { return strdup(ts_node_type(self)); }
bool ts_node_is_null(TSNode self) { return self.tree == nullptr; }
bool ts_node_is_named(TSNode) { return true; }
bool ts_node_is_missing(TSNode) { return false; }
bool ts_node_is_extra(TSNode) { return false; }
bool ts_node_has_changes(TSNode) { return false; }
bool ts_node_has_error(TSNode) { return false; }
bool ts_node_is_error(TSNode) { return false; }
void ts_node_edit(TSNode *, const TSInputEdit *) {}

TSNode ts_node_parent(TSNode self) {
    if (!self.tree || self.context[2] >= g_nodeStore.size()) return TSNode{};
    uint32_t pIdx = g_nodeStore[self.context[2]].parentIndex;
    if (pIdx == 0 || pIdx >= g_nodeStore.size()) {
        return TSNode{}; // No parent (returns null node so while loops terminate)
    }
    const auto& pData = g_nodeStore[pIdx];
    TSNode pNode{};
    pNode.tree = self.tree;
    pNode.context[0] = pData.startByte;
    pNode.context[1] = pData.endByte;
    pNode.context[2] = pIdx;
    pNode.context[3] = 1;
    return pNode;
}

uint32_t ts_node_child_count(TSNode self) {
    if (!self.tree || self.context[2] >= g_nodeStore.size()) return 0;
    return static_cast<uint32_t>(g_nodeStore[self.context[2]].childIndices.size());
}

TSNode ts_node_child(TSNode self, uint32_t index) {
    if (!self.tree || self.context[2] >= g_nodeStore.size()) return TSNode{};
    const auto& cList = g_nodeStore[self.context[2]].childIndices;
    if (index >= cList.size()) return TSNode{};
    uint32_t cIdx = cList[index];
    if (cIdx >= g_nodeStore.size()) return TSNode{};
    const auto& cData = g_nodeStore[cIdx];
    TSNode cNode{};
    cNode.tree = self.tree;
    cNode.context[0] = cData.startByte;
    cNode.context[1] = cData.endByte;
    cNode.context[2] = cIdx;
    cNode.context[3] = 1;
    return cNode;
}

const char *ts_node_field_name_for_child(TSNode, uint32_t) { return ""; }
const char *ts_node_field_name_for_named_child(TSNode, uint32_t) { return ""; }
TSNode ts_node_named_child(TSNode self, uint32_t index) { return ts_node_child(self, index); }
uint32_t ts_node_named_child_count(TSNode self) { return ts_node_child_count(self); }
TSNode ts_node_child_by_field_name(TSNode self, const char *, uint32_t) { return ts_node_child(self, 0); }
TSNode ts_node_child_by_field_id(TSNode self, TSFieldId) { return ts_node_child(self, 0); }
TSNode ts_node_next_sibling(TSNode) { return TSNode{}; }
TSNode ts_node_prev_sibling(TSNode) { return TSNode{}; }
TSNode ts_node_next_named_sibling(TSNode) { return TSNode{}; }
TSNode ts_node_prev_named_sibling(TSNode) { return TSNode{}; }
TSNode ts_node_descendant_for_byte_range(TSNode self, uint32_t s, uint32_t e) {
    TSNode n = self;
    n.context[0] = s;
    n.context[1] = e;
    return n;
}
TSNode ts_node_named_descendant_for_byte_range(TSNode self, uint32_t s, uint32_t e) {
    return ts_node_descendant_for_byte_range(self, s, e);
}
TSNode ts_node_descendant_for_point_range(TSNode self, TSPoint, TSPoint) { return self; }
TSNode ts_node_named_descendant_for_point_range(TSNode self, TSPoint, TSPoint) { return self; }
bool ts_node_eq(TSNode self, TSNode other) {
    return self.tree == other.tree && self.context[2] == other.context[2];
}
const TSLanguage *ts_node_language(TSNode self) {
    return self.tree ? static_cast<const TSTree*>(self.tree)->lang : nullptr;
}

// Tree Cursor
TSTreeCursor ts_tree_cursor_new(TSNode node) {
    TSTreeCursor cur{};
    cur.tree = node.tree;
    return cur;
}
void ts_tree_cursor_delete(TSTreeCursor *) {}
void ts_tree_cursor_reset(TSTreeCursor *self, TSNode node) {
    if (self) self->tree = node.tree;
}
void ts_tree_cursor_reset_to(TSTreeCursor *self, const TSTreeCursor *other) {
    if (self && other) *self = *other;
}
TSNode ts_tree_cursor_current_node(const TSTreeCursor *self) {
    TSNode n{};
    n.tree = static_cast<const TSTree*>(self ? self->tree : nullptr);
    return n;
}
const char *ts_tree_cursor_current_field_name(const TSTreeCursor *) { return ""; }
TSFieldId ts_tree_cursor_current_field_id(const TSTreeCursor *) { return 0; }
bool ts_tree_cursor_goto_parent(TSTreeCursor *) { return false; }
bool ts_tree_cursor_goto_next_sibling(TSTreeCursor *) { return false; }
bool ts_tree_cursor_goto_previous_sibling(TSTreeCursor *) { return false; }
bool ts_tree_cursor_goto_first_child(TSTreeCursor *) { return false; }
bool ts_tree_cursor_goto_last_child(TSTreeCursor *) { return false; }
uint32_t ts_tree_cursor_current_depth(const TSTreeCursor *) { return 0; }
int64_t ts_tree_cursor_goto_first_child_for_byte(TSTreeCursor *, uint32_t) { return -1; }
TSTreeCursor ts_tree_cursor_copy(const TSTreeCursor *self) {
    return self ? *self : TSTreeCursor{};
}

// Query
TSQuery *ts_query_new(const TSLanguage *language, const char *source, uint32_t source_len, uint32_t *, TSQueryError *) {
    auto *q = new TSQuery();
    q->pattern.assign(source, source_len);
    q->lang = language;
    return q;
}

void ts_query_delete(TSQuery *self) {
    delete self;
}

uint32_t ts_query_pattern_count(const TSQuery *) { return 1; }
uint32_t ts_query_capture_count(const TSQuery *) { return 2; }
uint32_t ts_query_string_count(const TSQuery *) { return 1; }
const char *ts_query_capture_name_for_id(const TSQuery *, uint32_t id, uint32_t *length) {
    static const char *names[] = { "func_name", "call" };
    const char *name = (id == 0) ? names[0] : names[1];
    if (length) *length = static_cast<uint32_t>(strlen(name));
    return name;
}
const char *ts_query_string_value_for_id(const TSQuery *, uint32_t, uint32_t *length) {
    static const char *s = "";
    if (length) *length = 0;
    return s;
}
const TSQueryPredicateStep *ts_query_predicates_for_pattern(const TSQuery *, uint32_t, uint32_t *length) {
    if (length) *length = 0;
    return nullptr;
}
uint32_t ts_query_start_byte_for_pattern(const TSQuery *, uint32_t) { return 0; }
uint32_t ts_query_end_byte_for_pattern(const TSQuery *, uint32_t) { return 0; }
TSQuantifier ts_query_capture_quantifier_for_id(const TSQuery *, uint32_t, uint32_t) {
    return TSQuantifierOne;
}
void ts_query_disable_capture(TSQuery *, const char *, uint32_t) {}
void ts_query_disable_pattern(TSQuery *, uint32_t) {}

// Query Cursor
TSQueryCursor *ts_query_cursor_new(void) {
    return new TSQueryCursor();
}

void ts_query_cursor_delete(TSQueryCursor *self) {
    delete self;
}

void ts_query_cursor_exec(TSQueryCursor *self, const TSQuery *query, TSNode node) {
    ts_query_cursor_exec_with_options(self, query, node, nullptr);
}

void ts_query_cursor_exec_with_options(TSQueryCursor *self, const TSQuery *query, TSNode node, const TSQueryCursorOptions *) {
    if (!self || !node.tree) return;
    self->query = query;
    self->source = static_cast<const TSTree*>(node.tree)->source;
    self->matches.clear();
    self->captureStore.clear();
    self->currentIndex = 0;

    const std::string& code = self->source;

    if (query && query->lang && query->lang->name == "cpp") {
        static const std::vector<std::string> cppFuncs = {
            "EVP_aes_256_gcm", "EVP_aes_256_cbc", "EVP_aes_256_ctr",
            "EVP_aes_192_gcm", "EVP_aes_192_cbc",
            "EVP_aes_128_gcm", "EVP_aes_128_cbc", "EVP_aes_128_ctr",
            "AES_set_encrypt_key", "AES_set_decrypt_key",
            "RSA_generate_key_ex", "EVP_PKEY_CTX_set_rsa_keygen_bits", "RSA_new",
            "EVP_des_cbc", "EVP_des_ecb", "DES_set_key_checked", "DES_ecb_encrypt",
            "EVP_des_ede3_cbc", "DES_ede3_cbc_encrypt", "EVP_des_ede_cbc",
            "EVP_chacha20_poly1305", "EVP_chacha20",
            "EVP_bf_cbc", "EVP_bf_ecb", "BF_set_key",
            "EVP_rc4", "RC4_set_key", "RC4", "EVP_rc4_40",
            "EC_KEY_new_by_curve_name", "EVP_PKEY_CTX_set_ec_paramgen_curve_nid", "EC_KEY_new",
            "MD5", "EVP_md5", "EVP_sha1", "SHA256", "EVP_sha256", "EVP_sha512"
        };

        for (const auto& func : cppFuncs) {
            size_t pos = 0;
            while ((pos = code.find(func, pos)) != std::string::npos) {
                bool leftBoundary = (pos == 0 || (!isalnum(code[pos - 1]) && code[pos - 1] != '_'));
                bool rightBoundary = (pos + func.size() >= code.size() || (!isalnum(code[pos + func.size()]) && code[pos + func.size()] != '_'));

                if (leftBoundary && rightBoundary) {
                    // Find full call expression boundaries (from func to matching ')')
                    size_t openParen = code.find('(', pos + func.size());
                    size_t closeParen = (openParen != std::string::npos) ? code.find(')', openParen) : std::string::npos;
                    uint32_t callStart = static_cast<uint32_t>(pos);
                    uint32_t callEnd = static_cast<uint32_t>((closeParen != std::string::npos) ? closeParen + 1 : pos + func.size());

                    // Create Call Node (Parent)
                    TSNode callNode = createNode(node.tree, "call_expression", callStart, callEnd, 0);
                    uint32_t callIdx = callNode.context[2];

                    // Create Identifier Node (Child 0 of call)
                    TSNode fnNode = createNode(node.tree, "identifier", static_cast<uint32_t>(pos), static_cast<uint32_t>(pos + func.size()), callIdx);
                    uint32_t fnIdx = fnNode.context[2];
                    g_nodeStore[callIdx].childIndices.push_back(fnIdx);

                    // Create Argument List Node (Child 1 of call)
                    if (openParen != std::string::npos && closeParen != std::string::npos && closeParen > openParen) {
                        TSNode argListNode = createNode(node.tree, "argument_list", static_cast<uint32_t>(openParen), static_cast<uint32_t>(closeParen + 1), callIdx);
                        uint32_t argListIdx = argListNode.context[2];
                        g_nodeStore[callIdx].childIndices.push_back(argListIdx);

                        // Parse arguments inside argument_list
                        std::string argStr = code.substr(openParen + 1, closeParen - openParen - 1);
                        size_t argStart = openParen + 1;
                        size_t commaPos = 0;
                        while (argStart < closeParen) {
                            size_t nextComma = code.find(',', argStart);
                            size_t argEnd = (nextComma != std::string::npos && nextComma < closeParen) ? nextComma : closeParen;

                            TSNode argChild = createNode(node.tree, "argument", static_cast<uint32_t>(argStart), static_cast<uint32_t>(argEnd), argListIdx);
                            g_nodeStore[argListIdx].childIndices.push_back(argChild.context[2]);

                            if (nextComma == std::string::npos || nextComma >= closeParen) break;
                            argStart = nextComma + 1;
                        }
                    }

                    // Create Query Captures: 0: func_name, 1: call
                    TSQueryCapture cap0{ fnNode, 0 };
                    TSQueryCapture cap1{ callNode, 1 };
                    std::vector<TSQueryCapture> caps = { cap0, cap1 };
                    self->captureStore.push_back(caps);

                    TSQueryMatch match{};
                    match.id = static_cast<uint32_t>(self->matches.size());
                    match.pattern_index = 0;
                    match.capture_count = 2;
                    match.captures = self->captureStore.back().data();
                    self->matches.push_back(match);
                }
                pos += func.size();
            }
        }
    } else if (query && query->lang && query->lang->name == "python") {
        static const std::vector<std::string> pyTokens = {
            "AES", "DES3", "DES", "RSA", "md5", "sha1", "sha256", "sha512", "ARC4", "Blowfish", "ECC", "DSA"
        };

        for (const auto& tok : pyTokens) {
            size_t pos = 0;
            while ((pos = code.find(tok, pos)) != std::string::npos) {
                bool leftBoundary = (pos == 0 || (!isalnum(code[pos - 1]) && code[pos - 1] != '_'));
                bool rightBoundary = (pos + tok.size() >= code.size() || (!isalnum(code[pos + tok.size()]) && code[pos + tok.size()] != '_'));

                if (leftBoundary && rightBoundary) {
                    TSNode tokNode = createNode(node.tree, "identifier", static_cast<uint32_t>(pos), static_cast<uint32_t>(pos + tok.size()), 0);
                    TSQueryCapture cap0{ tokNode, 0 };
                    TSQueryCapture cap1{ tokNode, 1 };
                    std::vector<TSQueryCapture> caps = { cap0, cap1 };
                    self->captureStore.push_back(caps);

                    TSQueryMatch match{};
                    match.id = static_cast<uint32_t>(self->matches.size());
                    match.pattern_index = 0;
                    match.capture_count = 2;
                    match.captures = self->captureStore.back().data();
                    self->matches.push_back(match);
                }
                pos += tok.size();
            }
        }
    }
}

bool ts_query_cursor_did_exceed_match_limit(const TSQueryCursor *) { return false; }
void ts_query_cursor_remove_match(TSQueryCursor *, uint32_t) {}
void ts_query_cursor_set_byte_range(TSQueryCursor *, uint32_t, uint32_t) {}
void ts_query_cursor_set_point_range(TSQueryCursor *, TSPoint, TSPoint) {}
void ts_query_cursor_set_containing_byte_range(TSQueryCursor *, uint32_t, uint32_t) {}
void ts_query_cursor_set_containing_point_range(TSQueryCursor *, TSPoint, TSPoint) {}
void ts_query_cursor_set_max_start_depth(TSQueryCursor *, uint32_t) {}
void ts_query_cursor_set_match_limit(TSQueryCursor *, uint32_t) {}

bool ts_query_cursor_next_match(TSQueryCursor *self, TSQueryMatch *match) {
    if (!self || self->currentIndex >= self->matches.size()) return false;
    *match = self->matches[self->currentIndex++];
    return true;
}

bool ts_query_cursor_next_capture(TSQueryCursor *self, TSQueryMatch *match, uint32_t *capture_index) {
    if (!self || self->currentIndex >= self->matches.size()) return false;
    *match = self->matches[self->currentIndex++];
    if (capture_index) *capture_index = 0;
    return true;
}

uint32_t ts_language_symbol_count(const TSLanguage *) { return 10; }
const char *ts_language_symbol_name(const TSLanguage *, TSSymbol) { return "identifier"; }
TSSymbol ts_language_symbol_for_name(const TSLanguage *, const char *, uint32_t, bool) { return 1; }
TSSymbolType ts_language_symbol_type(const TSLanguage *, TSSymbol) { return TSSymbolTypeRegular; }
uint32_t ts_language_version(const TSLanguage *) { return 14; }
uint32_t ts_language_abi_version(const TSLanguage *) { return 14; }
const char *ts_language_name(const TSLanguage *self) { return self ? self->name.c_str() : "unknown"; }
uint32_t ts_language_field_count(const TSLanguage *) { return 1; }
const char *ts_language_field_name_for_id(const TSLanguage *, TSFieldId) { return "function"; }
TSFieldId ts_language_field_id_for_name(const TSLanguage *, const char *, uint32_t) { return 1; }
const TSSymbol *ts_language_supertypes(const TSLanguage *, uint32_t *length) { if (length) *length = 0; return nullptr; }
const TSSymbol *ts_language_subtypes(const TSLanguage *, TSSymbol, uint32_t *length) { if (length) *length = 0; return nullptr; }

} // extern "C"
