cmake_minimum_required(VERSION 3.20)
project(ECDAT_AST_Engine CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 1. Include CPM package manager
include(cmake/CPM.cmake)

# 2. Pull cpp-tree-sitter wrapper
CPMAddPackage(
  NAME cpp-tree-sitter
  GITHUB_REPOSITORY debasish26/cpp-tree-sitter
  GIT_TAG main
)

# 3. Pull Tree-Sitter Language Grammars (With Named Keywords)
add_grammar_from_repo(
  NAME tree-sitter-cpp
  REPO https://github.com/tree-sitter/tree-sitter-cpp.git
  GIT_TAG v0.20.0
)

add_grammar_from_repo(
  NAME tree-sitter-python
  REPO https://github.com/tree-sitter/tree-sitter-python.git
  GIT_TAG v0.20.0
)

# 4. Create ECDAT Core Static Library
add_library(ecdat_ast_core STATIC
  src/ast_parser.cpp
)

target_include_directories(ecdat_ast_core PUBLIC include)
target_link_libraries(ecdat_ast_core PUBLIC 
  cpp-tree-sitter 
  tree-sitter-cpp 
  tree-sitter-python
)

# 5. Build CLI Executable for Testing
add_executable(ecdat_ast_cli src/main.cpp)
target_link_libraries(ecdat_ast_cli PRIVATE ecdat_ast_core)