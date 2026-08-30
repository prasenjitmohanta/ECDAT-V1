cmake_minimum_required(VERSION 3.20)
project(ECDAT VERSION 1.0.0 LANGUAGES CXX)

# ── Cross-Platform C++ Standard (C++23 for std::expected & std::to_underlying) ──
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ── Auto-Detect Qt6 on macOS / Linux / Windows ────────────────
if(APPLE)
    list(APPEND CMAKE_PREFIX_PATH
        "/opt/homebrew/opt/qt6"
        "/opt/homebrew/opt/qt@6"
        "/opt/homebrew/opt/qt"
        "/usr/local/opt/qt6"
        "/usr/local/opt/qt@6"
        "/usr/local/opt/qt"
    )
elseif(WIN32)
    file(GLOB QT_PATHS "C:/Qt/6.*/*/lib/cmake" "C:/Qt/Qt6.*/*/lib/cmake" "C:/Qt/6.*/msvc*/lib/cmake" "C:/Qt/6.*/mingw*/lib/cmake")
    list(APPEND CMAKE_PREFIX_PATH ${QT_PATHS})
endif()

# ── Qt Auto-Processors ────────────────────────────────────────
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# ── Find Qt 6 (Core, Widgets, Charts, Svg, Concurrent) ────────
find_package(Qt6 REQUIRED COMPONENTS Core Widgets Charts Svg Concurrent)
if(NOT Qt6_FOUND)
    message(FATAL_ERROR
        "Qt6 not found!\n"
        "Please install Qt6 and set CMAKE_PREFIX_PATH to your Qt directory.\n"
        "macOS:   brew install qt@6\n"
        "Ubuntu:  sudo apt install qt6-base-dev qt6-charts-dev qt6-svg-dev\n"
        "Windows: Install Qt 6 via Qt Online Installer or vcpkg")
endif()
message(STATUS "✓ Found Qt6: ${Qt6_VERSION} (${Qt6_DIR})")

# ── nlohmann/json ─────────────────────────────────────────────
find_package(nlohmann_json QUIET)
if(NOT nlohmann_json_FOUND)
    message(STATUS "nlohmann_json not found via find_package — using bundled headers in thirdparty/")
    include_directories(${CMAKE_SOURCE_DIR}/thirdparty)
endif()

# ── Core Library (Multi-Stage Discovery: AST, YARA, ML Bridge, Mosca) ──
add_library(ecdat_core STATIC
    core/src/MoscaEngine.cpp
    "${CMAKE_SOURCE_DIR}/AST-Parser-main 2/src/ast_parser.cpp"
    "${CMAKE_SOURCE_DIR}/AST-Parser-main 2/src/yara_scanner.cpp"
    "${CMAKE_SOURCE_DIR}/AST-Parser-main 2/src/ml_bridge.cpp"
    thirdparty/tree_sitter/tree_sitter_impl.cpp
)
target_include_directories(ecdat_core PUBLIC
    ${CMAKE_SOURCE_DIR}/core/include
    "${CMAKE_SOURCE_DIR}/AST-Parser-main 2"
    "${CMAKE_SOURCE_DIR}/AST-Parser-main 2/include"
    ${CMAKE_SOURCE_DIR}/thirdparty
)
target_link_libraries(ecdat_core PUBLIC Qt6::Core)
if(nlohmann_json_FOUND)
    target_link_libraries(ecdat_core PUBLIC nlohmann_json::nlohmann_json)
endif()

# ── Qt UI Application ─────────────────────────────────────────
qt6_add_resources(UI_RESOURCES ui/resources/app.qrc)

add_executable(ecdat_app
    # ── Sources ──────────────────────────────────────────────
    ui/src/main.cpp
    ui/src/MainWindow.cpp
    ui/src/RiskGaugeWidget.cpp
    ui/src/CbomTableModel.cpp
    ui/src/ScanWorker.cpp

    # ── Headers (REQUIRED for AUTOMOC to process Q_OBJECT) ───
    ui/include/MainWindow.h
    ui/include/RiskGaugeWidget.h
    ui/include/CbomTableModel.h
    ui/include/ScanWorker.h

    ${UI_RESOURCES}
)

target_include_directories(ecdat_app PRIVATE
    ui/include
    core/include
    "${CMAKE_SOURCE_DIR}/AST-Parser-main 2"
    "${CMAKE_SOURCE_DIR}/AST-Parser-main 2/include"
    ${CMAKE_SOURCE_DIR}/thirdparty
)

target_link_libraries(ecdat_app PRIVATE
    ecdat_core
    Qt6::Core
    Qt6::Widgets
    Qt6::Charts
    Qt6::Svg
    Qt6::Concurrent
)

# ── Platform-Specific Executable Properties ───────────────────
if(WIN32)
    # Hide console in Release builds on Windows
    set_target_properties(ecdat_app PROPERTIES WIN32_EXECUTABLE $<IF:$<CONFIG:Debug>,FALSE,TRUE>)
elseif(APPLE)
    set(MACOSX_BUNDLE_ICON_FILE "ecdat.icns")
    set_source_files_properties("${CMAKE_CURRENT_SOURCE_DIR}/ui/resources/icons/ecdat.icns" PROPERTIES
        MACOSX_PACKAGE_LOCATION "Resources"
    )
    target_sources(ecdat_app PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/ui/resources/icons/ecdat.icns")
    set_target_properties(ecdat_app PROPERTIES
        MACOSX_BUNDLE TRUE
        MACOSX_BUNDLE_BUNDLE_NAME "ECDAT"
        MACOSX_BUNDLE_ICON_FILE "ecdat.icns"
        MACOSX_BUNDLE_GUI_IDENTIFIER "org.ecdat.scanner"
        MACOSX_BUNDLE_INFO_PLIST "${CMAKE_CURRENT_SOURCE_DIR}/ui/resources/Info.plist.in"
    )
endif()

# ── Post-Build: Ensure models, ml_engine, and rules are copied to build output directory ──
add_custom_command(TARGET ecdat_app POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:ecdat_app>/models"
    COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:ecdat_app>/ml_engine"
    COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:ecdat_app>/rules"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_SOURCE_DIR}/models/ciphertext_ml_scanner.pkl"
        "$<TARGET_FILE_DIR:ecdat_app>/models/ciphertext_ml_scanner.pkl"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_SOURCE_DIR}/AST-Parser-main 2/ml_engine/predict.py"
        "$<TARGET_FILE_DIR:ecdat_app>/ml_engine/predict.py"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_SOURCE_DIR}/AST-Parser-main 2/rules/crypto_signatures.yar"
        "$<TARGET_FILE_DIR:ecdat_app>/rules/crypto_signatures.yar"
    COMMENT "Bundling ML models, Python engine, and YARA rules with executable"
)

# ── Install Target ────────────────────────────────────────────
install(TARGETS ecdat_app
    BUNDLE DESTINATION .
    RUNTIME DESTINATION bin
)

message(STATUS "ECDAT configured successfully. Run: cmake --build build")
