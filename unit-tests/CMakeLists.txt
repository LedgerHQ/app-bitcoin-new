cmake_minimum_required(VERSION 3.10)

if(${CMAKE_VERSION} VERSION_LESS 3.10)
  cmake_policy(VERSION ${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION})
endif()

# project information
project(unit_tests
  VERSION 0.1
  DESCRIPTION "Unit tests for Ledger Nano application"
  LANGUAGES C)

# guard against bad build-type strings
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Debug")
endif()

include(CTest)
ENABLE_TESTING()

# specify C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED True)
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Wall -pedantic -g -O0 --coverage")

set(GCC_COVERAGE_LINK_FLAGS "--coverage -lgcov")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${GCC_COVERAGE_LINK_FLAGS}")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${GCC_COVERAGE_LINK_FLAGS}")

# guard against in-source builds
if(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})
  message(FATAL_ERROR "In-source builds not allowed. Please make a new directory (called a build directory) and run CMake from there. You may need to remove CMakeCache.txt. ")
endif()

add_compile_definitions(TEST DEBUG=0 SKIP_FOR_CMOCKA PRINTF=printf)

include_directories(../src)
include_directories(mock_includes)
include_directories(libs)

add_executable(test_apdu_parser test_apdu_parser.c)
add_executable(test_base58 test_base58.c)
add_executable(test_bip32 test_bip32.c)
add_executable(test_bitvector test_bitvector.c)
add_executable(test_buffer test_buffer.c)
add_executable(test_format test_format.c)
add_executable(test_display_utils test_display_utils.c)
add_executable(test_parser test_parser.c)
add_executable(test_script test_script.c)
add_executable(test_wallet test_wallet.c)
add_executable(test_write test_write.c)

# add_executable(test_crypto test_crypto.c)

# Mock libraries
add_library(crypto_mocks SHARED libs/crypto_mocks.c)
add_library(sha256 SHARED libs/sha-256.c)

# App's libraries
add_library(apdu_parser SHARED ../src/boilerplate/apdu_parser.c)
add_library(base58 SHARED ../src/common/base58.c)
add_library(bip32 SHARED ../src/common/bip32.c)
add_library(buffer SHARED ../src/common/buffer.c)
add_library(display_utils SHARED ../src/ui/display_utils.c)
add_library(format SHARED ../src/common/format.c)
add_library(parser SHARED ../src/common/parser.c)
add_library(read SHARED ../src/common/read.c)
add_library(script SHARED ../src/common/script.c)
add_library(varint SHARED ../src/common/varint.c)
add_library(wallet SHARED ../src/common/wallet.c)
add_library(write SHARED ../src/common/write.c)

# add_library(crypto SHARED ../src/crypto.c)

# Mock libraries
target_link_libraries(crypto_mocks PUBLIC sha256)

# App's libraries
target_link_libraries(test_apdu_parser PUBLIC cmocka gcov apdu_parser)
target_link_libraries(test_base58 PUBLIC cmocka gcov base58)
target_link_libraries(test_bip32 PUBLIC cmocka gcov bip32 read)
target_link_libraries(test_bitvector PUBLIC cmocka gcov)
target_link_libraries(test_buffer PUBLIC cmocka gcov buffer varint read write bip32)
target_link_libraries(test_display_utils PUBLIC cmocka gcov display_utils)
target_link_libraries(test_format PUBLIC cmocka gcov format)
target_link_libraries(test_parser PUBLIC cmocka gcov parser buffer varint read write bip32)
target_link_libraries(test_script PUBLIC cmocka gcov script buffer varint read write bip32)
target_link_libraries(test_wallet PUBLIC cmocka gcov wallet script buffer varint read write bip32 base58 crypto_mocks)
target_link_libraries(test_write PUBLIC cmocka gcov write)

# target_link_libraries(test_crypto PUBLIC cmocka gcov crypto)
add_test(test_apdu_parser test_apdu_parser)
add_test(test_base58 test_base58)
add_test(test_bip32 test_bip32)
add_test(test_bitvector test_bitvector)
add_test(test_buffer test_buffer)
add_test(test_display_utils test_display_utils)
add_test(test_format test_format)
add_test(test_parser test_parser)
add_test(test_script test_script)
add_test(test_wallet test_wallet)
add_test(test_write test_write)

# add_test(test_crypto test_crypto)
