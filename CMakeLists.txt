# If not stated otherwise in this file or this component's Licenses.txt file the
# following copyright and licenses apply:
#
# Copyright 2019 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


cmake_minimum_required(VERSION 3.16)
project(sec_api C CXX)

set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})
set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Set OPENSSL_ROOT_DIR if not found
find_package(OpenSSL REQUIRED)
# Set YAJL_ROOT if not found
find_package(YAJL REQUIRED)

enable_testing()

include_directories(
        ${OPENSSL_INCLUDE_DIR}
        ${YAJL_INCLUDE_DIR}
        src/headers
        src
)

add_compile_options(-DSEC_TARGET_LOCAL
        -Wall
        -Werror
        -Wfatal-errors
        -Wno-unused-result
        -Wno-unused-but-set-variable
        -Wno-unused-value
        -fPIC
        -fdata-sections
        -ffunction-sections
        -pthread
        -Os
        -DSEC_PLATFORM_OPENSSL
        -DYAJL_V2)

add_library(sec_api STATIC
        src/headers/sec_security.h
        src/headers/sec_security_comcastids.h
        src/headers/sec_security_common.h
        src/headers/sec_security_datatype.h
        src/outprot.cpp
        src/outprot.h
        src/outprot_mock.cpp
        src/sec_pubops.h
        src/sec_pubops_openssl.c
        src/sec_security_asn1kc.c
        src/sec_security_asn1kc.h
        src/sec_security_buffer.c
        src/sec_security_common.c
        src/sec_security_endian.c
        src/sec_security_engine.c
        src/sec_security_json.h
        src/sec_security_json_yajl.c
        src/sec_security_jtype.c
        src/sec_security_jtype.h
        src/sec_security_logger.c
        src/sec_security_mutex.c
        src/sec_security_mutex.h
        src/sec_security_openssl.c
        src/sec_security_openssl.h
        src/sec_security_outprot.c
        src/sec_security_outprot.h
        src/sec_security_shm.c
        src/sec_security_shm.h
        src/sec_security_store.c
        src/sec_security_store.h
        src/sec_security_strptime.c
        src/sec_security_utils.c
        src/sec_security_utils.h
        src/sec_security_utils_b64.c
        src/sec_security_utils_time.c
        src/sec_version.h
        )

target_link_libraries(sec_api
        PRIVATE
        ${OPENSSL_CRYPTO_LIBRARY}
        )

add_executable(sec_api_test
        test/main/cpp/bundle.cpp
        test/main/cpp/bundle.h
        test/main/cpp/cert.cpp
        test/main/cpp/cert.h
        test/main/cpp/cipher.cpp
        test/main/cpp/cipher.h
        test/main/cpp/concurrent.cpp
        test/main/cpp/concurrent.h
        test/main/cpp/digest.cpp
        test/main/cpp/digest.h
        test/main/cpp/exchange.cpp
        test/main/cpp/exchange.h
        test/main/cpp/jtype.cpp
        test/main/cpp/jtype.h
        test/main/cpp/key.cpp
        test/main/cpp/key.h
        test/main/cpp/keyctrl.cpp
        test/main/cpp/keyctrl.h
        test/main/cpp/mac.cpp
        test/main/cpp/mac.h
        test/main/cpp/processor.cpp
        test/main/cpp/processor.h
        test/main/cpp/random.cpp
        test/main/cpp/random.h
        test/main/cpp/sec_api_utest_main.cpp
        test/main/cpp/sec_api_utest_main.h
        test/main/cpp/sign.cpp
        test/main/cpp/sign.h
        test/main/cpp/svp.cpp
        test/main/cpp/svp.h
        test/main/cpp/test_creds_clear.cpp
        test/main/cpp/test_ctx.cpp
        test/main/cpp/wrapped.cpp
        test/main/cpp/wrapped.h
        test/main/headers/test_creds.h
        test/main/headers/test_ctx.h
        test/openssl/cpp/test_creds_soc.cpp
        )

target_include_directories(sec_api_test
        PRIVATE
        src
        test/main/cpp
        test/main/headers
        )

target_link_libraries(sec_api_test
        PRIVATE
        pthread
        sec_api
        ${OPENSSL_CRYPTO_LIBRARY}
        ${YAJL_LIBRARY}
        )

add_test(sec_api_test sec_api_utest_main)

# 'make install' to the correct locations (provided by GNUInstallDirs).
install(TARGETS sec_api
        ARCHIVE DESTINATION lib
        LIBRARY DESTINATION lib
        RUNTIME DESTINATION bin
        )

install(DIRECTORY headers/ DESTINATION include)
