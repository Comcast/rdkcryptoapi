lib_LIBRARIES = libsec_api.a

include_HEADERS = headers/sec_security_datatype.h
include_HEADERS += headers/sec_security.h
include_HEADERS += headers/sec_security_common.h

libsec_api_a_SOURCES = sec_security_logger.c sec_security_openssl.c sec_security_store.c sec_security_utils.c sec_security_asn1kc.c sec_security_buffer.c sec_security_common.c sec_security_endian.c sec_security_engine.c sec_security_json_yajl.c sec_security_jtype.c sec_security_keyctrl.cpp sec_security_mutex.c sec_security_shm.c sec_security_strptime.c sec_security_utils_b64.c sec_security_utils_time.c

AM_CFLAGS = -DSEC_TARGET_LOCAL -Wall -Werror -Wfatal-errors -Wno-unused-result -Wno-unused-but-set-variable -Wno-unused-value -fPIC -fdata-sections -ffunction-sections -pthread -Os -DSEC_PLATFORM_OPENSSL -DYAJL_V2
AM_CFLAGS += -I./headers/

AM_CXXFLAGS = -DSEC_TARGET_LOCAL -Wall -Werror -Wfatal-errors -Wno-unused-result -Wno-unused-but-set-variable -Wno-unused-value -fPIC -fdata-sections -ffunction-sections -pthread -Os -DSEC_PLATFORM_OPENSSL -DYAJL_V2
AM_CXXFLAGS += -I./headers/
