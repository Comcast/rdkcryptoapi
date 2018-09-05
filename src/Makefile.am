lib_LIBRARIES = libsec_api.a

include_HEADERS = headers/sec_security_datatype.h
include_HEADERS += headers/sec_security.h
include_HEADERS += headers/sec_security_common.h

libsec_api_a_SOURCES = ANY.c INTEGER.c REAL.c asn_codecs_prim.c der_encoder.c sec_security_logger.c Asn1KC.c ISO646String.c RELATIVE-OID.c ber_decoder.c per_decoder.c sec_security_openssl.c Asn1KCAttribute.c NULL.c  T61String.c ber_tlv_length.c per_encoder.c sec_security_store.c BIT_STRING.c NativeEnumerated.c TeletexString.c ber_tlv_tag.c per_opentype.c sec_security_utils.c BMPString.c NativeInteger.c UTCTime.c constr_CHOICE.c per_support.c xer_decoder.c BOOLEAN.c NativeReal.c UTF8String.c constr_SEQUENCE.c xer_encoder.c ENUMERATED.c NumericString.c UniversalString.c constr_SEQUENCE_OF.c sec_security_asn1kc.c xer_support.c GeneralString.c OBJECT_IDENTIFIER.c VideotexString.c constr_SET.c sec_security_buffer.c GeneralizedTime.c OCTET_STRING.c VisibleString.c constr_SET_OF.c sec_security_common.c GraphicString.c ObjectDescriptor.c asn_SEQUENCE_OF.c constr_TYPE.c sec_security_endian.c IA5String.c PrintableString.c asn_SET_OF.c constraints.c sec_security_engine.c sec_security_json_yajl.c sec_security_jtype.c sec_security_keyctrl.cpp sec_security_mutex.c sec_security_shm.c sec_security_strptime.c sec_security_utils_b64.c sec_security_utils_time.c

AM_CFLAGS = -DSEC_TARGET_LOCAL -Wall -Werror -Wfatal-errors -Wno-unused-result -Wno-unused-but-set-variable -Wno-unused-value -fPIC -fdata-sections -ffunction-sections -pthread -Os -DSEC_PLATFORM_OPENSSL -DYAJL_V2
AM_CFLAGS += -I./headers/

AM_CXXFLAGS = -DSEC_TARGET_LOCAL -Wall -Werror -Wfatal-errors -Wno-unused-result -Wno-unused-but-set-variable -Wno-unused-value -fPIC -fdata-sections -ffunction-sections -pthread -Os -DSEC_PLATFORM_OPENSSL -DYAJL_V2
AM_CXXFLAGS += -I./headers/
