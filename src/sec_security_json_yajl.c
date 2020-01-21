/**
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2019 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "sec_security_json.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <yajl/yajl_gen.h>
#include <yajl/yajl_parse.h>

#ifndef SEC_TRACE_JSON
#define SEC_TRACE_JSON 0
#endif

#if SEC_TRACE_JSON
#pragma message "SEC_TRACE_JSON is enabled.  Please disable in production builds."
#endif

#define YAJL_GEN_STRING(yajl_gen, str) \
    yajl_gen_string(yajl_gen, (const unsigned char *) str, strlen(str))

#define CHECKED_YAJL_GEN(yajl_call, yajl_gen_status, label) \
    yajl_gen_status = yajl_call; \
    if (yajl_gen_status_ok != yajl_gen_status) \
    { \
        SEC_LOG_ERROR("%s - status %d", #yajl_call, yajl_gen_status); \
        goto label; \
    }

#define CHECKED_YAJL_PARSE(yajl_call, yajl_status, label, hdl) \
    yajl_status = yajl_call; \
    if (yajl_status_ok != yajl_status) \
    { \
        unsigned char *msg = yajl_get_error(hdl, 1, (const unsigned char *) json, strlen(json)); \
        SEC_LOG_ERROR("%s - status %d: %s", #yajl_call, yajl_status, msg); \
        yajl_free_error(hdl, msg); \
        goto label; \
    }

#define JSON_CHECK_GEN(session) \
    if (session == NULL || session->gen == NULL) \
        return SEC_RESULT_FAILURE;

#define JSON_CHECK_PARSE(session) \
    if (session == NULL || session->handle == NULL) \
        return SEC_RESULT_FAILURE;

#define JSON_ENSURE_INIT() do { if (0 == g_sec_json_inited) SecJson_Init(); } while(0)

typedef enum {
    JVT_STR = 0,
    JVT_OBJ,
    JVT_ARR,
    JVT_NUM
} JsonValType;

struct Sec_JsonVal_struct {
    JsonValType type;
    char *str;
    struct SecJsonValObj_struct *obj;
    struct SecJsonValArr_struct *arr;
};

typedef struct SecJsonValObj_struct {
    char *key;
    Sec_JsonVal *val;
    struct SecJsonValObj_struct *next;
} SecJsonValObj;

typedef struct SecJsonValArr_struct {
    Sec_JsonVal *val;
    struct SecJsonValArr_struct *next;
} SecJsonValArr;

typedef struct SecJsonCtx_struct {
    Sec_JsonVal *val;
    struct SecJsonCtx_struct *prev;
} SecJsonCtx;

struct Sec_JsonGenCtx_struct
{
    yajl_gen gen;
};

struct Sec_JsonParseCtx_struct {
    yajl_handle handle;
    SecJsonCtx *ctx;
    Sec_JsonVal *res;
};

int g_sec_json_inited = 0;

#if !defined(YAJL_V2)
yajl_gen_config g_sec_json_yajl_gen_config;
yajl_parser_config g_sec_json_yajl_parser_config;
#endif

yajl_callbacks g_sec_json_yajl_callbacks_config;

static void SecJsonVal_Free(Sec_JsonVal *val);
static SecJsonValObj* SecJsonVal_GetObj(Sec_JsonVal *val);
static SecJsonValArr* SecJsonVal_GetArr(Sec_JsonVal *val);

#if SEC_TRACE_JSON
static void _Print(Sec_JsonVal *val, int indent) {
    int i;
    SecJsonValArr *arr;
    SecJsonValObj *obj;

    if (val == NULL) {
        SEC_PRINT("null");
        return;
    }

    switch (val->type) {
        case JVT_STR:
            SEC_PRINT("\"%s\"", (val->str == NULL) ? "null" : val->str);
            break;

        case JVT_OBJ:
            SEC_PRINT("{\n");

            obj = SecJsonVal_GetObj(val);

            while (obj != NULL) {
                for (i=0; i<indent+1; ++i) {
                    SEC_PRINT("  ");
                }

                SEC_PRINT("\"%s\": ", obj->key);
                _Print(obj->val, indent + 1);
                SEC_PRINT("\n");
                obj = obj->next;
            }

            for (i=0; i<indent; ++i) {
                SEC_PRINT("  ");
            }
            SEC_PRINT("}");
            break;

        case JVT_ARR:
            SEC_PRINT("[\n");
            arr = SecJsonVal_GetArr(val);

            while (arr != NULL) {
                for (i=0; i<indent+1; ++i) {
                    SEC_PRINT("  ");
                }

                _Print(arr->val, indent + 1);
                SEC_PRINT(",\n");
                arr = arr->next;
            }

            for (i=0; i<indent; ++i) {
                SEC_PRINT("  ");
            }
            SEC_PRINT("]");
            break;

        default:
            break;
    }
}
#endif

#if SEC_TRACE_JSON
static void _PrintJsonVal(Sec_JsonVal *val) {
    SEC_PRINT("SecJsonVal { addr: %08x, ", val);
    if (val == NULL) {
        SEC_PRINT("}");
        return;
    }

    switch (val->type) {
        case JVT_STR:
            SEC_PRINT("str: \"%s\"", (val->str == NULL) ? "null" : val->str);
            break;

        case JVT_OBJ:
            SEC_PRINT("obj: %08x", val->obj);
            break;

        case JVT_ARR:
            SEC_PRINT("arr: %08x", val->arr);
            break;

        default:
            break;
    }

    SEC_PRINT("}");
}

static void _PrintJsonCtx(SecJsonCtx *ctx) {
    if (ctx == NULL) {
        return;
    }

    SEC_PRINT("-> { addr: %08x, val: %08x } ");

    if (ctx->prev != NULL) {
        _PrintJsonCtx(ctx->prev);
    }
}

static void _PrintJsonParseCtx(Sec_JsonParseCtx *parseCtx) {
    SEC_PRINT("ParseCtx { addr: %08x, res: %08x, ctx: ", parseCtx, parseCtx->res);
    _PrintJsonCtx(parseCtx->ctx);
    SEC_PRINT("}");
}

/*
static void _PrintIndent(int num) {
    int i=0;

    for (i=0; i<num; ++i) {
        SEC_PRINT(" ");
    }
}
*/

static void _PrintJsonValArr(SecJsonValArr* arr) {
    if (arr == NULL) {
        return;
    }

    SEC_PRINT("=> { addr: %08x, val: %08x }", arr, arr->val);

    if (arr->next != NULL) {
        _PrintJsonValArr(arr->next);
    }
}

static void _PrintJsonValObj(SecJsonValObj* obj) {
    if (obj == NULL) {
        return;
    }

    SEC_PRINT("=> { addr: %08x, key: %s, val: %08x }", obj, obj->key, obj->val);

    if (obj->next != NULL) {
        _PrintJsonValObj(obj->next);
    }
}

#endif

static SecJsonValObj* SecJsonValObj_New() {
    SecJsonValObj *obj = (SecJsonValObj *) malloc(sizeof(SecJsonValObj));
    if (obj == NULL) {
        SEC_LOG_ERROR("malloc failed");
        return NULL;
    }

    memset(obj, 0, sizeof(SecJsonValObj));

#if SEC_TRACE_JSON
    SEC_PRINT("SecJsonValObj_New: ");
    _PrintJsonValObj(obj);
    SEC_PRINT("\n");
#endif

    return obj;
}

static SecJsonValArr* SecJsonValArr_New() {
    SecJsonValArr *obj = (SecJsonValArr *) malloc(sizeof(SecJsonValArr));
    if (obj == NULL) {
        SEC_LOG_ERROR("malloc failed");
        return NULL;
    }

    memset(obj, 0, sizeof(SecJsonValArr));

#if SEC_TRACE_JSON
    SEC_PRINT("JsonValArr_New: ");
    _PrintJsonValArr(obj);
    SEC_PRINT("\n");
#endif

    return obj;
}

static void SecJsonValObj_Free(SecJsonValObj *obj) {
    if (obj == NULL) {
        return;
    }

#if SEC_TRACE_JSON
    SEC_PRINT("SecJsonValObj_Free: ");
    _PrintJsonValObj(obj);
    SEC_PRINT("\n");
#endif

    SEC_FREE(obj->key);
    SecJsonVal_Free(obj->val);
    SecJsonValObj_Free(obj->next);
    SEC_FREE(obj);
}

static void SecJsonValArr_Free(SecJsonValArr *arr) {
    if (arr == NULL) {
        return;
    }

#if SEC_TRACE_JSON
    SEC_PRINT("SecJsonValArr_Free: ");
    _PrintJsonValArr(arr);
    SEC_PRINT("\n");
#endif

    SecJsonVal_Free(arr->val);
    SecJsonValArr_Free(arr->next);
    SEC_FREE(arr);
}

static SecJsonValArr* SecJsonValArr_Add(SecJsonValArr *arr, Sec_JsonVal *val) {
#if SEC_TRACE_JSON
    SEC_PRINT("SecJsonValArr_Add BEFORE: ");
    _PrintJsonValArr(arr);
    SEC_PRINT("\n");
#endif

    if (arr == NULL) {
        SEC_LOG_ERROR("arr == NULL");
        return NULL;
    }

    SecJsonValArr *last = arr;
    while (last->next != NULL) {
        last = last->next;
    }

    last->next = SecJsonValArr_New();
    if (last->next == NULL) {
        SEC_LOG_ERROR("JsonValArr_New failed");
        return NULL;
    }

    last->next->val = val;

#if SEC_TRACE_JSON
    SEC_PRINT("SecJsonValArr_Add AFTER: ");
    _PrintJsonValArr(arr);
    SEC_PRINT("\n");
#endif

    return arr;
}

static void SecJsonVal_Free(Sec_JsonVal *val) {
    if (val == NULL) {
        return;
    }

#if SEC_TRACE_JSON
    SEC_PRINT("SecJsonVal_Free: ");
    _PrintJsonVal(val);
    SEC_PRINT("\n");
#endif

    SEC_FREE(val->str);
    SecJsonValObj_Free(val->obj);
    SecJsonValArr_Free(val->arr);

    SEC_FREE(val);
}

static char * _copyString(const char *input, SEC_SIZE len) {
    char *output = (char *) malloc(len+1);
    if (output == NULL) {
        SEC_LOG_ERROR("malloc failed");
        return NULL;
    }
    memset(output, 0, len+1);

    strncpy(output, input, len);

    return output;
}

char debug_buffer[1024];
char * _debugString(const char *input, SEC_SIZE len) {
    if (len >= sizeof(debug_buffer)) {
        return (char *) "********";
    }

    memset(debug_buffer, 0, sizeof(debug_buffer));
    strncpy(debug_buffer, input, len);

    return debug_buffer;
}

static Sec_JsonVal* SecJsonVal_NewStr(const char *str, SEC_SIZE len) {
    Sec_JsonVal *val = (Sec_JsonVal *) malloc(sizeof(Sec_JsonVal));
    if (val == NULL) {
        SEC_LOG_ERROR("malloc failed");
        return NULL;
    }

    memset(val, 0, sizeof(Sec_JsonVal));

    val->type = JVT_STR;
    val->str = _copyString(str, len);
    if (val->str == NULL) {
        SecJsonVal_Free(val);
        SEC_LOG_ERROR("_copyString failed");
        return NULL;
    }

#if SEC_TRACE_JSON
    SEC_PRINT("SecJsonVal_NewStr: ");
    _PrintJsonVal(val);
    SEC_PRINT("\n");
#endif

    return val;
}

static Sec_JsonVal* SecJsonVal_NewObj() {
    Sec_JsonVal *val = (Sec_JsonVal *) malloc(sizeof(Sec_JsonVal));
    if (val == NULL) {
        SEC_LOG_ERROR("malloc failed");
        return NULL;
    }
    memset(val, 0, sizeof(Sec_JsonVal));

    val->type = JVT_OBJ;
    val->obj = SecJsonValObj_New();

    if (val->obj == NULL) {
        SecJsonVal_Free(val);
        SEC_LOG_ERROR("SecJsonValObj_New failed");
        return NULL;
    }

#if SEC_TRACE_JSON
    SEC_PRINT("SecJsonVal_NewObj: ");
    _PrintJsonVal(val);
    SEC_PRINT("\n");
#endif

    return val;
}

static SecJsonValObj* SecJsonVal_GetObj(Sec_JsonVal *val) {
    if (val == NULL) {
        SEC_LOG_ERROR("val == NULL");
        return NULL;
    }

    if (val->type != JVT_OBJ) {
        SEC_LOG_ERROR("val has the wrong type");
        return NULL;
    }

    return val->obj;
}

static Sec_JsonVal* SecJsonVal_NewArr() {
    Sec_JsonVal *val = (Sec_JsonVal *) malloc(sizeof(Sec_JsonVal));
    if (val == NULL) {
        SEC_LOG_ERROR("malloc failed");
        return NULL;
    }
    memset(val, 0, sizeof(Sec_JsonVal));

    val->type = JVT_ARR;
    val->arr = SecJsonValArr_New();

    if (val->arr == NULL) {
        SecJsonVal_Free(val);
        SEC_LOG_ERROR("SecJsonValArr_New failed");
        return NULL;
    }

#if SEC_TRACE_JSON
    SEC_PRINT("SecJsonVal_NewArr: ");
    _PrintJsonVal(val);
    SEC_PRINT("\n");
#endif

    return val;
}

static SecJsonValArr* SecJsonVal_GetArr(Sec_JsonVal *val) {
    if (val == NULL) {
        SEC_LOG_ERROR("val == NULL");
        return NULL;
    }

    if (val->type != JVT_ARR) {
        SEC_LOG_ERROR("val has the wrong type");
        return NULL;
    }

    return val->arr;
}

static SecJsonCtx* SecJsonCtx_New(Sec_JsonVal *val) {
    SecJsonCtx *ctx = (SecJsonCtx *) malloc(sizeof(SecJsonCtx));
    if (ctx == NULL) {
        SEC_LOG_ERROR("malloc failed");
        return NULL;
    }
    memset(ctx, 0, sizeof(SecJsonCtx));

    ctx->val = val;

#if SEC_TRACE_JSON
    SEC_PRINT("SecJsonCtx_New: ");
    _PrintJsonCtx(ctx);
    SEC_PRINT("\n");
#endif

    return ctx;
}

static void SecJsonCtx_Free(SecJsonCtx *ctx) {
    if (ctx == NULL) {
        return;
    }

#if SEC_TRACE_JSON
    SEC_PRINT("SecJsonCtx_Free: ");
    _PrintJsonCtx(ctx);
    SEC_PRINT("\n");
#endif

    SecJsonCtx_Free(ctx->prev);
    SEC_FREE(ctx);
}

static int _PopCtx(Sec_JsonParseCtx *session) {
#if SEC_TRACE_JSON
    SEC_PRINT("_PopCtx BEFORE: ");
    _PrintJsonParseCtx(session);
    SEC_PRINT("\n");
#endif

    if (session == NULL) {
        SEC_LOG_ERROR("session == NULL");
        return 0;
    }

    if (session->ctx == NULL) {
        SEC_LOG_ERROR("session->ctx == NULL");
        return 0;
    }

    SecJsonCtx *temp = session->ctx;
    session->ctx = temp->prev;
    temp->prev = NULL;
    SecJsonCtx_Free(temp);

#if SEC_TRACE_JSON
    SEC_PRINT("_PopCtx AFTER: ");
    _PrintJsonParseCtx(session);
    SEC_PRINT("\n");
#endif

    return 1;
}

static int _PushCtx(Sec_JsonParseCtx *session, Sec_JsonVal *val) {
#if SEC_TRACE_JSON
    SEC_PRINT("_PushCtx BEFORE: ");
    _PrintJsonParseCtx(session);
    SEC_PRINT("\n");
#endif

    if (session == NULL) {
        SEC_LOG_ERROR("session == NULL");
        return 0;
    }

    SecJsonCtx *newctx = SecJsonCtx_New(val);
    if (newctx == NULL) {
        SEC_LOG_ERROR("SecJsonCtx_New failed");
        return 0;
    }
    newctx->prev = session->ctx;
    session->ctx = newctx;

#if SEC_TRACE_JSON
    SEC_PRINT("_PushCtx AFTER: ");
    _PrintJsonParseCtx(session);
    SEC_PRINT("\n");
#endif

    return 1;
}

static int _SetValue(Sec_JsonParseCtx *session, Sec_JsonVal *val) {
#if SEC_TRACE_JSON
    SEC_PRINT("_SetValue BEFORE: ");
    _PrintJsonParseCtx(session);
    SEC_PRINT("\n");
#endif

    if (session == NULL) {
        SEC_LOG_ERROR("session == NULL");
        return 0;
    }

    if (session->ctx == NULL) {
        SEC_LOG_ERROR("session->ctx == NULL");
        return 0;
    }

    //a) no existing value
    if (session->ctx->val == NULL) {
        if (session->res != NULL) {
            SEC_LOG_ERROR("res has already been set");
            return 0;
        }

        if (!_PopCtx(session)) {
            SEC_LOG_ERROR("_PopCtx failed");
            return 0;
        }

        session->res = val;

#if SEC_TRACE_JSON
    SEC_PRINT("_SetValue AFTER: ");
    _PrintJsonParseCtx(session);
    SEC_PRINT("\n");
#endif

        return 1;
    }

    //b) obj with key already set
    if (session->ctx->val->type == JVT_OBJ) {
        SecJsonValObj *obj = SecJsonVal_GetObj(session->ctx->val);
        if (obj == NULL) {
            SEC_LOG_ERROR("obj == NULL");
            return 0;
        }

        if (obj->key == NULL) {
            SEC_LOG_ERROR("obj->key == NULL");
            return 0;
        }

        if (obj->val != NULL) {
            SEC_LOG_ERROR("obj->val != NULL");
            return 0;
        }

        obj->val = val;

        //free malloced val
        SEC_TRACE(SEC_TRACE_JSON, "Freeing val %08x", session->ctx->val);
        SEC_FREE(session->ctx->val);

        if (!_PopCtx(session)) {
            SEC_LOG_ERROR("_PopCtx failed");
            return 0;
        }

#if SEC_TRACE_JSON
    SEC_PRINT("_SetValue AFTER: ");
    _PrintJsonParseCtx(session);
    SEC_PRINT("\n");
#endif

        return 1;
    }

    //c) array
    if (session->ctx->val->type == JVT_ARR) {
        SecJsonValArr *arr = SecJsonVal_GetArr(session->ctx->val);
        if (arr == NULL) {
            SEC_LOG_ERROR("arr == NULL");
            return 0;
        }

        if (NULL == SecJsonValArr_Add(arr, val)) {
            SEC_LOG_ERROR("SecJsonValArr_Add failed");
            return 0;
        }

#if SEC_TRACE_JSON
    SEC_PRINT("_SetValue AFTER: ");
    _PrintJsonParseCtx(session);
    SEC_PRINT("\n");
#endif

        return 1;
    }

    SEC_LOG_ERROR("Invalid context stack state detected");
    return 0;
}

static int _BooleanCallback(void * ctx, int booleanval) {
    Sec_JsonParseCtx *session = (Sec_JsonParseCtx *) ctx;

#if SEC_TRACE_JSON
    SEC_PRINT("_BooleanCallback BEFORE: ");
    _PrintJsonParseCtx(session);
    SEC_PRINT("\n");
#endif

    Sec_JsonVal *val = NULL;

    if (booleanval != 0) {
        val = SecJsonVal_NewStr("true", strlen("true"));
    } else {
        val = SecJsonVal_NewStr("false", strlen("false"));
    }
    if (val == NULL) {
        SEC_LOG_ERROR("JsonVal_NewBoolean failed");
        return 0;
    }

    if (!_SetValue(session, val)) {
        SecJsonVal_Free(val);
        SEC_LOG_ERROR("_SetValue failed");
        return 0;
    }

#if SEC_TRACE_JSON
    SEC_PRINT("_BooleanCallback AFTER: ");
    _PrintJsonParseCtx(session);
    SEC_PRINT("\n");
#endif

    return 1;
}

static int _NullCallback(void * ctx) {
    Sec_JsonParseCtx *session = (Sec_JsonParseCtx *) ctx;

#if SEC_TRACE_JSON
    SEC_PRINT("_NullCallback BEFORE: ");
    _PrintJsonParseCtx(session);
    SEC_PRINT("\n");
#endif

    if (!_SetValue(session, NULL)) {
        SEC_LOG_ERROR("_SetValue failed");
        return 0;
    }

#if SEC_TRACE_JSON
    SEC_PRINT("_NullCallback AFTER: ");
    _PrintJsonParseCtx(session);
    SEC_PRINT("\n");
#endif

    return 1;
}

#if !defined(YAJL_V2)
static int _StringCallback(void * ctx, const unsigned char * stringVal, unsigned int stringLen) {
#else
static int _StringCallback(void * ctx, const unsigned char * stringVal, size_t stringLen) {
#endif
    Sec_JsonParseCtx *session = (Sec_JsonParseCtx *) ctx;

#if SEC_TRACE_JSON
    SEC_PRINT("_StringCallback BEFORE: ");
    _PrintJsonParseCtx(session);
    SEC_PRINT("\n");
#endif

    Sec_JsonVal *val = SecJsonVal_NewStr((const char *) stringVal, stringLen);
    if (val == NULL) {
        SEC_LOG_ERROR("SecJsonVal_NewStr failed");
        return 0;
    }

    if (!_SetValue(session, val)) {
        SecJsonVal_Free(val);
        SEC_LOG_ERROR("_SetValue failed");
        return 0;
    }

#if SEC_TRACE_JSON
    SEC_PRINT("_StringCallback AFTER: ");
    _PrintJsonParseCtx(session);
    SEC_PRINT("\n");
#endif

    return 1;
}

#if !defined(YAJL_V2)
static int _NumberCallback(void * ctx, const char * stringVal, unsigned int stringLen) {
#else
static int _NumberCallback(void * ctx, const char * stringVal, size_t stringLen) {
#endif
    Sec_JsonParseCtx *session = (Sec_JsonParseCtx *) ctx;
#if SEC_TRACE_JSON
    SEC_PRINT("_NumberCallback BEFORE: ");
    _PrintJsonParseCtx(session);
    SEC_PRINT("\n");
#endif

    Sec_JsonVal *val = SecJsonVal_NewStr((const char *) stringVal, stringLen);
    if (val == NULL) {
        SEC_LOG_ERROR("SecJsonVal_NewStr failed");
        return 0;
    }

    if (!_SetValue(session, val)) {
        SecJsonVal_Free(val);
        SEC_LOG_ERROR("_SetValue failed");
        return 0;
    }

#if SEC_TRACE_JSON
    SEC_PRINT("_NumberCallback AFTER: ");
    _PrintJsonParseCtx(session);
    SEC_PRINT("\n");
#endif

    return 1;
}

#if !defined(YAJL_V2)
static int _MapKeyCallback(void * ctx, const unsigned char * key, unsigned int stringLen) {
#else
static int _MapKeyCallback(void * ctx, const unsigned char * key, size_t stringLen) {
#endif
    Sec_JsonParseCtx *session = (Sec_JsonParseCtx *) ctx;

#if SEC_TRACE_JSON
    SEC_PRINT("_MapKeyCallback BEFORE: ");
    _PrintJsonParseCtx(session);
    SEC_PRINT("\n");
#endif

    if (session->ctx == NULL) {
        SEC_LOG_ERROR("Invalid nesting of JSON detected");
        return 0;
    }

    SecJsonValObj *top = SecJsonVal_GetObj(session->ctx->val);
    if (NULL == top) {
        SEC_LOG_ERROR("Top of the stack is not an object as expected");
        return 0;
    }

    while (top->next != NULL) {
        top = top->next;
    }

    Sec_JsonVal *val = SecJsonVal_NewObj();
    if (val == NULL) {
        SEC_LOG_ERROR("SecJsonVal_NewObj failed");
        return 0;
    }

    val->obj->key = _copyString((const char *) key, stringLen);
    if (val->obj->key == NULL) {
        SecJsonVal_Free(val);
        SEC_LOG_ERROR("_copyString failed");
        return 0;
    }

    top->next = val->obj;

    SecJsonCtx *newctx = SecJsonCtx_New(val);
    if (newctx == NULL) {
        SecJsonVal_Free(val);
        SEC_LOG_ERROR("SecJsonCtx_New failed");
        return 0;
    }
    newctx->prev = session->ctx;
    session->ctx = newctx;

#if SEC_TRACE_JSON
    SEC_PRINT("_MapKeyCallback AFTER: ");
    _PrintJsonParseCtx(session);
    SEC_PRINT("\n");
#endif

    return 1;
}

static int _StartMapCallback(void *ctx) {
    Sec_JsonParseCtx *session = (Sec_JsonParseCtx *) ctx;

#if SEC_TRACE_JSON
    SEC_PRINT("_StartMapCallback BEFORE: ");
    _PrintJsonParseCtx(session);
    SEC_PRINT("\n");
#endif

    if (session->ctx == NULL) {
        SEC_LOG_ERROR("Invalid nesting of JSON detected");
        return 0;
    }

    Sec_JsonVal *val = SecJsonVal_NewObj();
    if (val == NULL) {
        SEC_LOG_ERROR("SecJsonVal_NewObj failed");
        return 0;
    }

    if (!_SetValue(session, val)) {
        SecJsonVal_Free(val);
        SEC_LOG_ERROR("_SetValue failed");
        return 0;
    }

    if (!_PushCtx(session, val)) {
        SecJsonVal_Free(val);
        SEC_LOG_ERROR("_PushCtx failed");
        return 0;
    }

#if SEC_TRACE_JSON
    SEC_PRINT("_StartMapCallback AFTER: ");
    _PrintJsonParseCtx(session);
    SEC_PRINT("\n");
#endif

    return 1;
}

static int _EndMapCallback(void *ctx) {
    Sec_JsonParseCtx *session = (Sec_JsonParseCtx *) ctx;

#if SEC_TRACE_JSON
    SEC_PRINT("_EndMapCallback BEFORE: ");
    _PrintJsonParseCtx(session);
    SEC_PRINT("\n");
#endif

    if (session->ctx == NULL) {
        SEC_LOG_ERROR("Invalid nesting of JSON detected");
        return 0;
    }

    SecJsonValObj *obj = SecJsonVal_GetObj(session->ctx->val);
    if (obj == NULL) {
        SEC_LOG_ERROR("obj == NULL");
        return 0;
    }

    if (!_PopCtx(session)) {
        SEC_LOG_ERROR("_PopCtx failed");
        return 0;
    }

#if SEC_TRACE_JSON
    SEC_PRINT("_EndMapCallback AFTER: ");
    _PrintJsonParseCtx(session);
    SEC_PRINT("\n");
#endif

    return 1;
}

static int _StartArrayCallback(void *ctx) {
    Sec_JsonParseCtx *session = (Sec_JsonParseCtx *) ctx;

#if SEC_TRACE_JSON
    SEC_PRINT("_StartArrayCallback BEFORE: ");
    _PrintJsonParseCtx(session);
    SEC_PRINT("\n");
#endif

    if (session->ctx == NULL) {
        SEC_LOG_ERROR("Invalid nesting of JSON detected");
        return 0;
    }

    Sec_JsonVal *val = SecJsonVal_NewArr();
    if (val == NULL) {
        SEC_LOG_ERROR("SecJsonVal_NewArr failed");
        return 0;
    }

    if (!_SetValue(session, val)) {
        SecJsonVal_Free(val);
        SEC_LOG_ERROR("_SetValue failed");
        return 0;
    }

    if (!_PushCtx(session, val)) {
        SecJsonVal_Free(val);
        SEC_LOG_ERROR("_PushCtx failed");
        return 0;
    }

#if SEC_TRACE_JSON
    SEC_PRINT("_StartArrayCallback AFTER: ");
    _PrintJsonParseCtx(session);
    SEC_PRINT("\n");
#endif

    return 1;
}

static int _EndArrayCallback(void *ctx) {
    Sec_JsonParseCtx *session = (Sec_JsonParseCtx *) ctx;

#if SEC_TRACE_JSON
    SEC_PRINT("_EndArrayCallback BEFORE: ");
    _PrintJsonParseCtx(session);
    SEC_PRINT("\n");
#endif

    if (session->ctx == NULL) {
        SEC_LOG_ERROR("Invalid nesting of JSON detected");
        return 0;
    }

    SecJsonValArr *arr = SecJsonVal_GetArr(session->ctx->val);
    if (arr == NULL) {
        SEC_LOG_ERROR("arr == NULL");
        return 0;
    }

    if (!_PopCtx(session)) {
        SEC_LOG_ERROR("_PopCtx failed");
        return 0;
    }

#if SEC_TRACE_JSON
    SEC_PRINT("_EndArrayCallback AFTER: ");
    _PrintJsonParseCtx(session);
    SEC_PRINT("\n");
#endif

    return 1;
}

void SecJson_Init(void)
{
    if (0 != g_sec_json_inited)
        return;

#if !defined(YAJL_V2)
    g_sec_json_yajl_gen_config.beautify = 1;
    g_sec_json_yajl_gen_config.indentString = "  ";

    g_sec_json_yajl_parser_config.allowComments = 0;
    g_sec_json_yajl_parser_config.checkUTF8 = 1;
#endif

    g_sec_json_yajl_callbacks_config.yajl_boolean = _BooleanCallback;
    g_sec_json_yajl_callbacks_config.yajl_double = NULL;
    g_sec_json_yajl_callbacks_config.yajl_end_array = _EndArrayCallback;
    g_sec_json_yajl_callbacks_config.yajl_end_map = _EndMapCallback;
    g_sec_json_yajl_callbacks_config.yajl_integer = NULL;
    g_sec_json_yajl_callbacks_config.yajl_map_key = _MapKeyCallback;
    g_sec_json_yajl_callbacks_config.yajl_null = _NullCallback;
    g_sec_json_yajl_callbacks_config.yajl_number = _NumberCallback;
    g_sec_json_yajl_callbacks_config.yajl_start_array = _StartArrayCallback;
    g_sec_json_yajl_callbacks_config.yajl_start_map = _StartMapCallback;
    g_sec_json_yajl_callbacks_config.yajl_string = _StringCallback;

    g_sec_json_inited = 1;
}

Sec_JsonGenCtx* SecJson_GenInit()
{
    Sec_JsonGenCtx *ctx = NULL;
    yajl_gen_status yajl_gen_status = yajl_gen_status_ok;

    JSON_ENSURE_INIT();

    ctx = (Sec_JsonGenCtx *) calloc(1, sizeof(Sec_JsonGenCtx));
    if (ctx == NULL) {
        SEC_LOG_ERROR("calloc failed");
        goto cleanup;
    }

#if !defined(YAJL_V2)
    ctx->gen = yajl_gen_alloc(&g_sec_json_yajl_gen_config, NULL );
#else
    ctx->gen = yajl_gen_alloc(NULL);
#endif
    if (ctx->gen == NULL )
    {
        SEC_LOG_ERROR("yajl_gen_alloc failed");
        goto cleanup;
    }
#if defined(YAJL_V2)
    yajl_gen_config(ctx->gen, yajl_gen_beautify, 1);
    yajl_gen_config(ctx->gen, yajl_gen_indent_string, "  ");
#endif

    CHECKED_YAJL_GEN(yajl_gen_map_open(ctx->gen), yajl_gen_status, cleanup);

    return ctx;

cleanup:
    if (ctx != NULL) {
        if (ctx->gen != NULL) {
            yajl_gen_free(ctx->gen);
        }
        ctx->gen = NULL;
        SEC_FREE(ctx);
    }

    return NULL;
}

Sec_Result SecJson_GenClose(Sec_JsonGenCtx *ctx, char *result, SEC_SIZE max_len) {
    yajl_gen_status yajl_gen_status = yajl_max_depth_exceeded;
    const unsigned char * yajl_buffer = NULL;

#if !defined(YAJL_V2)
    unsigned int yajl_buffer_len = 0;
#else
    size_t yajl_buffer_len = 0;
#endif

    if (result != NULL && max_len > 0)
        result[0] = '\0';
    else if(result == NULL)
        goto cleanup;

    JSON_ENSURE_INIT();

    JSON_CHECK_GEN(ctx);

    CHECKED_YAJL_GEN(yajl_gen_map_close(ctx->gen), yajl_gen_status, cleanup);
    CHECKED_YAJL_GEN(
            yajl_gen_get_buf(ctx->gen, &yajl_buffer, &yajl_buffer_len),
            yajl_gen_status, cleanup);

    if (yajl_buffer_len > (max_len-1)) {
        yajl_gen_status = yajl_max_depth_exceeded;
        goto cleanup;
    }

    strncpy(result, (const char *) yajl_buffer, yajl_buffer_len);
    result[yajl_buffer_len] = '\0';

    yajl_gen_status = yajl_gen_status_ok;

cleanup:
    yajl_gen_free(ctx->gen);
    ctx->gen = NULL;
    SEC_FREE(ctx);

    return (yajl_gen_status_ok == yajl_gen_status) ?
            SEC_RESULT_SUCCESS : SEC_RESULT_FAILURE;
}

Sec_Result SecJson_GenAdd(Sec_JsonGenCtx *ctx,
        const char* field, const char* value)
{
    yajl_gen_status yajl_gen_status = yajl_gen_status_ok;

    JSON_ENSURE_INIT();

    JSON_CHECK_GEN(ctx);

    CHECKED_YAJL_GEN(YAJL_GEN_STRING(ctx->gen, field), yajl_gen_status,
            cleanup);
    CHECKED_YAJL_GEN(YAJL_GEN_STRING(ctx->gen, value), yajl_gen_status,
            cleanup);

cleanup:
    return (yajl_gen_status_ok == yajl_gen_status) ?
                    SEC_RESULT_SUCCESS : SEC_RESULT_FAILURE;
}

Sec_Result SecJson_ParseInit(Sec_JsonParseCtx *session)
{
    SEC_TRACE(SEC_TRACE_JSON, "SecSrv_JsonParseInit");

    JSON_ENSURE_INIT();

    session->res = NULL;
    session->ctx = SecJsonCtx_New(NULL);
    if (session->ctx == NULL) {
        SEC_LOG_ERROR("SecJsonCtx_New failed");
        return SEC_RESULT_FAILURE;
    }

#if !defined(YAJL_V2)
    session->handle = yajl_alloc(&g_sec_json_yajl_callbacks_config, &g_sec_json_yajl_parser_config, NULL, session);
#else
    session->handle = yajl_alloc(&g_sec_json_yajl_callbacks_config, NULL, session);
#endif
    if (session->handle == NULL )
    {
        SecJsonCtx_Free(session->ctx);
        SEC_LOG_ERROR("yajl_alloc failed");
        return SEC_RESULT_FAILURE;
    }

#if SEC_TRACE_JSON
    SEC_PRINT("SecSrv_JsonParseInit: ");
    _PrintJsonParseCtx(session);
    SEC_PRINT("\n");
#endif

    return SEC_RESULT_SUCCESS;
}

Sec_Result SecJson_ParseClose(Sec_JsonParseCtx *session)
{
#if SEC_TRACE_JSON
    SEC_PRINT("SecSrv_JsonParseClose: ");
    _PrintJsonParseCtx(session);
    SEC_PRINT("\n");
#endif

    JSON_ENSURE_INIT();

    JSON_CHECK_PARSE(session);

    yajl_free(session->handle);
    session->handle = NULL;

    SecJsonCtx_Free(session->ctx);
    session->ctx = NULL;

    return SEC_RESULT_SUCCESS;
}

void SecJson_ValFree(Sec_JsonVal *res)
{
    SecJsonVal_Free(res);
}

Sec_JsonVal* SecJson_Parse(const char *json)
{
    SEC_TRACE(SEC_TRACE_JSON, "SecJson_Parse");

    Sec_JsonParseCtx ctx;
    Sec_Result sec_status;
    yajl_status yajl_status = yajl_status_ok;
    Sec_JsonVal *root = NULL;

    sec_status = SecJson_ParseInit(&ctx);
    if (sec_status != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("sec_json_parse_init failed");
        goto return_status;
    }

    CHECKED_YAJL_PARSE(
            yajl_parse(ctx.handle, (const unsigned char *) json, strlen(json)),
            yajl_status, cleanup, ctx.handle);


#if !defined(YAJL_V2)
    CHECKED_YAJL_PARSE(yajl_parse_complete(ctx.handle), yajl_status, cleanup, ctx.handle);
#else
    CHECKED_YAJL_PARSE(yajl_complete_parse(ctx.handle), yajl_status, cleanup, ctx.handle);
#endif

    root = ctx.res;

cleanup:
    SecJson_ParseClose(&ctx);

return_status:
    return root;
}

Sec_Result SecJson_Gen(char *json, SEC_SIZE json_len, ...)
{
    Sec_JsonGenCtx *json_gen_ctx = NULL;
    va_list args;
    char *key;
    char *value;
    Sec_Result res = SEC_RESULT_FAILURE;

    if ((json_gen_ctx = SecJson_GenInit()) == NULL)
    {
        SEC_LOG_ERROR("SecSrv_JsonGenInit failed");
        goto cleanup;
    }

    va_start(args, json_len);
    while ((key=va_arg(args, char*)) && (value = va_arg(args, char*)))
    {
        if (SEC_RESULT_SUCCESS != SecJson_GenAdd(json_gen_ctx, key, value))
        {
            SEC_LOG_ERROR("SecSrv_JsonGenAdd failed");
            va_end(args);
            goto cleanup;
        }
    }
    va_end(args);

    if (SEC_RESULT_SUCCESS != SecJson_GenClose(json_gen_ctx, json, json_len)) {
        SEC_LOG_ERROR("SecSrv_JsonGenClose failed");
        json_gen_ctx = NULL;
        goto cleanup;
    }
    json_gen_ctx = NULL;

    res = SEC_RESULT_SUCCESS;

cleanup:
    if (json_gen_ctx != NULL)
        SecJson_GenClose(json_gen_ctx, NULL, 0);

    return res;
}

Sec_JsonVal * SecJson_GetObjEntry(Sec_JsonVal *val, const char *key) {
    SecJsonValObj *obj = SecJsonVal_GetObj(val);
    if (obj == NULL) {
        SEC_LOG_ERROR("SecJsonVal_GetObj failed");
        return NULL;
    }

    while (obj != NULL) {
        if (obj->key != NULL && strcmp(obj->key, key) == 0) {
            return obj->val;
        }

        obj = obj->next;
    }

    return NULL;
}

Sec_JsonVal * SecJson_GetArrayEntry(Sec_JsonVal *val, SEC_SIZE idx) {
    SecJsonValArr *arr = SecJsonVal_GetArr(val);
    if (arr == NULL) {
        SEC_LOG_ERROR("SecJsonVal_GetArr failed");
        return NULL;
    }

    SEC_SIZE i=0;
    for (i=0; i<=idx; ++i) {
        if (arr->next == NULL) {
            SEC_LOG_ERROR("index out of array bounds");
            return NULL;
        }
        arr = arr->next;
    }

    return arr->val;
}

SEC_SIZE SecJson_GetArraySize(Sec_JsonVal *val) {
    SecJsonValArr *arr = SecJsonVal_GetArr(val);
    if (arr == NULL) {
        SEC_LOG_ERROR("SecJsonVal_GetArr failed");
        return 0;
    }

    SEC_SIZE count = 0;
    while (arr->next != NULL) {
        arr = arr->next;
        ++count;
    }

    return count;
}

const char *SecJson_GetValue(Sec_JsonVal *val) {
    if (val == NULL) {
        return NULL;
    }

    if (val->type != JVT_STR) {
        SEC_LOG_ERROR("val is not a string");
        return NULL;
    }

    return val->str;
}

SEC_SIZE SecJson_GetObjNumKeys(Sec_JsonVal *val) {
    SecJsonValObj *obj = SecJsonVal_GetObj(val);
    if (obj == NULL) {
        SEC_LOG_ERROR("SecJsonVal_GetObj failed");
        return 0;
    }

    SEC_SIZE count = 0;
    while (obj->next != NULL) {
        obj = obj->next;
        ++count;
    }

    return count;
}

const char * SecJson_GetObjKey(Sec_JsonVal *val, SEC_SIZE idx) {
    SecJsonValObj *obj = SecJsonVal_GetObj(val);
    if (obj == NULL) {
        SEC_LOG_ERROR("SecJsonVal_GetObj failed");
        return NULL;
    }

    SEC_SIZE count = 0;
    while (obj->next != NULL) {
        obj = obj->next;
        if (count == idx) {
            return obj->key;
        }
        ++count;
    }

    return NULL;
}
