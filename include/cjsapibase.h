
#ifndef AY_CJSAPIBASE_H
#define AY_CJSAPIBASE_H

#ifdef __cplusplus
extern "C" {
#endif

#pragma warning(push)
#pragma warning(disable: 4244)
#pragma warning(disable: 6001)
#include "./thirdParty/quickjs-ng/include/quickjs.h"
#pragma warning(pop)

#if defined(_MSC_VER)
#define CAEXP __declspec(dllexport)
#elif defined(__GNUC__)
#define CAEXP __attribute__((dllexport))
#else
#define CAEXP
#endif

    typedef int CARESULT;
#define CAENTRY CAEXP CARESULT
#if defined(_WIN32)
#define CACALL __stdcall
#else
#define CACALL
#endif
#define CARSUCCESS 0
#define CARERROR 1

    typedef unsigned long long CJSVERSION, cjs_uint64, CJSUint64, CJSID;
    typedef uint8_t cjs_uint8, CJSUint8;
    typedef long long CJSValue;
    typedef void* CJSContext;
    typedef double cjs_double, CJSDouble;
    typedef long long cjs_int64, CJSInt64;
    typedef int cjs_int32, CJSInt32;
    typedef int cjs_int, CJSInt;
    typedef bool cjs_bool, CJSBool;
    typedef unsigned char cjs_byte, CJSByte;
    typedef unsigned long long cjs_size, CJSSize;
    typedef const char* cjs_string, * CJSString;
    typedef unsigned long long cjs_tag, CJSTAG;
    typedef const void* cjs_ptr, * CJSPtr;

    const CJSValue CJS_ERROR = 0;
    const CJSValue CJS_ERROR_PROMISE_STATE_BAD = -1;

    typedef struct {
        CJSValue promise;
        CJSValue resolve;
        CJSValue reject;
    } CJSPromise;
    typedef struct {
        CJSContext ctx;
        CJSValue global;
    } cjs_main_info_1;
    typedef struct {
        CJSID id;
        CJSContext ctx;
        CJSValue thisVal;
        CJSSize argumentCount;
        CJSValue* argumentValues;
    } CJSArgumentPackage;
    typedef enum {
        CJS_STATE_ERROR = -1,
        CJS_STATE_PROMISE_PENDING = 0,
        CJS_STATE_PROMISE_FULFILLED = 1,
        CJS_STATE_PROMISE_REJECTED = 2,
        CJS_STATE_TASK_NOTRUNNED = 3,
    } CJSPromiseState;

    typedef CJSValue(CACALL* type_cjs_NewString)(CJSContext, cjs_string);
    typedef CJSValue(CACALL* type_cjs_NewUint64)(CJSContext, cjs_uint64);
    typedef CJSValue(CACALL* type_cjs_NewObject)(CJSContext);
    typedef type_cjs_NewObject type_cjs_NewArray;
    typedef JSCFunction cjs_function;
    typedef CJSValue(CACALL* type_cjs_NewFunction)(CJSContext, cjs_string, cjs_function, cjs_int);
    typedef cjs_bool(CACALL* type_cjs_FreeCJSValue)(CJSContext, CJSValue);
    typedef cjs_bool(CACALL* type_cjs_FreeAllCJSValue)(CJSContext);
    typedef cjs_bool(CACALL* type_cjs_SetProperty)(CJSContext, CJSValue, CJSValue, CJSValue, cjs_int64);
    typedef cjs_bool(CACALL* type_cjs_SetPrototype)(CJSContext, CJSValue, CJSValue);
    typedef CJSValue(CACALL* type_cjs_GetPrototype)(CJSContext, CJSValue);
    typedef cjs_bool(CACALL* type_cjs_RemoveProperty)(CJSContext, CJSValue, CJSValue);
    typedef CJSValue(CACALL* type_cjs_NewBool)(CJSContext, cjs_bool);
    typedef CJSValue(CACALL* type_cjs_NewNumber)(CJSContext, cjs_double);
    typedef CJSValue(CACALL* type_cjs_NewInt64)(CJSContext, cjs_int64);
    typedef CJSValue(CACALL* type_cjs_NewDouble)(CJSContext, cjs_double);
    typedef CJSValue(CACALL* type_cjs_NewArrayBuffer)(CJSContext, cjs_size, cjs_byte*);
    typedef CJSValue(CACALL* type_cjs_NewError)(CJSContext);
    typedef CJSValue(CACALL* type_cjs_NewTypeError)(CJSContext, cjs_string);
    typedef CJSValue(CACALL* type_cjs_NewRangeError)(CJSContext, cjs_string);
    typedef CJSValue(CACALL* type_cjs_NewSyntaxError)(CJSContext, cjs_string);
    typedef CJSValue(CACALL* type_cjs_NewInternalError)(CJSContext, cjs_string);
    typedef CJSValue(CACALL* type_cjs_NewPlainError)(CJSContext, cjs_string);
    typedef CJSValue(CACALL* type_cjs_NewConstructor)(CJSContext, cjs_string, cjs_function, cjs_int);
    typedef CJSValue(CACALL* type_cjs_NewIterator)(CJSContext, CJSValue, cjs_string, cjs_function, cjs_int64);
    typedef CJSValue(CACALL* type_cjs_NewUint8Array)(CJSContext, cjs_size, cjs_byte*);
    typedef CJSValue(CACALL* type_cjs_NewUint16Array)(CJSContext, cjs_size, cjs_byte*);
    typedef CJSValue(CACALL* type_cjs_NewUint32Array)(CJSContext, cjs_size, cjs_byte*);
    typedef CJSValue(CACALL* type_cjs_NewInt8Array)(CJSContext, cjs_size, cjs_byte*);
    typedef CJSValue(CACALL* type_cjs_NewInt16Array)(CJSContext, cjs_size, cjs_byte*);
    typedef CJSValue(CACALL* type_cjs_NewInt32Array)(CJSContext, cjs_size, cjs_byte*);
    typedef CJSPromise(CACALL* type_cjs_NewPromise)(CJSContext);
    typedef cjs_bool(CACALL* type_cjs_FreePromise)(CJSContext, CJSPromise);
    typedef CJSValue(CACALL* type_cjs_GetProperty)(CJSContext in_ctx, CJSValue in_obj, CJSValue in_propName);
    typedef CJSArgumentPackage(CACALL* type_cjs_GetArgumentPackage)(JSContext* in_ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues);
    typedef cjs_bool(CACALL* type_cjs_FreeArgumentPackage)(CJSArgumentPackage);
    typedef cjs_bool(CACALL* type_cjs_GeneralNewCJSValue)(CJSContext);
    typedef JSValue(CACALL* type_cjs_GetOriginValue)(CJSContext, CJSValue);
    typedef JSContext* (CACALL* type_cjs_GetOriginContext)(CJSContext);
    typedef void(CACALL* type_cjs_ExitHandle)();
    typedef CJSValue(CACALL* type_cjs_CallFunction)(CJSContext, CJSValue, CJSValue, cjs_int, CJSValue*);
    typedef CJSValue(CACALL* type_cjs_CallConstructor)(CJSContext, CJSValue, cjs_int, CJSValue*);
    typedef CJSValue(CACALL* type_cjs_GetCJSValue)(CJSContext, JSValue);
    typedef cjs_bool(CACALL* type_cjs_ArrayPushBack)(CJSContext, CJSValue, CJSValue);
    typedef cjs_bool(CACALL* type_cjs_ArrayPopBack)(CJSContext, CJSValue);
    typedef cjs_bool(CACALL* type_cjs_ArrayInsert)(CJSContext, CJSValue, cjs_uint64, CJSValue);
    typedef cjs_bool(CACALL* type_cjs_ArrayErase)(CJSContext, CJSValue, cjs_uint64);
    typedef cjs_bool(CACALL* type_cjs_ArrayClear)(CJSContext, CJSValue);
    typedef cjs_bool(CACALL* type_cjs_ArrayResize)(CJSContext, CJSValue, cjs_uint64);
    typedef cjs_bool(CACALL* type_cjs_ArrayAssign)(CJSContext, CJSValue, cjs_uint64, CJSValue);
    typedef CJSValue(CACALL* type_cjs_ArrayAt)(CJSContext, CJSValue, cjs_uint64);
    typedef CJSValue(CACALL* type_cjs_DupValue)(CJSContext, CJSValue);
    typedef cjs_bool(CACALL* type_cjs_FreeValue)(CJSContext, CJSPtr);
    typedef cjs_bool(CACALL* type_cjs_ReadAsArrayBufferView)(CJSContext, CJSValue, cjs_size*, cjs_byte**);
    typedef type_cjs_ReadAsArrayBufferView type_cjs_ReadAsArrayBuffer, type_cjs_ReadAsUint8Array, type_cjs_ReadAsUint16Array, type_cjs_ReadAsUint32Array, type_cjs_ReadAsInt8Array, type_cjs_ReadAsInt16Array, type_cjs_ReadAsInt32Array;
    typedef cjs_bool(CACALL* type_cjs_ReadAsBool)(CJSContext, CJSValue, cjs_bool*);
    typedef cjs_bool(CACALL* type_cjs_ReadAsString)(CJSContext, CJSValue, cjs_string*);
    typedef cjs_bool(CACALL* type_cjs_ReadAsInt32)(CJSContext, CJSValue, cjs_int32*);
    typedef cjs_bool(CACALL* type_cjs_ReadAsInt64)(CJSContext, CJSValue, cjs_int64*);
    typedef cjs_bool(CACALL* type_cjs_ReadAsUint64)(CJSContext, CJSValue, cjs_uint64*);
    typedef cjs_bool(CACALL* type_cjs_ReadAsDouble)(CJSContext, CJSValue, cjs_double*);
    typedef CJSValue(CACALL* type_cjs_Eval)(CJSContext, CJSValue, cjs_string, cjs_string);
    typedef cjs_bool(CACALL* type_cjs_IsXXX)(CJSContext, CJSValue);
    typedef cjs_bool(CACALL* type_cjs_IsDoubleXXX)(CJSContext, CJSValue, CJSValue);
    typedef CJSValue(CACALL* type_cjs_PromiseGetResult)(CJSContext, CJSValue);
    typedef CJSPromiseState(CACALL* type_cjs_PromiseGetState)(CJSContext, CJSValue);
    typedef cjs_bool(CACALL* type_cjs_PromiseResolveReject)(CJSContext, CJSValue, CJSValue);
    typedef CJSID(CACALL* type_cjs_EnqueueTask)(CJSContext, CJSValue, CJSValue, cjs_int, CJSValue*);
    typedef cjs_bool(CACALL* type_cjs_RemoveTask)(CJSContext, CJSID);
    typedef CJSValue(CACALL* type_cjs_QueryTask)(CJSContext, CJSID);
    typedef CJSSize(CACALL* type_cjs_RunTask)(CJSContext);

#define CJS_Assert_Print(expr) \
    fprintf(stderr, "\n========================================\n" \
    "          CJS_Assert FAILED\n" \
    "----------------------------------------\n" \
    "Expression : %s\n" \
    "File       : %s\n" \
    "Line       : %d\n" \
    "========================================\n\n", \
    #expr, __FILE__, __LINE__)

#ifdef _DEBUG
#define CJS_Assert(expr) \
do { \
    if (!(expr)) { \
        CJS_Assert_Print(expr); \
        assert(0 && #expr); \
    } \
} while(0)
#else
#define CJS_Assert(expr) \
do { \
    if (!(expr)) { \
        CJS_Assert_Print(expr); \
        abort(); \
    } \
} while(0)
#endif

#ifdef __cplusplus
}
#endif

#endif

