
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
    typedef const wchar_t* cjs_string, CJSString;
    typedef unsigned long long cjs_tag, CJSTAG;

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

    typedef CJSValue(*type_cjs_NewString)(CJSVERSION version, CJSContext, cjs_string);
    typedef CJSValue(*type_cjs_NewUint64)(CJSVERSION version, CJSContext, cjs_uint64);
    typedef CJSValue(*type_cjs_NewObject)(CJSVERSION version, CJSContext);
    typedef type_cjs_NewObject type_cjs_NewArray;
    typedef JSCFunction cjs_function;
    typedef CJSValue(*type_cjs_NewFunction)(CJSVERSION version, CJSContext, cjs_string, cjs_function, cjs_int);
    typedef bool(*type_cjs_FreeCJSValue)(CJSVERSION version, CJSContext, CJSValue);
    typedef bool(*type_cjs_FreeAllCJSValue)(CJSVERSION version, CJSContext);
    typedef bool(*type_cjs_SetProperty)(CJSVERSION version, CJSContext, CJSValue, CJSValue, CJSValue, cjs_int64);
    typedef bool(*type_cjs_SetPrototype)(CJSVERSION version, CJSContext, CJSValue, CJSValue);
    typedef CJSValue(*type_cjs_GetPrototype)(CJSVERSION version, CJSContext, CJSValue);
    typedef bool(*type_cjs_RemoveProperty)(CJSVERSION version, CJSContext, CJSValue, CJSValue);
    typedef CJSValue(*type_cjs_NewBool)(CJSVERSION version, CJSContext, cjs_bool);
    typedef CJSValue(*type_cjs_NewNumber)(CJSVERSION version, CJSContext, cjs_double);
    typedef CJSValue(*type_cjs_NewInt64)(CJSVERSION version, CJSContext, cjs_int64);
    typedef CJSValue(*type_cjs_NewDouble)(CJSVERSION version, CJSContext, cjs_double);
    typedef CJSValue(*type_cjs_NewArrayBuffer)(CJSVERSION version, CJSContext, cjs_size, cjs_byte*);
    typedef CJSValue(*type_cjs_NewError)(CJSVERSION version, CJSContext);
    typedef CJSValue(*type_cjs_NewTypeError)(CJSVERSION version, CJSContext, cjs_string);
    typedef CJSValue(*type_cjs_NewRangeError)(CJSVERSION version, CJSContext, cjs_string);
    typedef CJSValue(*type_cjs_NewSyntaxError)(CJSVERSION version, CJSContext, cjs_string);
    typedef CJSValue(*type_cjs_NewInternalError)(CJSVERSION version, CJSContext, cjs_string);
    typedef CJSValue(*type_cjs_NewPlainError)(CJSVERSION version, CJSContext, cjs_string);
    typedef CJSValue(*type_cjs_NewConstructor)(CJSVERSION version, CJSContext, cjs_string, cjs_function, cjs_int);
    typedef CJSValue(*type_cjs_NewIterator)(CJSVERSION version, CJSContext, CJSValue, cjs_string, cjs_function, cjs_int64);
    typedef CJSValue(*type_cjs_NewUint8Array)(CJSVERSION version, CJSContext, cjs_size, cjs_byte*);
    typedef CJSValue(*type_cjs_NewUint16Array)(CJSVERSION version, CJSContext, cjs_size, cjs_byte*);
    typedef CJSValue(*type_cjs_NewUint32Array)(CJSVERSION version, CJSContext, cjs_size, cjs_byte*);
    typedef CJSValue(*type_cjs_NewInt8Array)(CJSVERSION version, CJSContext, cjs_size, cjs_byte*);
    typedef CJSValue(*type_cjs_NewInt16Array)(CJSVERSION version, CJSContext, cjs_size, cjs_byte*);
    typedef CJSValue(*type_cjs_NewInt32Array)(CJSVERSION version, CJSContext, cjs_size, cjs_byte*);
    typedef CJSPromise(*type_cjs_NewPromise)(CJSVERSION version, CJSContext);
    typedef bool(*type_cjs_FreePromise)(CJSVERSION version, CJSContext, CJSPromise);
    typedef CJSValue(*type_cjs_GetProperty)(CJSVERSION version, CJSContext in_ctx, CJSValue in_obj, CJSValue in_propName);
    typedef CJSArgumentPackage(*type_cjs_GetArgumentPackage)(CJSVERSION version, JSContext* in_ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues);
    typedef bool(*type_cjs_FreeArgumentPackage)(CJSVERSION version, CJSArgumentPackage);
    typedef bool(*type_cjs_GeneralNewCJSValue)(CJSVERSION version, CJSContext);
    typedef JSValue(*type_cjs_GetOriginValue)(CJSVERSION version, CJSContext, CJSValue);
    typedef JSContext*(*type_cjs_GetOriginContext)(CJSVERSION version, CJSContext);
    typedef void(*type_cjs_ExitHandle)();
    typedef CJSValue(*type_cjs_CallFunction)(CJSVERSION version, CJSContext, CJSValue, CJSValue, cjs_int, CJSValue*);
    typedef CJSValue(*type_cjs_CallConstructor)(CJSVERSION version, CJSContext, CJSValue, cjs_int, CJSValue*);
    typedef CJSValue(*type_cjs_GetCJSValue)(CJSVERSION version, CJSContext, JSValue);
    typedef bool(*type_cjs_ArrayPushBack)(CJSVERSION version, CJSContext, CJSValue, CJSValue);
    typedef bool(*type_cjs_ArrayPopBack)(CJSVERSION version, CJSContext, CJSValue);
    typedef bool(*type_cjs_ArrayInsert)(CJSVERSION version, CJSContext, CJSValue, cjs_uint64, CJSValue);
    typedef bool(*type_cjs_ArrayErase)(CJSVERSION version, CJSContext, CJSValue, cjs_uint64);
    typedef bool(*type_cjs_ArrayClear)(CJSVERSION version, CJSContext, CJSValue);
    typedef bool(*type_cjs_ArrayResize)(CJSVERSION version, CJSContext, CJSValue, cjs_uint64);
    typedef bool(*type_cjs_ArrayAssign)(CJSVERSION version, CJSContext, CJSValue, cjs_uint64, CJSValue);
    typedef CJSValue(*type_cjs_ArrayAt)(CJSVERSION version, CJSContext, CJSValue, cjs_uint64);
    typedef CJSValue(*type_cjs_DupValue)(CJSVERSION version, CJSContext, CJSValue);
    typedef bool(*type_cjs_FreeValue)(CJSVERSION version, CJSContext, void*);
    typedef bool(*type_cjs_ReadAsArrayBufferView)(CJSVERSION version, CJSContext, CJSValue, cjs_size*, cjs_byte**);
    typedef type_cjs_ReadAsArrayBufferView type_cjs_ReadAsArrayBuffer, type_cjs_ReadAsUint8Array, type_cjs_ReadAsUint16Array, type_cjs_ReadAsUint32Array, type_cjs_ReadAsInt8Array, type_cjs_ReadAsInt16Array, type_cjs_ReadAsInt32Array;
    typedef bool(*type_cjs_ReadAsBool)(CJSVERSION version, CJSContext, CJSValue, cjs_bool*);
    typedef bool(*type_cjs_ReadAsString)(CJSVERSION version, CJSContext, CJSValue, cjs_string*);
    typedef bool(*type_cjs_ReadAsInt32)(CJSVERSION version, CJSContext, CJSValue, cjs_int32*);
    typedef bool(*type_cjs_ReadAsInt64)(CJSVERSION version, CJSContext, CJSValue, cjs_int64*);
    typedef bool(*type_cjs_ReadAsUint64)(CJSVERSION version, CJSContext, CJSValue, cjs_uint64*);
    typedef bool(*type_cjs_ReadAsDouble)(CJSVERSION version, CJSContext, CJSValue, cjs_double*);
    typedef CJSValue(*type_cjs_Eval)(CJSVERSION version, CJSContext, CJSValue, cjs_string, cjs_string);
    typedef bool(*type_cjs_IsXXX)(CJSVERSION version, CJSContext, CJSValue);
    typedef bool(*type_cjs_IsDoubleXXX)(CJSVERSION version, CJSContext, CJSValue, CJSValue);
    typedef CJSValue(*type_cjs_PromiseGetResult)(CJSVERSION version, CJSContext, CJSValue);
    typedef CJSPromiseState(*type_cjs_PromiseGetState)(CJSVERSION version, CJSContext, CJSValue);
    typedef bool(*type_cjs_PromiseResolveReject)(CJSVERSION version, CJSContext, CJSValue, CJSValue);
    typedef CJSID(*type_cjs_EnqueueTask)(CJSVERSION version, CJSContext, CJSValue, CJSValue, cjs_int, CJSValue*);
    typedef bool(*type_cjs_RemoveTask)(CJSVERSION version, CJSContext, CJSID);
    typedef CJSValue(*type_cjs_QueryTask)(CJSVERSION version, CJSContext, CJSID);
    typedef CJSSize(*type_cjs_RunTask)(CJSVERSION version, CJSContext);


#ifdef __cplusplus
}
#endif

#endif

