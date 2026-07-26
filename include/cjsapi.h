//CJS-CAPI


#ifndef AY_CJSAPI_H
#define AY_CJSAPI_H
#define AY_CJSAPI_H_VL 102026031601

#ifdef __cplusplus
extern "C" {
#endif

#include <windows.h>
#include <assert.h>
#include "cjsapibase.h"

    typedef cjs_main_info_1 CJSMAININFO;

    HMODULE hm = NULL;
    const CJSVERSION ver = (CJSVERSION)AY_CJSAPI_H_VL;
    CJSContext ctx = NULL;
    type_cjs_ExitHandle onExit = NULL;

    /**
     * @brief 入口函数。
     * @details 将在JS创建时或被include时被调用。
     * @param info 启动信息。
     * @return 未使用。
     * @note 必须实现定义。
     */
    CAENTRY CJS_Main(CJSMAININFO info);
    CAEXP CJSVERSION cjs_versionExchanger() {
        return ver;
    }
    CAENTRY cjs_main(void* info) {

        hm = GetModuleHandleW(NULL);

        CJSMAININFO cjsinfo = *((CJSMAININFO*)info);
        ctx = cjsinfo.ctx;

        CJS_Main(cjsinfo);
        return CARSUCCESS;
    }
    CAENTRY cjs_exit() {
        ctx = NULL;
        if (onExit) onExit();
        return CARSUCCESS;
    }
    /**
     * @brief 获取全局对象。
     * @return JS值(Object)。
     */
    CJSValue CJS_GetGlobalObject() {
        static type_cjs_GeneralNewCJSValue f = (type_cjs_GeneralNewCJSValue)GetProcAddress(hm, "cjs_GetGlobalObject");
        CJS_Assert(f && "方法不可用");
        return f(ctx);
    }
    /**
     * @brief 获取JS的null值。
     * @return JS值(null)。
     */
    CJSValue CJS_NewNull() {
        static type_cjs_GeneralNewCJSValue f = (type_cjs_GeneralNewCJSValue)GetProcAddress(hm, "cjs_NewNull");
        CJS_Assert(f && "方法不可用");
        return f(ctx);
    }
    /**
     * @brief 获取JS的undefined值。
     * @return JS值(undefined)。
     */
    CJSValue CJS_NewUndefined() {
        static type_cjs_GeneralNewCJSValue f = (type_cjs_GeneralNewCJSValue)GetProcAddress(hm, "cjs_NewUndefined");
        CJS_Assert(f && "方法不可用");
        return f(ctx);
    }
    /**
     * @brief 获取未初始化的JS值。
     * @return JS值(未初始化)。
     */
    CJSValue CJS_NewUninititalized() {
        static type_cjs_GeneralNewCJSValue f = (type_cjs_GeneralNewCJSValue)GetProcAddress(hm, "cjs_NewUninititalized");
        CJS_Assert(f && "方法不可用");
        return f(ctx);
    }
    /**
     * @brief 创建新的JS字符串。
     * @param in_propName 字符串的值。
     * @return JS值(String)。
     */
    CJSValue CJS_NewString(cjs_string in_propName) {
        static type_cjs_NewString f = (type_cjs_NewString)GetProcAddress(hm, "cjs_NewString");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_propName);
    }
    /**
     * @brief 创建新的JS64位无符号整数。
     * @param in_uint64 Uint64的值。
     * @return JS值(Uint64)。
     */
    CJSValue CJS_NewUint64(cjs_uint64 in_uint64) {
        static type_cjs_NewUint64 f = (type_cjs_NewUint64)GetProcAddress(hm, "cjs_NewUint64");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_uint64);
    }
    /**
     * @brief 创建新的JS对象。
     * @return JS值(Object)。
     */
    CJSValue CJS_NewObject() {
        static type_cjs_NewObject f = (type_cjs_NewObject)GetProcAddress(hm, "cjs_NewObject");
        CJS_Assert(f && "方法不可用");
        return f(ctx);
    }
    /**
     * @brief 创建新的JS数组。
     * @return JS值(Array)。
     */
    CJSValue CJS_NewArray() {
        static type_cjs_NewArray f = (type_cjs_NewArray)GetProcAddress(hm, "cjs_NewArray");
        CJS_Assert(f && "方法不可用");
        return f(ctx);
    }
    /**
     * @brief 创建新的JS函数（完整参数版）。
     * @param in_name 函数名称。
     * @param in_func 函数体。
     * @param argLength 参数长度。
     * @return JS值(Function)。
     */
    CJSValue CJS_NewFunctionFull(cjs_string in_name, cjs_function in_func, cjs_int argLength) {
        static type_cjs_NewFunction f = (type_cjs_NewFunction)GetProcAddress(hm, "cjs_NewFunction");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_name, in_func, argLength);
    }
    /**
     * @brief 创建新的JS函数。
     * @param in_name 函数名称。
     * @param in_func 函数体。
     * @return JS值(Function)。
     */
    CJSValue CJS_NewFunction(cjs_string in_name, cjs_function in_func) {
        return CJS_NewFunctionFull(in_name, in_func, -1);
    }
    /**
    * @brief 创建新的JS布尔值。
    * @param in_bool 布尔值。
    * @return JS值(Boolean)。
    */
    CJSValue CJS_NewBool(cjs_bool in_bool) {
        static type_cjs_NewBool f = (type_cjs_NewBool)GetProcAddress(hm, "cjs_NewBool");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_bool);
    }
    /**
     * @brief 创建新的JS数字值。
     * @param in_num 数字值。
     * @return JS值(Number)。
     */
    CJSValue CJS_NewNumber(cjs_double in_num) {
        static type_cjs_NewNumber f = (type_cjs_NewNumber)GetProcAddress(hm, "cjs_NewNumber");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_num);
    }
    /**
     * @brief 创建新的JS64位有符号整数。
     * @param in_int64 Int64的值。
     * @return JS值(Int64)。
     */
    CJSValue CJS_NewInt64(cjs_int64 in_int64) {
        static type_cjs_NewInt64 f = (type_cjs_NewInt64)GetProcAddress(hm, "cjs_NewInt64");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_int64);
    }
    /**
     * @brief 创建新的JS双精度浮点数。
     * @param in_num 双精度浮点数值。
     * @return JS值(Double)。
     */
    CJSValue CJS_NewDouble(cjs_double in_num) {
        static type_cjs_NewDouble f = (type_cjs_NewDouble)GetProcAddress(hm, "cjs_NewDouble");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_num);
    }
    /**
     * @brief 创建新的JS ArrayBuffer。
     * @param in_byte_size 字节长度。
     * @param in_byte 字节数据指针。
     * @return JS值(ArrayBuffer)。
     */
    CJSValue CJS_NewArrayBuffer(cjs_size in_byte_size, cjs_byte* in_byte) {
        static type_cjs_NewArrayBuffer f = (type_cjs_NewArrayBuffer)GetProcAddress(hm, "cjs_NewArrayBuffer");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_byte_size, in_byte);
    }
    /**
     * @brief 创建新的JS通用错误对象。
     * @return JS值(Error)。
     */
    CJSValue CJS_NewError() {
        static type_cjs_NewError f = (type_cjs_NewError)GetProcAddress(hm, "cjs_NewError");
        CJS_Assert(f && "方法不可用");
        return f(ctx);
    }
    /**
     * @brief 创建新的JS类型错误对象。
     * @param in_error 错误信息。
     * @return JS值(TypeError)。
     */
    CJSValue CJS_NewTypeError(cjs_string in_error) {
        static type_cjs_NewTypeError f = (type_cjs_NewTypeError)GetProcAddress(hm, "cjs_NewTypeError");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_error);
    }
    /**
     * @brief 创建新的JS范围错误对象。
     * @param in_error 错误信息。
     * @return JS值(RangeError)。
     */
    CJSValue CJS_NewRangeError(cjs_string in_error) {
        static type_cjs_NewRangeError f = (type_cjs_NewRangeError)GetProcAddress(hm, "cjs_NewRangeError");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_error);
    }
    /**
     * @brief 创建新的JS语法错误对象。
     * @param in_error 错误信息。
     * @return JS值(SyntaxError)。
     */
    CJSValue CJS_NewSyntaxError(cjs_string in_error) {
        static type_cjs_NewSyntaxError f = (type_cjs_NewSyntaxError)GetProcAddress(hm, "cjs_NewSyntaxError");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_error);
    }
    /**
     * @brief 创建新的JS内部错误对象。
     * @param in_error 错误信息。
     * @return JS值(InternalError)。
     */
    CJSValue CJS_NewInternalError(cjs_string in_error) {
        static type_cjs_NewInternalError f = (type_cjs_NewInternalError)GetProcAddress(hm, "cjs_NewInternalError");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_error);
    }
    /**
     * @brief 创建新的JS普通错误对象。
     * @param in_error 错误信息。
     * @return JS值(PlainError)。
     */
    CJSValue CJS_NewPlainError(cjs_string in_error) {
        static type_cjs_NewPlainError f = (type_cjs_NewPlainError)GetProcAddress(hm, "cjs_NewPlainError");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_error);
    }
    /**
     * @brief 创建新的JS构造函数（完整参数版）。
     * @param in_name 构造函数名称。
     * @param in_func 函数体。
     * @param argLength 参数长度。
     * @return JS值(Constructor)。
     */
    CJSValue CJS_NewConstructorFull(cjs_string in_name, cjs_function in_func, cjs_int argLength) {
        static type_cjs_NewConstructor f = (type_cjs_NewConstructor)GetProcAddress(hm, "cjs_NewConstructor");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_name, in_func, argLength);
    }
    /**
     * @brief 创建新的JS构造函数。
     * @param in_name 构造函数名称。
     * @param in_func 函数体。
     * @return JS值(Constructor)。
     */
    CJSValue CJS_NewConstructor(cjs_string in_name, cjs_function in_func) {
        return CJS_NewConstructorFull(in_name, in_func, -1);
    }
    /**
     * @brief 创建新的JS迭代器（完整参数版）。
     * @param in_obj 迭代器关联的对象。
     * @param in_name 迭代器名称。
     * @param in_func 迭代器函数体。
     * @param flags 迭代器标志。
     * @return JS值(Iterator)。
     */
    CJSValue CJS_NewIteratorFull(CJSValue in_obj, cjs_string in_name, cjs_function in_func, cjs_int64 flags) {
        static type_cjs_NewIterator f = (type_cjs_NewIterator)GetProcAddress(hm, "cjs_NewIterator");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_obj, in_name, in_func, flags);
    }
    /**
     * @brief 创建新的JS迭代器。
     * @param in_obj 迭代器关联的对象。
     * @param in_name 迭代器名称。
     * @param in_func 迭代器函数体。
     * @return JS值(Iterator)。
     */
    CJSValue CJS_NewIterator(CJSValue in_obj, cjs_string in_name, cjs_function in_func) {
        return CJS_NewIteratorFull(in_obj, in_name, in_func, -1);
    }
    /**
     * @brief 创建新的JS Uint8Array。
     * @param in_byte_size 字节长度。
     * @param in_byte 字节数据指针。
     * @return JS值(Uint8Array)。
     */
    CJSValue CJS_NewUint8Array(cjs_size in_byte_size, cjs_byte* in_byte) {
        static type_cjs_NewUint8Array f = (type_cjs_NewUint8Array)GetProcAddress(hm, "cjs_NewUint8Array");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_byte_size, in_byte);
    }
    /**
     * @brief 创建新的JS Uint16Array。
     * @param in_byte_size 字节长度。
     * @param in_byte 字节数据指针。
     * @return JS值(Uint16Array)。
     */
    CJSValue CJS_NewUint16Array(cjs_size in_byte_size, cjs_byte* in_byte) {
        static type_cjs_NewUint16Array f = (type_cjs_NewUint16Array)GetProcAddress(hm, "cjs_NewUint16Array");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_byte_size, in_byte);
    }
    /**
     * @brief 创建新的JS Uint32Array。
     * @param in_byte_size 字节长度。
     * @param in_byte 字节数据指针。
     * @return JS值(Uint32Array)。
     */
    CJSValue CJS_NewUint32Array(cjs_size in_byte_size, cjs_byte* in_byte) {
        static type_cjs_NewUint32Array f = (type_cjs_NewUint32Array)GetProcAddress(hm, "cjs_NewUint32Array");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_byte_size, in_byte);
    }
    /**
     * @brief 创建新的JS Int8Array。
     * @param in_byte_size 字节长度。
     * @param in_byte 字节数据指针。
     * @return JS值(Int8Array)。
     */
    CJSValue CJS_NewInt8Array(cjs_size in_byte_size, cjs_byte* in_byte) {
        static type_cjs_NewInt8Array f = (type_cjs_NewInt8Array)GetProcAddress(hm, "cjs_NewInt8Array");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_byte_size, in_byte);
    }
    /**
     * @brief 创建新的JS Int16Array。
     * @param in_byte_size 字节长度。
     * @param in_byte 字节数据指针。
     * @return JS值(Int16Array)。
     */
    CJSValue CJS_NewInt16Array(cjs_size in_byte_size, cjs_byte* in_byte) {
        static type_cjs_NewInt16Array f = (type_cjs_NewInt16Array)GetProcAddress(hm, "cjs_NewInt16Array");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_byte_size, in_byte);
    }
    /**
     * @brief 创建新的JS Int32Array。
     * @param in_byte_size 字节长度。
     * @param in_byte 字节数据指针。
     * @return JS值(Int32Array)。
     */
    CJSValue CJS_NewInt32Array(cjs_size in_byte_size, cjs_byte* in_byte) {
        static type_cjs_NewInt32Array f = (type_cjs_NewInt32Array)GetProcAddress(hm, "cjs_NewInt32Array");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_byte_size, in_byte);
    }
    /**
     * @brief 创建新的JS Promise对象。
     * @return JS Promise对象(包含promise/reject/resolve)。
     */
    CJSPromise CJS_NewPromise() {
        static type_cjs_NewPromise f = (type_cjs_NewPromise)GetProcAddress(hm, "cjs_NewPromise");
        CJS_Assert(f && "方法不可用");
        return f(ctx);
    }
    /**
     * @brief 提前释放JS值(非必要，未释放的值将在程序结束后自动释放)。
     * @param in_cjsv 待释放的JS值。
     * @return 操作状态。
     */
    CJSBool CJS_FreeCJSValue(CJSValue in_cjsv) {
        static type_cjs_FreeCJSValue f = (type_cjs_FreeCJSValue)GetProcAddress(hm, "cjs_FreeCJSValue");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_cjsv);
    }
    /**
     * @brief 释放JS Promise对象。
     * @param in_promise 待释放的Promise对象。
     * @return 操作状态。
     */
    CJSBool CJS_FreePromise(CJSPromise in_promise) {
        static type_cjs_FreePromise f = (type_cjs_FreePromise)GetProcAddress(hm, "cjs_FreePromise");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_promise);
    }
    /**
     * @brief 提前释放所有JS值(非必要，未释放的值将在程序结束后自动释放)。
     * @return 操作状态。
     */
    CJSBool CJS_FreeAllCJSValue() {
        static type_cjs_FreeAllCJSValue f = (type_cjs_FreeAllCJSValue)GetProcAddress(hm, "cjs_FreeAllCJSValue");
        CJS_Assert(f && "方法不可用");
        return f(ctx);
    }
    /**
     * @brief 设置JS对象属性（完整参数版）。
     * @param in_cjsv 操作对象JS值。
     * @param in_propName 属性名称(JS值)。
     * @param in_propValue 属性值(JS值)。
     * @param flags 属性配置。
     * @return 操作状态。
     */
    CJSBool CJS_SetPropertyFull(CJSValue in_cjsv, CJSValue in_propName, CJSValue in_propValue, cjs_int64 flags) {
        static type_cjs_SetProperty f = (type_cjs_SetProperty)GetProcAddress(hm, "cjs_SetProperty");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_cjsv, in_propName, in_propValue, flags);
    }
    /**
     * @brief 设置JS对象属性。
     * @param in_cjsv 操作对象JS值。
     * @param in_propName 属性名称(JS值)。
     * @param in_propValue 属性值(JS值)。
     * @return 操作状态。
     */
    CJSBool CJS_SetProperty(CJSValue in_cjsv, CJSValue in_propName, CJSValue in_propValue) {
        return CJS_SetPropertyFull(in_cjsv, in_propName, in_propValue, -1);
    }
    /**
     * @brief 设置JS对象原型。
     * @param in_cjsv 操作对象JS值。
     * @param in_target 新的原型对象。
     * @return 操作状态。
     */
    CJSBool CJS_SetPrototype(CJSValue in_cjsv, CJSValue in_target) {
        static type_cjs_SetPrototype f = (type_cjs_SetPrototype)GetProcAddress(hm, "cjs_SetPrototype");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_cjsv, in_target);
    }
    /**
     * @brief 获取JS对象原型。
     * @param in_cjsv 操作对象JS值。
     * @return 操作状态。
     */
    CJSValue CJS_GetPrototype(CJSValue in_cjsv) {
        static type_cjs_GetPrototype f = (type_cjs_GetPrototype)GetProcAddress(hm, "cjs_GetPrototype");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_cjsv);
    }
    /**
     * @brief 移除JS对象属性。
     * @param in_cjsv 操作对象JS值。
     * @param in_propName 属性名称(JS值)。
     * @return 操作状态。
     */
    CJSBool CJS_RemoveProperty(CJSValue in_cjsv, CJSValue in_propName) {
        static type_cjs_RemoveProperty f = (type_cjs_RemoveProperty)GetProcAddress(hm, "cjs_RemoveProperty");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_cjsv, in_propName);
    }
    /**
     * @brief 获取JS对象属性。
     * @param in_obj 操作对象JS值。
     * @param in_propName 属性名称(JS值)。
     * @return 属性值(JS值，操作失败时为JS_ERROR)。
     */
    CJSValue CJS_GetProperty(CJSValue in_obj, CJSValue in_propName) {
        static type_cjs_GetProperty f = (type_cjs_GetProperty)GetProcAddress(hm, "cjs_GetProperty");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_obj, in_propName);
    }
    /**
     * @brief 包装QuickJs-NG绑定函数入参为库内资源。
     * @param in_ctx 绑定函数入参ctx。
     * @param in_thisVal 绑定函数入参thisVal。
     * @param in_argumentCount 绑定函数入参argumentCount。
     * @param in_argumentValues 绑定函数入参argumentValues。
     * @return 参数包装后的结构体(操作失败时id为0)。
     */
    CJSArgumentPackage CJS_GetArgumentPackage(JSContext* in_ctx, JSValueConst in_thisVal, int in_argumentCount, JSValueConst* in_argumentValues) {
        static type_cjs_GetArgumentPackage f = (type_cjs_GetArgumentPackage)GetProcAddress(hm, "cjs_GetArgumentPackage");
        CJS_Assert(f && "方法不可用");
        return f(in_ctx, in_thisVal, in_argumentCount, in_argumentValues);
    }
    /**
     * @brief 包装QuickJs-NG绑定函数入参为库内资源。
     * @param in_cap 参数包装。
     * @return 操作状态(全部释放成功返回true，任意失败返回false但不中断后续释放过程)。
     */
    CJSBool CJS_FreeArgumentPackage(CJSArgumentPackage in_cap) {
        static type_cjs_FreeArgumentPackage f = (type_cjs_FreeArgumentPackage)GetProcAddress(hm, "cjs_FreeArgumentPackage");
        CJS_Assert(f && "方法不可用");
        return f(in_cap);
    }
    /**
     * @brief 获取原始QuickJs-NG的JS值(需手动调用QuickJs-NG的API处理引用计数(返回的JSValue相对引用计数为0))。
     * @param in_cjsv CJSValue值。
     * @return JSValue值。
     */
    JSValue CJS_GetOriginValue(CJSValue in_cjsv) {
        static type_cjs_GetOriginValue f = (type_cjs_GetOriginValue)GetProcAddress(hm, "cjs_GetOriginValue");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_cjsv);
    }
    /**
     * @brief 将CJSValue转换成QuickJs_NG的绑定函数的返回值(转换后源CJSValue自动释放)。
     * @param in_cjsv CJSValue值。
     * @return JSValue值。
     */
    JSValue CJS_GetReturnValue(CJSValue in_cjsv) {
        static type_cjs_GetOriginValue f = (type_cjs_GetOriginValue)GetProcAddress(hm, "cjs_GetReturnValue");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_cjsv);
    }
    /**
     * @brief 获取原始QuickJs-NG的JSContext指针(生命周期仅在当前实例有效期内有效)。
     * @return JSContext指针。
     */
    JSContext* CJS_GetOriginContext() {
        static type_cjs_GetOriginContext f = (type_cjs_GetOriginContext)GetProcAddress(hm, "cjs_GetOriginContext");
        CJS_Assert(f && "方法不可用");
        return f(ctx);
    }
    /**
     * @brief 设置当前实例被销毁前的回调函数。
     * @param handleFunc 回调函数。
     */
    void CJS_SetExitHandle(type_cjs_ExitHandle handleFunc) {
        onExit = handleFunc;
    }
    /**
     * @brief 调用JS函数。
     * @param in_func 函数体。
     * @param in_this 调用函数时的this指向，不受JS规范限制。
     * @param in_argumentCount 参数数量，必须小于或等于真实参数数量，否则可能越界。
     * @param in_argumentValues 参数数据指针。
     * @return 函数返回JS值。
     */
    CJSValue CJS_CallFunction(CJSValue in_func, CJSValue in_this, cjs_int in_argumentCount, CJSValue* in_argumentValues) {
        static type_cjs_CallFunction f = (type_cjs_CallFunction)GetProcAddress(hm, "cjs_CallFunction");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_func, in_this, in_argumentCount, in_argumentValues);
    }
    /**
     * @brief 调用JS构造器(相当于new)。
     * @param in_func 构造器。
     * @param in_argumentCount 参数数量，必须小于或等于真实参数数量，否则可能越界。
     * @param in_argumentValues 参数数据指针。
     * @return 构造器返回JS值。
     */
    CJSValue CJS_CallConstructor(CJSValue in_func, cjs_int in_argumentCount, CJSValue* in_argumentValues) {
        static type_cjs_CallConstructor f = (type_cjs_CallConstructor)GetProcAddress(hm, "cjs_CallConstructor");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_func, in_argumentCount, in_argumentValues);
    }
    /**
     * @brief 包装QuickJs-NG的JSValue为库内类型。
     * @param in_jsvalue JSValue类型，必须剩余1引用(包装后原JSValue引用计数已平衡，CJSValue引用计数为1，不要求一定释放CJSValue)。
     * @return CJSValue。
     */
    CJSValue CJS_GetCJSValue(JSValue in_jsvalue) {
        static type_cjs_GetCJSValue f = (type_cjs_GetCJSValue)GetProcAddress(hm, "cjs_GetCJSValue");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_jsvalue);
    }
    /**
     * @brief 在JS数组的末尾添加一项。
     * @param in_array 数组(JS值)。
     * @param in_item 新项值(JS值)。
     * @return 操作状态。
     */
    CJSBool CJS_ArrayPushBack(CJSValue in_array, CJSValue in_item) {
        static type_cjs_ArrayPushBack f = (type_cjs_ArrayPushBack)GetProcAddress(hm, "cjs_ArrayPushBack");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_array, in_item);
    }
    /**
     * @brief 删除JS数组的最后一项。
     * @param in_array 数组(JS值)。
     * @return 操作状态。
     */
    CJSBool CJS_ArrayPopBack(CJSValue in_array) {
        static type_cjs_ArrayPopBack f = (type_cjs_ArrayPopBack)GetProcAddress(hm, "cjs_ArrayPopBack");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_array);
    }
    /**
     * @brief 在JS数组指定索引位置插入一项。
     * @param in_array 数组(JS值)。
     * @param insert_idx 插入位置的索引（从0开始）。
     * @param in_item 新项值(JS值)。
     * @return 操作状态。
     */
    CJSBool CJS_ArrayInsert(CJSValue in_array, cjs_uint64 insert_idx, CJSValue in_item) {
        static type_cjs_ArrayInsert f = (type_cjs_ArrayInsert)GetProcAddress(hm, "cjs_ArrayInsert");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_array, insert_idx, in_item);
    }
    /**
     * @brief 删除JS数组指定索引位置的项。
     * @param in_array 数组(JS值)。
     * @param erase_idx 要删除项的索引（从0开始）。
     * @return 操作状态。
     */
    CJSBool CJS_ArrayErase(CJSValue in_array, cjs_uint64 erase_idx) {
        static type_cjs_ArrayErase f = (type_cjs_ArrayErase)GetProcAddress(hm, "cjs_ArrayErase");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_array, erase_idx);
    }
    /**
     * @brief 清空JS数组的所有项。
     * @param in_array 数组(JS值)。
     * @return 操作状态。
     */
    CJSBool CJS_ArrayClear(CJSValue in_array) {
        static type_cjs_ArrayClear f = (type_cjs_ArrayClear)GetProcAddress(hm, "cjs_ArrayClear");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_array);
    }
    /**
     * @brief 调整JS数组的长度。
     * @param in_array 数组(JS值)。
     * @param new_size 数组新长度：小于原长度则截断，大于原长度则补undefined。
     * @return 操作状态。
     */
    CJSBool CJS_ArrayResize(CJSValue in_array, cjs_uint64 new_size) {
        static type_cjs_ArrayResize f = (type_cjs_ArrayResize)GetProcAddress(hm, "cjs_ArrayResize");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_array, new_size);
    }
    /**
     * @brief 替换JS数组的所有内容为指定数量的同一项。
     * @param in_array 数组(JS值)。
     * @param count 新数组的元素个数。
     * @param in_item 填充的元素值(JS值)。
     * @return 操作状态。
     */
    CJSBool CJS_ArrayAssign(CJSValue in_array, cjs_uint64 count, CJSValue in_item) {
        static type_cjs_ArrayAssign f = (type_cjs_ArrayAssign)GetProcAddress(hm, "cjs_ArrayAssign");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_array, count, in_item);
    }
    /**
     * @brief 获取JS数组指定索引位置的项。
     * @param in_array 数组(JS值)。
     * @param idx 要获取项的索引（从0开始）。
     * @return 索引对应的值(JS值)，越界/失败返回空值。
     */
    CJSValue CJS_ArrayAt(CJSValue in_array, cjs_uint64 idx) {
        static type_cjs_ArrayAt f = (type_cjs_ArrayAt)GetProcAddress(hm, "cjs_ArrayAt");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_array, idx);
    }
    /**
     * @brief 复制一份CJSValue(引用计数为1)。
     * @param in_cjsv 源CJSValue。
     * @return 新的CJSValue。
     */
    CJSValue CJS_DupValue(CJSValue in_cjsv) {
        static type_cjs_DupValue f = (type_cjs_DupValue)GetProcAddress(hm, "cjs_DupValue");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_cjsv);
    }
    /**
     * @brief 释放堆上指针的资源。
     * @param in_byte 堆上指针。
     * @return 操作状态。
     */
    CJSBool CJS_FreeValue(CJSPtr in_byte) {
        static type_cjs_FreeValue f = (type_cjs_FreeValue)GetProcAddress(hm, "cjs_FreeValue");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_byte);
    }
    /**
     * @brief 读取JS值(ArrayBuffer + ArrayBufferView)。
     * @param in_cjsv JS值。
     * @param out_size 二进制大小。
     * @param out_data 二进制体指针(连续)。
     * @return 操作状态。
     */
    CJSBool CJS_ReadAsArrayBufferView(CJSValue in_cjsv, cjs_size* out_size, cjs_byte** out_data) {
        static type_cjs_ReadAsArrayBufferView f = (type_cjs_ReadAsArrayBufferView)GetProcAddress(hm, "cjs_ReadAsArrayBufferView");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_cjsv, out_size, out_data);
    }
    /**
     * @brief 读取JS值(ArrayBuffer)。
     * @param in_cjsv JS值。
     * @param out_size 二进制大小。
     * @param out_data 二进制体指针(连续)。
     * @return 操作状态。
     */
    CJSBool CJS_ReadAsArrayBuffer(CJSValue in_cjsv, cjs_size* out_size, cjs_byte** out_data) {
        static type_cjs_ReadAsArrayBuffer f = (type_cjs_ReadAsArrayBuffer)GetProcAddress(hm, "cjs_ReadAsArrayBuffer");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_cjsv, out_size, out_data);
    }
    /**
     * @brief 读取JS值(Uint8Array)。
     * @param in_cjsv JS值。
     * @param out_size 二进制大小。
     * @param out_data 二进制体指针(连续)。
     * @return 操作状态。
     */
    CJSBool CJS_ReadAsUint8Array(CJSValue in_cjsv, cjs_size* out_size, cjs_byte** out_data) {
        static type_cjs_ReadAsUint8Array f = (type_cjs_ReadAsUint8Array)GetProcAddress(hm, "cjs_ReadAsUint8Array");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_cjsv, out_size, out_data);
    }
    /**
     * @brief 读取JS值(Uint16Array)。
     * @param in_cjsv JS值。
     * @param out_size 二进制大小。
     * @param out_data 二进制体指针(连续)。
     * @return 操作状态。
     */
    CJSBool CJS_ReadAsUint16Array(CJSValue in_cjsv, cjs_size* out_size, cjs_byte** out_data) {
        static type_cjs_ReadAsUint16Array f = (type_cjs_ReadAsUint16Array)GetProcAddress(hm, "cjs_ReadAsUint16Array");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_cjsv, out_size, out_data);
    }
    /**
     * @brief 读取JS值(Uint32Array)。
     * @param in_cjsv JS值。
     * @param out_size 二进制大小。
     * @param out_data 二进制体指针(连续)。
     * @return 操作状态。
     */
    CJSBool CJS_ReadAsUint32Array(CJSValue in_cjsv, cjs_size* out_size, cjs_byte** out_data) {
        static type_cjs_ReadAsUint32Array f = (type_cjs_ReadAsUint32Array)GetProcAddress(hm, "cjs_ReadAsUint32Array");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_cjsv, out_size, out_data);
    }
    /**
     * @brief 读取JS值(Int8Array)。
     * @param in_cjsv JS值。
     * @param out_size 二进制大小。
     * @param out_data 二进制体指针(连续)。
     * @return 操作状态。
     */
    CJSBool CJS_ReadAsInt8Array(CJSValue in_cjsv, cjs_size* out_size, cjs_byte** out_data) {
        static type_cjs_ReadAsInt8Array f = (type_cjs_ReadAsInt8Array)GetProcAddress(hm, "cjs_ReadAsInt8Array");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_cjsv, out_size, out_data);
    }
    /**
     * @brief 读取JS值(Int16Array)。
     * @param in_cjsv JS值。
     * @param out_size 二进制大小。
     * @param out_data 二进制体指针(连续)。
     * @return 操作状态。
     */
    CJSBool CJS_ReadAsInt16Array(CJSValue in_cjsv, cjs_size* out_size, cjs_byte** out_data) {
        static type_cjs_ReadAsInt16Array f = (type_cjs_ReadAsInt16Array)GetProcAddress(hm, "cjs_ReadAsInt16Array");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_cjsv, out_size, out_data);
    }
    /**
     * @brief 读取JS值(Int8Array)。
     * @param in_cjsv JS值。
     * @param out_size 二进制大小。
     * @param out_data 二进制体指针(连续)。
     * @return 操作状态。
     */
    CJSBool CJS_ReadAsInt32Array(CJSValue in_cjsv, cjs_size* out_size, cjs_byte** out_data) {
        static type_cjs_ReadAsInt32Array f = (type_cjs_ReadAsInt32Array)GetProcAddress(hm, "cjs_ReadAsInt32Array");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_cjsv, out_size, out_data);
    }
    /**
     * @brief 读取JS值(Boolean)。
     * @param in_cjsv JS值。
     * @param out_data 输出数据。
     * @return 操作状态。
     */
    CJSBool CJS_ReadAsBool(CJSValue in_cjsv, cjs_bool* out_data) {
        static type_cjs_ReadAsBool f = (type_cjs_ReadAsBool)GetProcAddress(hm, "cjs_ReadAsBool");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_cjsv, out_data);
    }
    /**
     * @brief 读取JS值(String)。
     * @param in_cjsv JS值。
     * @param out_data 输出数据（堆内存字符串指针，需调用CJS_FreeValue释放）。
     * @return 操作状态。
     */
    CJSBool CJS_ReadAsString(CJSValue in_cjsv, cjs_string* out_data) {
        static type_cjs_ReadAsString f = (type_cjs_ReadAsString)GetProcAddress(hm, "cjs_ReadAsString");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_cjsv, out_data);
    }
    /**
     * @brief 读取JS值(Int32)。
     * @param in_cjsv JS值。
     * @param out_data 输出数据。
     * @return 操作状态。
     */
    CJSBool CJS_ReadAsInt32(CJSValue in_cjsv, cjs_int32* out_data) {
        static type_cjs_ReadAsInt32 f = (type_cjs_ReadAsInt32)GetProcAddress(hm, "cjs_ReadAsInt32");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_cjsv, out_data);
    }
    /**
     * @brief 读取JS值(Int64)。
     * @param in_cjsv JS值。
     * @param out_data 输出数据。
     * @return 操作状态。
     */
    CJSBool CJS_ReadAsInt64(CJSValue in_cjsv, cjs_int64* out_data) {
        static type_cjs_ReadAsInt64 f = (type_cjs_ReadAsInt64)GetProcAddress(hm, "cjs_ReadAsInt64");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_cjsv, out_data);
    }
    /**
     * @brief 读取JS值(Uint64)。
     * @param in_cjsv JS值。
     * @param out_data 输出数据。
     * @return 操作状态。
     */
    CJSBool CJS_ReadAsUint64(CJSValue in_cjsv, cjs_uint64* out_data) {
        static type_cjs_ReadAsUint64 f = (type_cjs_ReadAsUint64)GetProcAddress(hm, "cjs_ReadAsUint64");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_cjsv, out_data);
    }
    /**
     * @brief 读取JS值(Double)。
     * @param in_cjsv JS值。
     * @param out_data 输出数据。
     * @return 操作状态。
     */
    CJSBool CJS_ReadAsDouble(CJSValue in_cjsv, cjs_double* out_data) {
        static type_cjs_ReadAsDouble f = (type_cjs_ReadAsDouble)GetProcAddress(hm, "cjs_ReadAsDouble");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_cjsv, out_data);
    }
    /**
     * @brief 在指定位置执行一段JS脚本。
     * @param in_cjsv 位置。
     * @param in_code 脚本。
     * @param in_path 可选路径。
     * @return 脚本的最后一次执行的返回值。
     */
    CJSValue CJS_Eval(CJSValue in_cjsv, cjs_string in_code, cjs_string in_path) {
        static type_cjs_Eval f = (type_cjs_Eval)GetProcAddress(hm, "cjs_Eval");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_cjsv, in_code, in_path);
    }
    /**
     * @brief 判断JS值是否为undefined。
     * @param in_cjsv JS值。
     * @return 结果。
     */
    CJSBool CJS_IsUndefined(CJSValue in_cjsv) {
        static type_cjs_IsXXX f = (type_cjs_IsXXX)GetProcAddress(hm, "cjs_IsUndefined");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_cjsv);
    }
    /**
     * @brief 判断JS值是否为null。
     * @param in_cjsv JS值。
     * @return 结果。
     */
    CJSBool CJS_IsNull(CJSValue in_cjsv) {
        static type_cjs_IsXXX f = (type_cjs_IsXXX)GetProcAddress(hm, "cjs_IsNull");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_cjsv);
    }
    /**
     * @brief 判断JS值是否为number。
     * @param in_cjsv JS值。
     * @return 结果。
     */
    CJSBool CJS_IsNumber(CJSValue in_cjsv) {
        static type_cjs_IsXXX f = (type_cjs_IsXXX)GetProcAddress(hm, "cjs_IsNumber");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_cjsv);
    }
    /**
     * @brief 判断JS值是否为bigint。
     * @param in_cjsv JS值。
     * @return 结果。
     */
    CJSBool CJS_IsBigInt(CJSValue in_cjsv) {
        static type_cjs_IsXXX f = (type_cjs_IsXXX)GetProcAddress(hm, "cjs_IsBigInt");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_cjsv);
    }
    /**
     * @brief 判断JS值是否为boolean。
     * @param in_cjsv JS值。
     * @return 结果。
     */
    CJSBool CJS_IsBool(CJSValue in_cjsv) {
        static type_cjs_IsXXX f = (type_cjs_IsXXX)GetProcAddress(hm, "cjs_IsBool");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_cjsv);
    }
    /**
     * @brief 判断JS值是否为exception。
     * @param in_cjsv JS值。
     * @return 结果。
     */
    CJSBool CJS_IsException(CJSValue in_cjsv) {
        static type_cjs_IsXXX f = (type_cjs_IsXXX)GetProcAddress(hm, "cjs_IsException");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_cjsv);
    }
    /**
     * @brief 判断JS值是否为uninitialized。
     * @param in_cjsv JS值。
     * @return 结果。
     */
    CJSBool CJS_IsUninitialized(CJSValue in_cjsv) {
        static type_cjs_IsXXX f = (type_cjs_IsXXX)GetProcAddress(hm, "cjs_IsUninitialized");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_cjsv);
    }
    /**
     * @brief 判断JS值是否为string。
     * @param in_cjsv JS值。
     * @return 结果。
     */
    CJSBool CJS_IsString(CJSValue in_cjsv) {
        static type_cjs_IsXXX f = (type_cjs_IsXXX)GetProcAddress(hm, "cjs_IsString");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_cjsv);
    }
    /**
     * @brief 判断JS值是否为symbol。
     * @param in_cjsv JS值。
     * @return 结果。
     */
    CJSBool CJS_IsSymbol(CJSValue in_cjsv) {
        static type_cjs_IsXXX f = (type_cjs_IsXXX)GetProcAddress(hm, "cjs_IsSymbol");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_cjsv);
    }
    /**
     * @brief 判断JS值是否为object。
     * @param in_cjsv JS值。
     * @return 结果。
     */
    CJSBool CJS_IsObject(CJSValue in_cjsv) {
        static type_cjs_IsXXX f = (type_cjs_IsXXX)GetProcAddress(hm, "cjs_IsObject");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_cjsv);
    }
    /**
     * @brief 判断JS值是否为module。
     * @param in_cjsv JS值。
     * @return 结果。
     */
    CJSBool CJS_IsModule(CJSValue in_cjsv) {
        static type_cjs_IsXXX f = (type_cjs_IsXXX)GetProcAddress(hm, "cjs_IsModule");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_cjsv);
    }
    /**
     * @brief 判断JS值是否为function。
     * @param in_cjsv JS值。
     * @return 结果。
     */
    CJSBool CJS_IsFunction(CJSValue in_cjsv) {
        static type_cjs_IsXXX f = (type_cjs_IsXXX)GetProcAddress(hm, "cjs_IsFunction");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_cjsv);
    }

    /**
     * @brief 判断JS值是否为constructor。
     * @param in_cjsv JS值。
     * @return 结果。
     */
    CJSBool CJS_IsConstructor(CJSValue in_cjsv) {
        static type_cjs_IsXXX f = (type_cjs_IsXXX)GetProcAddress(hm, "cjs_IsConstructor");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_cjsv);
    }
    /**
     * @brief 判断JS值是否为regexp。
     * @param in_cjsv JS值。
     * @return 结果。
     */
    CJSBool CJS_IsRegExp(CJSValue in_cjsv) {
        static type_cjs_IsXXX f = (type_cjs_IsXXX)GetProcAddress(hm, "cjs_IsRegExp");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_cjsv);
    }
    /**
     * @brief 判断JS值是否为map。
     * @param in_cjsv JS值。
     * @return 结果。
     */
    CJSBool CJS_IsMap(CJSValue in_cjsv) {
        static type_cjs_IsXXX f = (type_cjs_IsXXX)GetProcAddress(hm, "cjs_IsMap");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_cjsv);
    }
    /**
     * @brief 判断JS值是否为set。
     * @param in_cjsv JS值。
     * @return 结果。
     */
    CJSBool CJS_IsSet(CJSValue in_cjsv) {
        static type_cjs_IsXXX f = (type_cjs_IsXXX)GetProcAddress(hm, "cjs_IsSet");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_cjsv);
    }
    /**
     * @brief 判断JS值是否为weakref。
     * @param in_cjsv JS值。
     * @return 结果。
     */
    CJSBool CJS_IsWeakRef(CJSValue in_cjsv) {
        static type_cjs_IsXXX f = (type_cjs_IsXXX)GetProcAddress(hm, "cjs_IsWeakRef");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_cjsv);
    }
    /**
     * @brief 判断JS值是否为weakset。
     * @param in_cjsv JS值。
     * @return 结果。
     */
    CJSBool CJS_IsWeakSet(CJSValue in_cjsv) {
        static type_cjs_IsXXX f = (type_cjs_IsXXX)GetProcAddress(hm, "cjs_IsWeakSet");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_cjsv);
    }
    /**
     * @brief 判断JS值是否为weakmap。
     * @param in_cjsv JS值。
     * @return 结果。
     */
    CJSBool CJS_IsWeakMap(CJSValue in_cjsv) {
        static type_cjs_IsXXX f = (type_cjs_IsXXX)GetProcAddress(hm, "cjs_IsWeakMap");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_cjsv);
    }
    /**
     * @brief 判断JS值是否为dataview。
     * @param in_cjsv JS值。
     * @return 结果。
     */
    CJSBool CJS_IsDataView(CJSValue in_cjsv) {
        static type_cjs_IsXXX f = (type_cjs_IsXXX)GetProcAddress(hm, "cjs_IsDataView");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_cjsv);
    }
    /**
     * @brief 判断JS值是否为array。
     * @param in_cjsv JS值。
     * @return 结果。
     */
    CJSBool CJS_IsArray(CJSValue in_cjsv) {
        static type_cjs_IsXXX f = (type_cjs_IsXXX)GetProcAddress(hm, "cjs_IsArray");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_cjsv);
    }
    /**
     * @brief 判断JS值是否为proxy。
     * @param in_cjsv JS值。
     * @return 结果。
     */
    CJSBool CJS_IsProxy(CJSValue in_cjsv) {
        static type_cjs_IsXXX f = (type_cjs_IsXXX)GetProcAddress(hm, "cjs_IsProxy");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_cjsv);
    }
    /**
     * @brief 判断JS值是否为error。
     * @param in_cjsv JS值。
     * @return 结果。
     */
    CJSBool CJS_IsError(CJSValue in_cjsv) {
        static type_cjs_IsXXX f = (type_cjs_IsXXX)GetProcAddress(hm, "cjs_IsError");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_cjsv);
    }
    /**
     * @brief 判断JS值是否为uncatchableerror。
     * @param in_cjsv JS值。
     * @return 结果。
     */
    CJSBool CJS_IsUncatchableError(CJSValue in_cjsv) {
        static type_cjs_IsXXX f = (type_cjs_IsXXX)GetProcAddress(hm, "cjs_IsUncatchableError");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_cjsv);
    }
    /**
     * @brief 判断JS值是否为date。
     * @param in_cjsv JS值。
     * @return 结果。
     */
    CJSBool CJS_IsDate(CJSValue in_cjsv) {
        static type_cjs_IsXXX f = (type_cjs_IsXXX)GetProcAddress(hm, "cjs_IsDate");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_cjsv);
    }
    /**
     * @brief 判断JS值是否为extensible。
     * @param in_cjsv JS值。
     * @return 结果。
     */
    int CJS_IsExtensible(CJSValue in_cjsv) {
        static type_cjs_IsXXX f = (type_cjs_IsXXX)GetProcAddress(hm, "cjs_IsExtensible");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_cjsv);
    }
    /**
     * @brief 判断JS值是否为arraybuffer。
     * @param in_cjsv JS值。
     * @return 结果。
     */
    CJSBool CJS_IsArrayBuffer(CJSValue in_cjsv) {
        static type_cjs_IsXXX f = (type_cjs_IsXXX)GetProcAddress(hm, "cjs_IsArrayBuffer");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_cjsv);
    }
    /**
     * @brief 判断两个JS值是否相等。
     * @param in_cjsv1 JS值。
     * @param in_cjsv2 JS值。
     * @return 结果。
     */
    CJSBool CJS_IsSameValue(CJSValue in_cjsv1, CJSValue in_cjsv2) {
        static type_cjs_IsDoubleXXX f = (type_cjs_IsDoubleXXX)GetProcAddress(hm, "cjs_IsSameValue");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_cjsv1, in_cjsv2);
    }
    /**
     * @brief 判断两个JS值是否相等。
     * @param in_cjsv1 JS值。
    * @param in_cjsv2 JS值。
    * @return 结果。
    */
    int CJS_IsEqual(CJSValue in_cjsv1, CJSValue in_cjsv2) {
        static type_cjs_IsDoubleXXX f = (type_cjs_IsDoubleXXX)GetProcAddress(hm, "cjs_IsEqual");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_cjsv1, in_cjsv2);
    }
    /**
     * @brief 判断两个JS值是否严格相等。
     * @param in_cjsv1 JS值。
     * @param in_cjsv2 JS值。
     * @return 结果。
     */
    CJSBool CJS_IsStrictEqual(CJSValue in_cjsv1, CJSValue in_cjsv2) {
        static type_cjs_IsDoubleXXX f = (type_cjs_IsDoubleXXX)GetProcAddress(hm, "cjs_IsStrictEqual");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_cjsv1, in_cjsv2);
    }
    /**
     * @brief 判断两个JS值是否零值相等。
     * @param in_cjsv1 JS值。
     * @param in_cjsv2 JS值。
     * @return 结果。
     */
    CJSBool CJS_IsSameValueZero(CJSValue in_cjsv1, CJSValue in_cjsv2) {
        static type_cjs_IsDoubleXXX f = (type_cjs_IsDoubleXXX)GetProcAddress(hm, "cjs_IsSameValueZero");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_cjsv1, in_cjsv2);
    }
    /**
     * @brief 判断JS值是否为构造对象实例。
     * @param in_cjsv JS值。
     * @param in_instance 构造对象。
     * @return 结果。
     */
    int CJS_IsInstanceOf(CJSValue in_cjsv, CJSValue in_instance) {
        static type_cjs_IsDoubleXXX f = (type_cjs_IsDoubleXXX)GetProcAddress(hm, "cjs_IsInstanceOf");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_cjsv, in_instance);
    }
    /**
    * @brief 判断JS值是否为promise。
     * @param in_cjsv JS值。
     * @return 结果。
     */
    CJSBool CJS_IsPromise(CJSValue in_cjsv) {
        static type_cjs_IsXXX f = (type_cjs_IsXXX)GetProcAddress(hm, "cjs_IsPromise");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_cjsv);
    }
    /**
     * @brief 判断JS值是否为formdata。
     * @param in_cjsv JS值。
     * @return 结果。
     */
    CJSBool CJS_IsFormData(CJSValue in_cjsv) {
        static type_cjs_IsXXX f = (type_cjs_IsXXX)GetProcAddress(hm, "cjs_IsFormData");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_cjsv);
    }
    /**
     * @brief 判断JS值是否为blob。
     * @param in_cjsv JS值。
     * @return 结果。
     */
    CJSBool CJS_IsBlob(CJSValue in_cjsv) {
        static type_cjs_IsXXX f = (type_cjs_IsXXX)GetProcAddress(hm, "cjs_IsBlob");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_cjsv);
    }
    /**
     * @brief 获取一个已决议的Promise的结果。
     * @param in_promise Promise实例。
     * @return 结果。
     */
    CJSValue CJS_PromiseGetResult(CJSValue in_promise) {
        static type_cjs_PromiseGetResult f = (type_cjs_PromiseGetResult)GetProcAddress(hm, "cjs_PromiseGetResult");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_promise);
    }
    /**
     * @brief 获取一个Promise的决议状态。
     * @param in_promise Promise实例。
     * @return 状态。
     */
    CJSPromiseState CJS_PromiseGetState(CJSValue in_promise) {
        static type_cjs_PromiseGetState f = (type_cjs_PromiseGetState)GetProcAddress(hm, "cjs_PromiseGetState");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_promise);
    }
    /**
     * @brief 设置一个未被决议的Promise的决议状态为已满足。
     * @param in_promise Promise实例。
     * @param in_value 决议值。
     * @return 操作状态。
     */
    CJSBool CJS_PromiseResolve(CJSValue in_promise, CJSValue in_value) {
        static type_cjs_PromiseResolveReject f = (type_cjs_PromiseResolveReject)GetProcAddress(hm, "cjs_PromiseResolve");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_promise, in_value);
    }
    /**
     * @brief 设置一个未被决议的Promise的决议状态为已拒绝。
     * @param in_promise Promise实例。
     * @param in_value 决议值。
     * @return 操作状态。
     */
    CJSBool CJS_PromiseReject(CJSValue in_promise, CJSValue in_value) {
        static type_cjs_PromiseResolveReject f = (type_cjs_PromiseResolveReject)GetProcAddress(hm, "cjs_PromiseReject");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_promise, in_value);
    }
    /**
     * @brief 向任务队列中添加一个待执行的任务。
     * @param in_task 任务函数。
     * @param in_this 函数执行的this对象。
     * @param in_argumentCount 传入参数的数量。
     * @param in_argumentValues 传入的参数数组指针。
     * @return 任务ID。
     */
    CJSID CJS_EnqueueTask(CJSValue in_task, CJSValue in_this, cjs_int in_argumentCount, CJSValue* in_argumentValues) {
        static type_cjs_EnqueueTask f = (type_cjs_EnqueueTask)GetProcAddress(hm, "cjs_EnqueueTask");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_task, in_this, in_argumentCount, in_argumentValues);
    }
    /**
     * @brief 向任务队列中移除一个未执行的任务。
     * @param in_taskId 任务ID。
     * @return 操作状态。
     */
    CJSBool CJS_RemoveTask(CJSID in_taskId) {
        static type_cjs_RemoveTask f = (type_cjs_RemoveTask)GetProcAddress(hm, "cjs_RemoveTask");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_taskId);
    }
    /**
     * @brief 尝试在任务队列中查找一个任务。
     * @param in_taskId 任务ID。
     * @return 任务存在且已执行则返回回调结果，存在但未执行返回CJS_STATE_TASK_NOTRUNNED，否则返回CJS_ERROR。
     */
    CJSValue CJS_QueryTask(CJSID in_taskId) {
        static type_cjs_QueryTask f = (type_cjs_QueryTask)GetProcAddress(hm, "cjs_QueryTask");
        CJS_Assert(f && "方法不可用");
        return f(ctx, in_taskId);
    }
    /**
     * @brief 立即阻塞执行任务队列而非等到同步代码执行完成后执行。
     * @return 执行前的任务数。
     */
    CJSSize CJS_RunTask() {
        static type_cjs_RunTask f = (type_cjs_RunTask)GetProcAddress(hm, "cjs_RunTask");
        CJS_Assert(f && "方法不可用");
        return f(ctx);
    }


#ifdef __cplusplus
}
#endif

#endif
