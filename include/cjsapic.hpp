
#ifndef AY_CJSAPIC_HPP
#define AY_CJSAPIC_HPP

#ifdef __cplusplus
extern "C" {
#endif

#define jsm JavaScriptMethod

    bool FindCJSValue(JSMData* jsmdPtr, CJSValue cjsv, JSV& jsv) {
        auto it = jsmdPtr->hModuleCJSValueList.find(cjsv);
        if (it != jsmdPtr->hModuleCJSValueList.end()) {
            jsv = it->second;
            return true;
        }
        return false;
    }

    CAEXP bool cjs_FreeCJSValue(CJSVERSION version, CJSContext in_ctx, CJSValue in_cjsv) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) return {};
        return jsmdPtr->hModuleCJSValueList.count(in_cjsv) && jsmdPtr->hModuleCJSValueList.erase(in_cjsv);
    }
    CAEXP bool cjs_FreePromise(CJSVERSION version, CJSContext in_ctx, CJSPromise in_promise) {
        return cjs_FreeCJSValue(version, in_ctx, in_promise.promise) && cjs_FreeCJSValue(version, in_ctx, in_promise.resolve) && cjs_FreeCJSValue(version, in_ctx, in_promise.reject);
    }
    CAEXP bool cjs_FreeAllCJSValue(CJSVERSION version, CJSContext in_ctx) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) return {};
        jsmdPtr->hModuleCJSValueList.clear();
        return true;
    }

    CAEXP CJSValue cjs_NewNull(CJSVERSION version, CJSContext in_ctx) {
        JSContext* ctx = (JSContext*)in_ctx;
        return jsm::GetCJSValue(ctx, JS_NULL);
    }
    CAEXP CJSValue cjs_NewUndefined(CJSVERSION version, CJSContext in_ctx) {
        JSContext* ctx = (JSContext*)in_ctx;
        return jsm::GetCJSValue(ctx, JS_UNDEFINED);
    }
    CAEXP CJSValue cjs_NewUninititalized(CJSVERSION version, CJSContext in_ctx) {
        JSContext* ctx = (JSContext*)in_ctx;
        return jsm::GetCJSValue(ctx, JS_UNINITIALIZED);
    }
    CAEXP CJSValue cjs_GetGlobalObject(CJSVERSION version, CJSContext in_ctx) {
        JSContext* ctx = (JSContext*)in_ctx;
        return jsm::GetCJSValue(ctx, jsm::NewGlobalObject(ctx));
    }
    CAEXP CJSValue cjs_NewString(CJSVERSION version, CJSContext in_ctx, cjs_string in_propName) {
        JSContext* ctx = (JSContext*)in_ctx;
        return jsm::GetCJSValue(ctx, jsm::NewString(ctx, wstringToString(in_propName)));
    }
    CAEXP CJSValue cjs_NewBool(CJSVERSION version, CJSContext in_ctx, cjs_bool in_bool) {
        JSContext* ctx = (JSContext*)in_ctx;
        return jsm::GetCJSValue(ctx, jsm::NewBool(ctx, in_bool));
    }
    CAEXP CJSValue cjs_NewNumber(CJSVERSION version, CJSContext in_ctx, cjs_double in_num) {
        JSContext* ctx = (JSContext*)in_ctx;
        return jsm::GetCJSValue(ctx, jsm::NewNumber(ctx, in_num));
    }
    CAEXP CJSValue cjs_NewInt64(CJSVERSION version, CJSContext in_ctx, cjs_int64 in_num) {
        JSContext* ctx = (JSContext*)in_ctx;
        return jsm::GetCJSValue(ctx, jsm::NewInt64(ctx, in_num));
    }
    CAEXP CJSValue cjs_NewDouble(CJSVERSION version, CJSContext in_ctx, cjs_double in_num) {
        JSContext* ctx = (JSContext*)in_ctx;
        return jsm::GetCJSValue(ctx, jsm::NewDouble(ctx, in_num));
    }
    CAEXP CJSValue cjs_NewUint64(CJSVERSION version, CJSContext in_ctx, cjs_uint64 in_num) {
        JSContext* ctx = (JSContext*)in_ctx;
        return jsm::GetCJSValue(ctx, jsm::NewUint64(ctx, in_num));
    }
    CAEXP CJSValue cjs_NewArrayBuffer(CJSVERSION version, CJSContext in_ctx, cjs_size in_byte_size, cjs_byte* in_byte) {
        JSContext* ctx = (JSContext*)in_ctx;
        return jsm::GetCJSValue(ctx, jsm::NewArrayBuffer(ctx, BYTEBUFFER(in_byte, in_byte + in_byte_size)));
    }
    CAEXP CJSValue cjs_NewError(CJSVERSION version, CJSContext in_ctx) {
        JSContext* ctx = (JSContext*)in_ctx;
        return jsm::GetCJSValue(ctx, jsm::NewError(ctx));
    }
    CAEXP CJSValue cjs_NewTypeError(CJSVERSION version, CJSContext in_ctx, cjs_string in_error) {
        JSContext* ctx = (JSContext*)in_ctx;
        return jsm::GetCJSValue(ctx, jsm::NewTypeError(ctx, wstringToString(in_error)));
    }
    CAEXP CJSValue cjs_NewRangeError(CJSVERSION version, CJSContext in_ctx, cjs_string in_error) {
        JSContext* ctx = (JSContext*)in_ctx;
        return jsm::GetCJSValue(ctx, jsm::NewRangeError(ctx, wstringToString(in_error)));
    }
    CAEXP CJSValue cjs_NewSyntaxError(CJSVERSION version, CJSContext in_ctx, cjs_string in_error) {
        JSContext* ctx = (JSContext*)in_ctx;
        return jsm::GetCJSValue(ctx, jsm::NewSyntaxError(ctx, wstringToString(in_error)));
    }
    CAEXP CJSValue cjs_NewInternalError(CJSVERSION version, CJSContext in_ctx, cjs_string in_error) {
        JSContext* ctx = (JSContext*)in_ctx;
        return jsm::GetCJSValue(ctx, jsm::NewInternalError(ctx, wstringToString(in_error)));
    }
    CAEXP CJSValue cjs_NewPlainError(CJSVERSION version, CJSContext in_ctx, cjs_string in_error) {
        JSContext* ctx = (JSContext*)in_ctx;
        return jsm::GetCJSValue(ctx, jsm::NewPlainError(ctx, wstringToString(in_error)));
    }
    CAEXP CJSValue cjs_NewObject(CJSVERSION version, CJSContext in_ctx) {
        JSContext* ctx = (JSContext*)in_ctx;
        return jsm::GetCJSValue(ctx, jsm::NewObject(ctx));
    }
    CAEXP CJSValue cjs_NewArray(CJSVERSION version, CJSContext in_ctx) {
        JSContext* ctx = (JSContext*)in_ctx;
        return jsm::GetCJSValue(ctx, jsm::NewArray(ctx, {}));
    }
    CAEXP CJSValue cjs_NewFunction(CJSVERSION version, CJSContext in_ctx, cjs_string in_name, cjs_function in_func, cjs_int argLength = -1) {
        JSContext* ctx = (JSContext*)in_ctx;
        return jsm::GetCJSValue(ctx, jsm::NewFunction(ctx, wstringToString(in_name), in_func, argLength));
    }
    CAEXP CJSValue cjs_NewConstructor(CJSVERSION version, CJSContext in_ctx, cjs_string in_name, cjs_function in_func, cjs_int argLength = -1) {
        JSContext* ctx = (JSContext*)in_ctx;
        return jsm::GetCJSValue(ctx, jsm::NewConstructor(ctx, wstringToString(in_name), in_func, argLength));
    }
    CAEXP CJSValue cjs_NewIterator(CJSVERSION version, CJSContext in_ctx, CJSValue in_obj, cjs_string in_name, cjs_function in_func, cjs_int64 flags = -1) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) return {};
        JSV obj = {};
        if (!FindCJSValue(jsmdPtr, in_obj, obj)) {
            return {};
        }
        return jsm::GetCJSValue(ctx, jsm::NewIterator(ctx, obj, wstringToString(in_name), in_func, flags));
    }
    CAEXP CJSValue cjs_NewUint8Array(CJSVERSION version, CJSContext in_ctx, cjs_size in_byte_size, cjs_byte* in_byte) {
        JSContext* ctx = (JSContext*)in_ctx;
        return jsm::GetCJSValue(ctx, jsm::NewUint8Array(ctx, BYTEBUFFER(in_byte, in_byte + in_byte_size)));
    }
    CAEXP CJSValue cjs_NewUint16Array(CJSVERSION version, CJSContext in_ctx, cjs_size in_byte_size, cjs_byte* in_byte) {
        JSContext* ctx = (JSContext*)in_ctx;
        return jsm::GetCJSValue(ctx, jsm::NewUint16Array(ctx, BYTEBUFFER(in_byte, in_byte + in_byte_size)));
    }
    CAEXP CJSValue cjs_NewUint32Array(CJSVERSION version, CJSContext in_ctx, cjs_size in_byte_size, cjs_byte* in_byte) {
        JSContext* ctx = (JSContext*)in_ctx;
        return jsm::GetCJSValue(ctx, jsm::NewUint32Array(ctx, BYTEBUFFER(in_byte, in_byte + in_byte_size)));
    }
    CAEXP CJSValue cjs_NewInt8Array(CJSVERSION version, CJSContext in_ctx, cjs_size in_byte_size, cjs_byte* in_byte) {
        JSContext* ctx = (JSContext*)in_ctx;
        return jsm::GetCJSValue(ctx, jsm::NewInt8Array(ctx, BYTEBUFFER(in_byte, in_byte + in_byte_size)));
    }
    CAEXP CJSValue cjs_NewInt16Array(CJSVERSION version, CJSContext in_ctx, cjs_size in_byte_size, cjs_byte* in_byte) {
        JSContext* ctx = (JSContext*)in_ctx;
        return jsm::GetCJSValue(ctx, jsm::NewInt16Array(ctx, BYTEBUFFER(in_byte, in_byte + in_byte_size)));
    }
    CAEXP CJSValue cjs_NewInt32Array(CJSVERSION version, CJSContext in_ctx, cjs_size in_byte_size, cjs_byte* in_byte) {
        JSContext* ctx = (JSContext*)in_ctx;
        return jsm::GetCJSValue(ctx, jsm::NewInt32Array(ctx, BYTEBUFFER(in_byte, in_byte + in_byte_size)));
    }
    CAEXP CJSPromise cjs_NewPromise(CJSVERSION version, CJSContext in_ctx) {
        JSContext* ctx = (JSContext*)in_ctx;
        CJSPromise promise = {};
        Promise opromise = jsm::NewPromise(ctx);
        promise.promise = jsm::GetCJSValue(ctx, opromise.promise);
        promise.reject = jsm::GetCJSValue(ctx, opromise.reject);
        promise.resolve = jsm::GetCJSValue(ctx, opromise.resolve);
        return promise;
    }
    CAEXP CJSValue cjs_GetProperty(CJSVERSION version, CJSContext in_ctx, CJSValue in_obj, CJSValue in_propName) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) return {};
        JSV obj = {};
        JSV propName = {};
        if (!FindCJSValue(jsmdPtr, in_obj, obj) || !FindCJSValue(jsmdPtr, in_propName, propName)) {
            return {};
        }
        JSV property = {};
        bool ret = jsm::ReadObjectPropertyValue(ctx, obj, propName, property);
        return (!ret) ? CJS_ERROR : jsm::GetCJSValue(ctx, property);
    }
    CAEXP CJSArgumentPackage cjs_GetArgumentPackage(CJSVERSION version, JSContext* in_ctx, JSValueConst in_thisVal, int in_argumentCount, JSValueConst* in_argumentValues) {

        JSMData* jsmdPtr = nullptr;
        if (!GetData(in_ctx, &jsmdPtr) || jsmdPtr == nullptr) return {};

        CJSContext ctx = (CJSContext)in_ctx;
        CJSValue thisVal = jsm::GetCJSValue(in_ctx, JSV(in_ctx, in_thisVal).cget(1).cset(1));
        std::vector<CJSValue> argument = {};
        for (int i = 0; i < in_argumentCount; i++) {
            JSV arg = JSV(in_ctx, in_argumentValues[i]).cget(1).cset(1);
            argument.push_back(jsm::GetCJSValue(in_ctx, arg));
        }
        CJSValue* argumentValues = nullptr;
        size_t argumentCount = CopyVectorData(argument, &argumentValues);
        argument.clear();

        CJSID id = jsm::GetNewArgumentPackageId(in_ctx);
        jsmdPtr->argumentPackageList[id].id = id;
        jsmdPtr->argumentPackageList[id].ctx = ctx;
        jsmdPtr->argumentPackageList[id].thisVal = thisVal;
        jsmdPtr->argumentPackageList[id].argumentValues = argumentValues;
        jsmdPtr->argumentPackageList[id].argumentCount = argumentCount;

        return jsmdPtr->argumentPackageList[id];
    }
    CAEXP bool cjs_FreeArgumentPackage(CJSVERSION version, CJSArgumentPackage cap) {
        JSMData* jsmdPtr = nullptr;
        if (!GetData((JSContext*)cap.ctx, &jsmdPtr) || jsmdPtr == nullptr || !jsmdPtr->argumentPackageList.count(cap.id)) return {};
        bool ret = true;
        if (!cjs_FreeCJSValue(version, cap.ctx, cap.thisVal)) ret = false;
        for (CJSSize i = 0; i < cap.argumentCount; i++) {
            if (!cjs_FreeCJSValue(version, cap.ctx, cap.argumentValues[i])) ret = false;
        }
        delete[] cap.argumentValues;
        if (!jsmdPtr->argumentPackageList.erase(cap.id)) ret = false;
        return ret;
    }
    CAEXP bool cjs_SetProperty(CJSVERSION version, CJSContext in_ctx, CJSValue in_cjsv, CJSValue in_propName, CJSValue in_propValue, cjs_int64 flags) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) return {};
        JSV jsv = {};
        JSV propName = {};
        JSV propValue = {};
        if (!FindCJSValue(jsmdPtr, in_cjsv, jsv) || !FindCJSValue(jsmdPtr, in_propName, propName) || !FindCJSValue(jsmdPtr, in_propValue, propValue)) {
            return {};
        }
        return jsm::SetAttribute(ctx, jsv, propName, propValue, flags);
    }
    CAEXP bool cjs_SetPrototype(CJSVERSION version, CJSContext in_ctx, CJSValue in_cjsv, CJSValue in_target) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) return {};
        JSV jsv = {};
        JSV target = {};
        if (!FindCJSValue(jsmdPtr, in_cjsv, jsv) || !FindCJSValue(jsmdPtr, in_target, target)) {
            return {};
        }
        return jsm::SetPrototype(ctx, jsv, target);
    }
    CAEXP CJSValue cjs_GetPrototype(CJSVERSION version, CJSContext in_ctx, CJSValue in_cjsv) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) return {};
        JSV jsv = {};
        if (!FindCJSValue(jsmdPtr, in_cjsv, jsv)) {
            return {};
        }
        return jsm::GetCJSValue(ctx, jsm::GetPrototype(ctx, jsv));
    }
    CAEXP bool cjs_RemoveProperty(CJSVERSION version, CJSContext in_ctx, CJSValue in_cjsv, CJSValue in_propName) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) return {};
        JSV jsv = {};
        JSV propName = {};
        if (!FindCJSValue(jsmdPtr, in_cjsv, jsv) || !FindCJSValue(jsmdPtr, in_propName, propName)) {
            return {};
        }
        return jsm::RemoveAttribute(ctx, jsv, propName);
    }
    CAEXP JSValue cjs_GetOriginValue(CJSVERSION version, CJSContext in_ctx, CJSValue in_cjsv) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) return {};
        JSV jsv = {};
        if (!FindCJSValue(jsmdPtr, in_cjsv, jsv)) {
            return {};
        }
        return jsv.get(0);
    }
    CAEXP JSValue cjs_GetReturnValue(CJSVERSION version, CJSContext in_ctx, CJSValue in_cjsv) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) return {};
        JSV jsv = {};
        if (!FindCJSValue(jsmdPtr, in_cjsv, jsv)) {
            return {};
        }
        jsmdPtr->argumentPackageList.erase(in_cjsv);
        return jsv.get(1);
    }
    CAEXP JSContext* cjs_GetOriginContext(CJSVERSION version, CJSContext in_ctx) {
        return (JSContext*)in_ctx;
    }
    CAEXP CJSValue cjs_CallFunction(CJSVERSION version, CJSContext in_ctx, CJSValue in_func, CJSValue in_this, cjs_int in_argumentCount, CJSValue* in_argumentValues) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) return {};

        JSV func = {};
        JSV thisVal = {};
        if (!FindCJSValue(jsmdPtr, in_func, func) || !FindCJSValue(jsmdPtr, in_this, thisVal)) {
            return {};
        }
        std::vector<JSV> argument = {};
        for (cjs_int i = 0; i < in_argumentCount; i++) {
            JSV arg = {};
            if (!FindCJSValue(jsmdPtr, in_argumentValues[i], arg)) {
                return {};
            }
            argument.push_back(arg);
        }
        return jsm::GetCJSValue(ctx, jsm::CallFunction(ctx, func, thisVal, argument));
    }
    CAEXP CJSValue cjs_CallConstructor(CJSVERSION version, CJSContext in_ctx, CJSValue in_func, cjs_int in_argumentCount, CJSValue* in_argumentValues) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) return {};

        JSV func = {};
        if (!FindCJSValue(jsmdPtr, in_func, func)) {
            return {};
        }
        std::vector<JSV> argument = {};
        for (cjs_int i = 0; i < in_argumentCount; i++) {
            JSV arg = {};
            if (!FindCJSValue(jsmdPtr, in_argumentValues[i], arg)) {
                return {};
            }
            argument.push_back(arg);
        }
        return jsm::GetCJSValue(ctx, jsm::CallConstructor(ctx, func, argument));
    }
    CAEXP CJSValue cjs_GetCJSValue(CJSVERSION version, CJSContext in_ctx, JSValue in_jsvalue) {
        JSContext* ctx = (JSContext*)in_ctx;
        return jsm::GetCJSValue(ctx, JSV(ctx, in_jsvalue).cset(1));
    }
    CAEXP bool cjs_ArrayPushBack(CJSVERSION version, CJSContext in_ctx, CJSValue in_array, CJSValue in_item) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) return {};
        JSV array = {};
        JSV item = {};
        if (!FindCJSValue(jsmdPtr, in_array, array) || !FindCJSValue(jsmdPtr, in_item, item)) {
            return {};
        }
        return jsm::ArrayPushBack(ctx, array, item);
    }
    CAEXP bool cjs_ArrayPopBack(CJSVERSION version, CJSContext in_ctx, CJSValue in_array) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) return {};
        JSV array = {};
        if (!FindCJSValue(jsmdPtr, in_array, array)) {
            return {};
        }
        return jsm::ArrayPopBack(ctx, array);
    }
    CAEXP bool cjs_ArrayInsert(CJSVERSION version, CJSContext in_ctx, CJSValue in_array, cjs_uint64 insert_idx, CJSValue in_item) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) return {};
        JSV array = {};
        JSV item = {};
        if (!FindCJSValue(jsmdPtr, in_array, array) || !FindCJSValue(jsmdPtr, in_item, item)) {
            return {};
        }
        return jsm::ArrayInsert(ctx, array, insert_idx, item);
    }
    CAEXP bool cjs_ArrayErase(CJSVERSION version, CJSContext in_ctx, CJSValue in_array, cjs_uint64 erase_idx) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) return {};
        JSV array = {};
        if (!FindCJSValue(jsmdPtr, in_array, array)) {
            return {};
        }
        return jsm::ArrayErase(ctx, array, erase_idx);
    }
    CAEXP bool cjs_ArrayClear(CJSVERSION version, CJSContext in_ctx, CJSValue in_array) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) return {};
        JSV array = {};
        if (!FindCJSValue(jsmdPtr, in_array, array)) {
            return {};
        }
        return jsm::ArrayClear(ctx, array);
    }
    CAEXP bool cjs_ArrayResize(CJSVERSION version, CJSContext in_ctx, CJSValue in_array, cjs_uint64 new_size) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) return {};
        JSV array = {};
        if (!FindCJSValue(jsmdPtr, in_array, array)) {
            return {};
        }
        return jsm::ArrayResize(ctx, array, new_size);
    }
    CAEXP bool cjs_ArrayAssign(CJSVERSION version, CJSContext in_ctx, CJSValue in_array, cjs_uint64 count, CJSValue in_item) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) return {};
        JSV array = {};
        JSV item = {};
        if (!FindCJSValue(jsmdPtr, in_array, array) || !FindCJSValue(jsmdPtr, in_item, item)) {
            return {};
        }
        return jsm::ArrayAssign(ctx, array, count, item);
    }
    CAEXP CJSValue cjs_ArrayAt(CJSVERSION version, CJSContext in_ctx, CJSValue in_array, cjs_uint64 idx) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) return {};
        JSV array = {};
        if (!FindCJSValue(jsmdPtr, in_array, array)) {
            return {};
        }
        JSValue js_val = jsm::ArrayAt(ctx, array, idx);
        return jsm::GetCJSValue(ctx, JSV(ctx, js_val).cset(1));
    }
    CAEXP CJSValue cjs_DupValue(CJSVERSION version, CJSContext in_ctx, CJSValue in_cjsv) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) return {};
        JSV jsv = {};
        if (!FindCJSValue(jsmdPtr, in_cjsv, jsv)) {
            return {};
        }
        return jsm::GetCJSValue(ctx, jsv);
    }
    CAEXP bool cjs_FreeValue(CJSVERSION version, CJSContext in_ctx, void* in_data) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) return {};
        for (auto& [id, data] : jsmdPtr->cjsByteDataList) {
            if (data.data == in_data) {
                FreeHeapData(data);
                jsmdPtr->cjsByteDataList.erase(id);
                return true;
            }
        }
        return false;
    }
    CAEXP bool cjs_ReadAsArrayBufferView(CJSVERSION version, CJSContext in_ctx, CJSValue in_cjsv, cjs_size* out_sizePtr, cjs_byte** out_dataPtr) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) return {};
        JSV jsv = {};
        if (!FindCJSValue(jsmdPtr, in_cjsv, jsv)) {
            return {};
        }

        BYTEBUFFER data = {};
        if (!jsm::ReadJSValueAsArrayBufferView(ctx, jsv, data)) {
            return false;
        }
        cjs_byte* dataPtr = nullptr;
        cjs_size dataSize = static_cast<cjs_size>(CopyVectorData(data, &dataPtr));

        CJSID id = jsm::GetNewCJSByteId(ctx);
        jsmdPtr->cjsByteDataList[id].data = dataPtr;
        jsmdPtr->cjsByteDataList[id].size = dataSize;
        jsmdPtr->cjsByteDataList[id].tag = 1;

        if (out_sizePtr != nullptr) *out_sizePtr = dataSize;
        if (out_dataPtr != nullptr) *out_dataPtr = dataPtr;

        return true;
    }
    CAEXP bool cjs_ReadAsArrayBuffer(CJSVERSION version, CJSContext in_ctx, CJSValue in_cjsv, cjs_size* out_sizePtr, cjs_byte** out_dataPtr) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) return {};
        JSV jsv = {};
        if (!FindCJSValue(jsmdPtr, in_cjsv, jsv)) {
            return {};
        }

        BYTEBUFFER data = {};
        if (!jsm::ReadJSValueAsArrayBuffer(ctx, jsv, data)) {
            return false;
        }
        cjs_byte* dataPtr = nullptr;
        cjs_size dataSize = static_cast<cjs_size>(CopyVectorData(data, &dataPtr));

        CJSID id = jsm::GetNewCJSByteId(ctx);
        jsmdPtr->cjsByteDataList[id].data = dataPtr;
        jsmdPtr->cjsByteDataList[id].size = dataSize;
        jsmdPtr->cjsByteDataList[id].tag = 1;

        if (out_sizePtr != nullptr) *out_sizePtr = dataSize;
        if (out_dataPtr != nullptr) *out_dataPtr = dataPtr;

        return true;
    }
    CAEXP bool cjs_ReadAsUint8Array(CJSVERSION version, CJSContext in_ctx, CJSValue in_cjsv, cjs_size* out_sizePtr, cjs_byte** out_dataPtr) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) return {};
        JSV jsv = {};
        if (!FindCJSValue(jsmdPtr, in_cjsv, jsv)) {
            return {};
        }

        BYTEBUFFER data = {};
        if (!jsm::ReadJSValueAsUint8Array(ctx, jsv, data)) {
            return false;
        }
        cjs_byte* dataPtr = nullptr;
        cjs_size dataSize = static_cast<cjs_size>(CopyVectorData(data, &dataPtr));

        CJSID id = jsm::GetNewCJSByteId(ctx);
        jsmdPtr->cjsByteDataList[id].data = dataPtr;
        jsmdPtr->cjsByteDataList[id].size = dataSize;
        jsmdPtr->cjsByteDataList[id].tag = 1;

        if (out_sizePtr != nullptr) *out_sizePtr = dataSize;
        if (out_dataPtr != nullptr) *out_dataPtr = dataPtr;

        return true;
    }
    CAEXP bool cjs_ReadAsUint16Array(CJSVERSION version, CJSContext in_ctx, CJSValue in_cjsv, cjs_size* out_sizePtr, cjs_byte** out_dataPtr) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) return {};
        JSV jsv = {};
        if (!FindCJSValue(jsmdPtr, in_cjsv, jsv)) {
            return {};
        }

        BYTEBUFFER data = {};
        if (!jsm::ReadJSValueAsUint16Array(ctx, jsv, data)) {
            return false;
        }
        cjs_byte* dataPtr = nullptr;
        cjs_size dataSize = static_cast<cjs_size>(CopyVectorData(data, &dataPtr));

        CJSID id = jsm::GetNewCJSByteId(ctx);
        jsmdPtr->cjsByteDataList[id].data = dataPtr;
        jsmdPtr->cjsByteDataList[id].size = dataSize;
        jsmdPtr->cjsByteDataList[id].tag = 1;

        if (out_sizePtr != nullptr) *out_sizePtr = dataSize;
        if (out_dataPtr != nullptr) *out_dataPtr = dataPtr;

        return true;
    }
    CAEXP bool cjs_ReadAsUint32Array(CJSVERSION version, CJSContext in_ctx, CJSValue in_cjsv, cjs_size* out_sizePtr, cjs_byte** out_dataPtr) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) return {};
        JSV jsv = {};
        if (!FindCJSValue(jsmdPtr, in_cjsv, jsv)) {
            return {};
        }

        BYTEBUFFER data = {};
        if (!jsm::ReadJSValueAsUint32Array(ctx, jsv, data)) {
            return false;
        }
        cjs_byte* dataPtr = nullptr;
        cjs_size dataSize = static_cast<cjs_size>(CopyVectorData(data, &dataPtr));

        CJSID id = jsm::GetNewCJSByteId(ctx);
        jsmdPtr->cjsByteDataList[id].data = dataPtr;
        jsmdPtr->cjsByteDataList[id].size = dataSize;
        jsmdPtr->cjsByteDataList[id].tag = 1;

        if (out_sizePtr != nullptr) *out_sizePtr = dataSize;
        if (out_dataPtr != nullptr) *out_dataPtr = dataPtr;

        return true;
    }
    CAEXP bool cjs_ReadAsInt8Array(CJSVERSION version, CJSContext in_ctx, CJSValue in_cjsv, cjs_size* out_sizePtr, cjs_byte** out_dataPtr) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) return {};
        JSV jsv = {};
        if (!FindCJSValue(jsmdPtr, in_cjsv, jsv)) {
            return {};
        }

        BYTEBUFFER data = {};
        if (!jsm::ReadJSValueAsInt8Array(ctx, jsv, data)) {
            return false;
        }
        cjs_byte* dataPtr = nullptr;
        cjs_size dataSize = static_cast<cjs_size>(CopyVectorData(data, &dataPtr));

        CJSID id = jsm::GetNewCJSByteId(ctx);
        jsmdPtr->cjsByteDataList[id].data = dataPtr;
        jsmdPtr->cjsByteDataList[id].size = dataSize;

        if (out_sizePtr != nullptr) *out_sizePtr = dataSize;
        if (out_dataPtr != nullptr) *out_dataPtr = dataPtr;
        jsmdPtr->cjsByteDataList[id].tag = 1;

        return true;
    }
    CAEXP bool cjs_ReadAsInt16Array(CJSVERSION version, CJSContext in_ctx, CJSValue in_cjsv, cjs_size* out_sizePtr, cjs_byte** out_dataPtr) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) return {};
        JSV jsv = {};
        if (!FindCJSValue(jsmdPtr, in_cjsv, jsv)) {
            return {};
        }

        BYTEBUFFER data = {};
        if (!jsm::ReadJSValueAsInt16Array(ctx, jsv, data)) {
            return false;
        }
        cjs_byte* dataPtr = nullptr;
        cjs_size dataSize = static_cast<cjs_size>(CopyVectorData(data, &dataPtr));

        CJSID id = jsm::GetNewCJSByteId(ctx);
        jsmdPtr->cjsByteDataList[id].data = dataPtr;
        jsmdPtr->cjsByteDataList[id].size = dataSize;
        jsmdPtr->cjsByteDataList[id].tag = 1;

        if (out_sizePtr != nullptr) *out_sizePtr = dataSize;
        if (out_dataPtr != nullptr) *out_dataPtr = dataPtr;

        return true;
    }
    CAEXP bool cjs_ReadAsInt32Array(CJSVERSION version, CJSContext in_ctx, CJSValue in_cjsv, cjs_size* out_sizePtr, cjs_byte** out_dataPtr) {

        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) return {};
        JSV jsv = {};
        if (!FindCJSValue(jsmdPtr, in_cjsv, jsv)) {
            return {};
        }

        BYTEBUFFER data = {};
        if (!jsm::ReadJSValueAsInt32Array(ctx, jsv, data)) {
            return false;
        }
        cjs_byte* dataPtr = nullptr;
        cjs_size dataSize = static_cast<cjs_size>(CopyVectorData(data, &dataPtr));

        CJSID id = jsm::GetNewCJSByteId(ctx);
        jsmdPtr->cjsByteDataList[id].data = (void*)dataPtr;
        jsmdPtr->cjsByteDataList[id].size = dataSize;
        jsmdPtr->cjsByteDataList[id].tag = 1;

        if (out_sizePtr != nullptr) *out_sizePtr = dataSize;
        if (out_dataPtr != nullptr) *out_dataPtr = dataPtr;

        return true;
    }
    CAEXP bool cjs_ReadAsBool(CJSVERSION version, CJSContext in_ctx, CJSValue in_cjsv, cjs_bool* out_data) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) return {};
        JSV jsv = {};
        if (!FindCJSValue(jsmdPtr, in_cjsv, jsv)) return {};
        if (!jsm::ReadJSValueAsBool(ctx, jsv, *out_data)) return false;
        return true;
    }
    CAEXP bool cjs_ReadAsString(CJSVERSION version, CJSContext in_ctx, CJSValue in_cjsv, cjs_string* out_data) {

        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) return {};
        JSV jsv = {};
        if (!FindCJSValue(jsmdPtr, in_cjsv, jsv)) {
            return {};
        }

        std::string data = {};
        if (!jsm::ReadJSValueAsString(ctx, jsv, data)) {
            return false;
        }
        cjs_string dataPtr = nullptr;
        cjs_size dataSize = static_cast<cjs_size>(CopyWstringData(stringToWstring(data), &dataPtr));

        CJSID id = jsm::GetNewCJSByteId(ctx);
        jsmdPtr->cjsByteDataList[id].data = (void*)dataPtr;
        jsmdPtr->cjsByteDataList[id].size = dataSize;
        jsmdPtr->cjsByteDataList[id].tag = 2;

        if (out_data != nullptr) *out_data = dataPtr;

        return true;
    }
    CAEXP bool cjs_ReadAsInt32(CJSVERSION version, CJSContext in_ctx, CJSValue in_cjsv, cjs_int32* out_data) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) return {};
        JSV jsv = {};
        if (!FindCJSValue(jsmdPtr, in_cjsv, jsv)) return {};
        if (!jsm::ReadJSValueAsInt32(ctx, jsv, *out_data)) return false;
        return true;
    }
    CAEXP bool cjs_ReadAsInt64(CJSVERSION version, CJSContext in_ctx, CJSValue in_cjsv, cjs_int64* out_data) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) return {};
        JSV jsv = {};
        if (!FindCJSValue(jsmdPtr, in_cjsv, jsv)) return {};
        if (!jsm::ReadJSValueAsInt64(ctx, jsv, *out_data)) return false;
        return true;
    }
    CAEXP bool cjs_ReadAsUint64(CJSVERSION version, CJSContext in_ctx, CJSValue in_cjsv, cjs_uint64* out_data) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) return {};
        JSV jsv = {};
        if (!FindCJSValue(jsmdPtr, in_cjsv, jsv)) return {};
        if (!jsm::ReadJSValueAsUint64(ctx, jsv, *out_data)) return false;
        return true;
    }
    CAEXP bool cjs_ReadAsDouble(CJSVERSION version, CJSContext in_ctx, CJSValue in_cjsv, cjs_double* out_data) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) return {};
        JSV jsv = {};
        if (!FindCJSValue(jsmdPtr, in_cjsv, jsv)) return {};
        if (!jsm::ReadJSValueAsDouble(ctx, jsv, *out_data)) return false;
        return true;
    }
    CAEXP CJSValue CJS_Eval(CJSVERSION version, CJSContext in_ctx, CJSValue in_cjsv, cjs_string in_code, cjs_string in_path) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) return {};
        JSINFO ji = jsmdPtr->js->eval(in_code, in_path);
        if (!ji.isValid) return CJS_ERROR;
        return jsm::GetCJSValue(ctx, ji.result);
    }
    CAEXP bool cjs_IsUndefined(CJSVERSION version, CJSContext in_ctx, CJSValue in_cjsv) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        JSV jsv = {};
        if (!FindCJSValue(jsmdPtr, in_cjsv, jsv)) return {};
        return JS_IsUndefined(jsv.get(0));
    }
    CAEXP bool cjs_IsNull(CJSVERSION version, CJSContext in_ctx, CJSValue in_cjsv) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        JSV jsv = {};
        if (!FindCJSValue(jsmdPtr, in_cjsv, jsv)) return {};
        return JS_IsNull(jsv.get(0));
    }
    CAEXP bool cjs_IsNumber(CJSVERSION version, CJSContext in_ctx, CJSValue in_cjsv) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        JSV jsv = {};
        if (!FindCJSValue(jsmdPtr, in_cjsv, jsv)) return {};
        return JS_IsNull(jsv.get(0));
    }
    CAEXP bool cjs_IsBigInt(CJSVERSION version, CJSContext in_ctx, CJSValue in_cjsv) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        JSV jsv = {};
        if (!FindCJSValue(jsmdPtr, in_cjsv, jsv)) return {};
        return JS_IsBigInt(jsv.get(0));
    }
    CAEXP bool cjs_IsBool(CJSVERSION version, CJSContext in_ctx, CJSValue in_cjsv) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        JSV jsv = {};
        if (!FindCJSValue(jsmdPtr, in_cjsv, jsv)) return {};
        return JS_IsBool(jsv.get(0));
    }
    CAEXP bool cjs_IsException(CJSVERSION version, CJSContext in_ctx, CJSValue in_cjsv) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        JSV jsv = {};
        if (!FindCJSValue(jsmdPtr, in_cjsv, jsv)) return {};
        return JS_IsException(jsv.get(0));
    }
    CAEXP bool cjs_IsUninitialized(CJSVERSION version, CJSContext in_ctx, CJSValue in_cjsv) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        JSV jsv = {};
        if (!FindCJSValue(jsmdPtr, in_cjsv, jsv)) return {};
        return JS_IsUninitialized(jsv.get(0));
    }
    CAEXP bool cjs_IsString(CJSVERSION version, CJSContext in_ctx, CJSValue in_cjsv) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        JSV jsv = {};
        if (!FindCJSValue(jsmdPtr, in_cjsv, jsv)) return {};
        return JS_IsString(jsv.get(0));
    }
    CAEXP bool cjs_IsSymbol(CJSVERSION version, CJSContext in_ctx, CJSValue in_cjsv) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        JSV jsv = {};
        if (!FindCJSValue(jsmdPtr, in_cjsv, jsv)) return {};
        return JS_IsSymbol(jsv.get(0));
    }
    CAEXP bool cjs_IsObject(CJSVERSION version, CJSContext in_ctx, CJSValue in_cjsv) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        JSV jsv = {};
        if (!FindCJSValue(jsmdPtr, in_cjsv, jsv)) return {};
        return JS_IsObject(jsv.get(0));
    }
    CAEXP bool cjs_IsModule(CJSVERSION version, CJSContext in_ctx, CJSValue in_cjsv) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        JSV jsv = {};
        if (!FindCJSValue(jsmdPtr, in_cjsv, jsv)) return {};
        return JS_IsModule(jsv.get(0));
    }
    CAEXP bool cjs_IsFunction(CJSVERSION version, CJSContext in_ctx, CJSValue in_cjsv) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        JSV jsv = {};
        if (!FindCJSValue(jsmdPtr, in_cjsv, jsv)) return {};
        return JS_IsFunction(ctx, jsv.get(0));
    }
    CAEXP bool cjs_IsConstructor(CJSVERSION version, CJSContext in_ctx, CJSValue in_cjsv) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        JSV jsv = {};
        if (!FindCJSValue(jsmdPtr, in_cjsv, jsv)) return {};
        return JS_IsConstructor(ctx, jsv.get(0));
    }
    CAEXP bool cjs_IsRegExp(CJSVERSION version, CJSContext in_ctx, CJSValue in_cjsv) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        JSV jsv = {};
        if (!FindCJSValue(jsmdPtr, in_cjsv, jsv)) return {};
        return JS_IsRegExp(jsv.get(0));
    }
    CAEXP bool cjs_IsMap(CJSVERSION version, CJSContext in_ctx, CJSValue in_cjsv) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        JSV jsv = {};
        if (!FindCJSValue(jsmdPtr, in_cjsv, jsv)) return {};
        return JS_IsMap(jsv.get(0));
    }
    CAEXP bool cjs_IsSet(CJSVERSION version, CJSContext in_ctx, CJSValue in_cjsv) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        JSV jsv = {};
        if (!FindCJSValue(jsmdPtr, in_cjsv, jsv)) return {};
        return JS_IsSet(jsv.get(0));
    }
    CAEXP bool cjs_IsWeakRef(CJSVERSION version, CJSContext in_ctx, CJSValue in_cjsv) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        JSV jsv = {};
        if (!FindCJSValue(jsmdPtr, in_cjsv, jsv)) return {};
        return JS_IsWeakRef(jsv.get(0));
    }
    CAEXP bool cjs_IsWeakSet(CJSVERSION version, CJSContext in_ctx, CJSValue in_cjsv) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        JSV jsv = {};
        if (!FindCJSValue(jsmdPtr, in_cjsv, jsv)) return {};
        return JS_IsWeakSet(jsv.get(0));
    }
    CAEXP bool cjs_IsWeakMap(CJSVERSION version, CJSContext in_ctx, CJSValue in_cjsv) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        JSV jsv = {};
        if (!FindCJSValue(jsmdPtr, in_cjsv, jsv)) return {};
        return JS_IsWeakMap(jsv.get(0));
    }
    CAEXP bool cjs_IsDataView(CJSVERSION version, CJSContext in_ctx, CJSValue in_cjsv) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        JSV jsv = {};
        if (!FindCJSValue(jsmdPtr, in_cjsv, jsv)) return {};
        return JS_IsDataView(jsv.get(0));
    }
    CAEXP bool cjs_IsArray(CJSVERSION version, CJSContext in_ctx, CJSValue in_cjsv) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        JSV jsv = {};
        if (!FindCJSValue(jsmdPtr, in_cjsv, jsv)) return {};
        return JS_IsArray(jsv.get(0));
    }
    CAEXP bool cjs_IsProxy(CJSVERSION version, CJSContext in_ctx, CJSValue in_cjsv) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        JSV jsv = {};
        if (!FindCJSValue(jsmdPtr, in_cjsv, jsv)) return {};
        return JS_IsProxy(jsv.get(0));
    }
    CAEXP bool cjs_IsError(CJSVERSION version, CJSContext in_ctx, CJSValue in_cjsv) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        JSV jsv = {};
        if (!FindCJSValue(jsmdPtr, in_cjsv, jsv)) return {};
        return JS_IsError(jsv.get(0));
    }
    CAEXP bool cjs_IsUncatchableError(CJSVERSION version, CJSContext in_ctx, CJSValue in_cjsv) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        JSV jsv = {};
        if (!FindCJSValue(jsmdPtr, in_cjsv, jsv)) return {};
        return JS_IsUncatchableError(jsv.get(0));
    }
    CAEXP bool cjs_IsDate(CJSVERSION version, CJSContext in_ctx, CJSValue in_cjsv) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        JSV jsv = {};
        if (!FindCJSValue(jsmdPtr, in_cjsv, jsv)) return {};
        return JS_IsDate(jsv.get(0));
    }
    CAEXP int cjs_IsExtensible(CJSVERSION version, CJSContext in_ctx, CJSValue in_cjsv) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        JSV jsv = {};
        if (!FindCJSValue(jsmdPtr, in_cjsv, jsv)) return {};
        return JS_IsExtensible(ctx, jsv.get(0));
    }
    CAEXP bool cjs_IsArrayBuffer(CJSVERSION version, CJSContext in_ctx, CJSValue in_cjsv) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        JSV jsv = {};
        if (!FindCJSValue(jsmdPtr, in_cjsv, jsv)) return {};
        return JS_IsArrayBuffer(jsv.get(0));
    }
    CAEXP bool cjs_IsSameValue(CJSVERSION version, CJSContext in_ctx, CJSValue in_cjsv1, CJSValue in_cjsv2) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        JSV jsv1 = {};
        JSV jsv2 = {};
        if (!FindCJSValue(jsmdPtr, in_cjsv1, jsv1) || !FindCJSValue(jsmdPtr, in_cjsv2, jsv2)) return {};
        return JS_IsSameValue(ctx, jsv1.get(0), jsv2.get());
    }
    CAEXP int cjs_IsEqual(CJSVERSION version, CJSContext in_ctx, CJSValue in_cjsv1, CJSValue in_cjsv2) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        JSV jsv1 = {};
        JSV jsv2 = {};
        if (!FindCJSValue(jsmdPtr, in_cjsv1, jsv1) || !FindCJSValue(jsmdPtr, in_cjsv2, jsv2)) return {};
        return JS_IsEqual(ctx, jsv1.get(0), jsv2.get(0));
    }
    CAEXP bool cjs_IsStrictEqual(CJSVERSION version, CJSContext in_ctx, CJSValue in_cjsv1, CJSValue in_cjsv2) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        JSV jsv1 = {};
        JSV jsv2 = {};
        if (!FindCJSValue(jsmdPtr, in_cjsv1, jsv1) || !FindCJSValue(jsmdPtr, in_cjsv2, jsv2)) return {};
        return JS_IsStrictEqual(ctx, jsv1.get(0), jsv2.get(0));
    }
    CAEXP bool cjs_IsSameValueZero(CJSVERSION version, CJSContext in_ctx, CJSValue in_cjsv1, CJSValue in_cjsv2) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        JSV jsv1 = {};
        JSV jsv2 = {};
        if (!FindCJSValue(jsmdPtr, in_cjsv1, jsv1) || !FindCJSValue(jsmdPtr, in_cjsv2, jsv2)) return {};
        return JS_IsSameValueZero(ctx, jsv1.get(0), jsv2.get(0));
    }
    CAEXP int cjs_IsInstanceOf(CJSVERSION version, CJSContext in_ctx, CJSValue in_cjsv1, CJSValue in_cjsv2) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        JSV jsv1 = {};
        JSV jsv2 = {};
        if (!FindCJSValue(jsmdPtr, in_cjsv1, jsv1) || !FindCJSValue(jsmdPtr, in_cjsv2, jsv2)) return {};
        return JS_IsInstanceOf(ctx, jsv1.get(0), jsv2.get(0));
    }
    CAEXP bool cjs_IsPromise(CJSVERSION version, CJSContext in_ctx, CJSValue in_cjsv) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        JSV jsv = {};
        if (!FindCJSValue(jsmdPtr, in_cjsv, jsv)) return {};
        return jsm::GetSymbolName(ctx, jsv) == "Promise";
    }
    CAEXP bool cjs_IsFormData(CJSVERSION version, CJSContext in_ctx, CJSValue in_cjsv) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        JSV jsv = {};
        if (!FindCJSValue(jsmdPtr, in_cjsv, jsv)) return {};
        return jsm::GetSymbolName(ctx, jsv) == "FormData";
    }
    CAEXP bool cjs_IsBlob(CJSVERSION version, CJSContext in_ctx, CJSValue in_cjsv) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        JSV jsv = {};
        if (!FindCJSValue(jsmdPtr, in_cjsv, jsv)) return {};
        return jsm::GetSymbolName(ctx, jsv) == "Blob";
    }
    CAEXP CJSValue cjs_PromiseGetResult(CJSVERSION version, CJSContext in_ctx, CJSValue in_promise) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) return {};
        JSV js_promise = {};
        if (!FindCJSValue(jsmdPtr, in_promise, js_promise)) return {};
        JSV js_id = jsm::GetProperty(ctx, js_promise, { {"internal"}, {"id"} });
        ULL id = 0;
        jsm::ReadJSValueAsUint64(ctx, js_id, id);
        if (!jsmdPtr->promiseList.count(id)) {
            return {};
        }
        if (jsmdPtr->promiseList[id].state == CJS_STATE_PROMISE_PENDING) {
            return CJS_ERROR_PROMISE_STATE_BAD;
        }
        if (jsmdPtr->promiseList[id].state == CJS_STATE_PROMISE_FULFILLED) {
            return jsm::GetCJSValue(ctx, (jsmdPtr->promiseList[id].result.size() == 0) ? JS_UNDEFINED : jsmdPtr->promiseList[id].result[0]);
        }
        else {
            return jsm::GetCJSValue(ctx, (jsmdPtr->promiseList[id].error.size() == 0) ? JS_UNDEFINED : jsmdPtr->promiseList[id].error[0]);
        }
        return {};
    }
    CAEXP CJSPromiseState cjs_PromiseGetState(CJSVERSION version, CJSContext in_ctx, CJSValue in_promise) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) return {};
        JSV js_promise = {};
        if (!FindCJSValue(jsmdPtr, in_promise, js_promise)) return {};
        JSV js_id = jsm::GetProperty(ctx, js_promise, { {"internal"}, {"id"} });
        ULL id = 0;
        jsm::ReadJSValueAsUint64(ctx, js_id, id);
        if (!jsmdPtr->promiseList.count(id)) {
            return CJS_STATE_ERROR;
        }
        return static_cast<CJSPromiseState>(jsmdPtr->promiseList[id].state);
    }
    CAEXP bool cjs_PromiseResolve(CJSVERSION version, CJSContext in_ctx, CJSValue in_promise, CJSValue in_value) {
        CJSPromiseState ps = cjs_PromiseGetState(version, in_ctx, in_promise);
        if (ps != CJS_STATE_PROMISE_PENDING) return {};
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) return {};
        JSV js_promise = {};

        JSV js_value = {};
        if (!FindCJSValue(jsmdPtr, in_promise, js_promise) || !FindCJSValue(jsmdPtr, in_value, js_value)) return {};
        JSV js_id = jsm::GetProperty(ctx, js_promise, { {"internal"}, {"id"} });
        ULL id = 0;
        jsm::ReadJSValueAsUint64(ctx, js_id, id);
        if (!jsmdPtr->promiseList.count(id)) {
            return {};
        }
        JSV js_resolve = jsmdPtr->promiseList[id].resolve;
        JSV ret = CallFunction(ctx, js_resolve, js_promise, { js_value }, true, false);
        jsmdPtr->promiseList[id].callbackId = id;
        return true;
    }
    CAEXP bool cjs_PromiseReject(CJSVERSION version, CJSContext in_ctx, CJSValue in_promise, CJSValue in_value) {
        CJSPromiseState ps = cjs_PromiseGetState(version, in_ctx, in_promise);
        if (ps != CJS_STATE_PROMISE_PENDING) return {};
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) return {};
        JSV js_promise = {};

        JSV js_value = {};
        if (!FindCJSValue(jsmdPtr, in_promise, js_promise) || !FindCJSValue(jsmdPtr, in_value, js_value)) return {};
        JSV js_id = jsm::GetProperty(ctx, js_promise, { {"internal"}, {"id"} });
        ULL id = 0;
        jsm::ReadJSValueAsUint64(ctx, js_id, id);
        if (!jsmdPtr->promiseList.count(id)) {
            return {};
        }
        JSV js_reject = jsmdPtr->promiseList[id].reject;
        JSV ret = CallFunction(ctx, js_reject, js_promise, { js_value }, true, false);
        jsmdPtr->promiseList[id].callbackId = id;
        return true;
    }
    CAEXP CJSID cjs_EnqueueTask(CJSVERSION version, CJSContext in_ctx, CJSValue in_task, CJSValue in_this, cjs_int in_argumentCount, CJSValue* in_argumentValues) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) return {};
        JSV task = {};
        JSV thisValue = {};
        if (!FindCJSValue(jsmdPtr, in_task, task) || !FindCJSValue(jsmdPtr, in_this, thisValue)) return {};
        std::vector<JSV> argument = {};
        for (cjs_int i = 0; i < in_argumentCount; i++) {
            JSV arg = {};
            if (!FindCJSValue(jsmdPtr, in_argumentValues[i], arg)) {
                return {};
            }
            argument.push_back(arg);
        }
        return static_cast<CJSID>(jsm::addTask(ctx, task, thisValue, argument));
    }
    CAEXP bool CJS_RemoveTask(CJSVERSION version, CJSContext in_ctx, CJSID in_taskId) {
        JSContext* ctx = (JSContext*)in_ctx;
        return jsm::deleteTask(ctx, static_cast<ULL>(in_taskId));
    }
    CAEXP CJSValue CJS_QueryTask(CJSVERSION version, CJSContext in_ctx, CJSID in_taskId) {
        JSContext* ctx = (JSContext*)in_ctx;
        TaskData td = jsm::queryTask(ctx, static_cast<ULL>(in_taskId));
        if (!td.isValid) return CJS_STATE_TASK_NOTRUNNED;
        return jsm::GetCJSValue(ctx, td.ret);
    }
    CAEXP CJSSize CJS_RunTask(CJSVERSION version, CJSContext in_ctx) {
        JSContext* ctx = (JSContext*)in_ctx;
        JSMData* jsmdPtr = nullptr;
        if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) return {};
        size_t size = jsmdPtr->taskList.size();
        jsm::RunTask(ctx);
        return static_cast<CJSSize>(size);
    }


#undef jsm
#ifdef __cplusplus
}
#endif

#endif