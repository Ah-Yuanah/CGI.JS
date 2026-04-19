

#ifndef AY_CJS_CPP
#define AY_CJS_CPP
#define AY_CJS_CPP_VW std::wstring(L"1.1.20260419.01")
#define AY_CJS_CPP_VL []() -> std::wstring { \
    std::wstring s(AY_CJS_CPP_VW); \
    s.erase(std::remove(s.begin(), s.end(), L'.'), s.end()); \
    return static_cast<unsigned long long>std::stoll(s); \
}()
#if defined(_WIN32)


#include "../include/cjskit.hpp"
using namespace cjs;


int Main() {
    mode = "repl";

    int consoleResult = CreateConsole(L"CGI.JS - " + cplatform + AY_CJS_CPP_VW + L"");
    if (consoleResult == -1) {
        return EXIT_SUCCESS;
    }
    else if (consoleResult == 0) {
        return EXIT_FAILURE;
    }

    if (!SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE)) {
        CreateOutput(L"Error: Failed to initialize console. Program will exit.");
        if (isAlwaysPauseWhenQuit) system("pause");
        return EXIT_FAILURE;
    }

    JS js = nullptr;
    try {
        js = std::make_shared<JavaScript>();
    }
    catch (...) {}
    if (js == nullptr || !js->init()) {
        CreateOutput(L"Error: Failed to initialize JavaScript engine. Program will exit.", TextLightColorValue[L"Error"]);
        if (isAlwaysPauseWhenQuit) system("pause");
        return EXIT_FAILURE;
    }

    CreateOutput(L"Welcome to Cgi.js " + cplatform + AY_CJS_CPP_VW + L"\n");
    CreateOutput(L"Type \"", GetColorValue(L"Default"));
    CreateOutput(L"system.help()", GetColorValue(L"Function"));
    CreateOutput(L"\" for more information.\n", GetColorValue(L"Default"));
    CreateOutput(L"Interactive shell\n");
    CreateOutput(L"\n");

    if (!isWTConsole) CreateOutput(L"For a better experience, please use the new Windows Terminal.\n\n");

    if (!errorOutput.empty()) {
        CreateOutput(errorOutput, GetColorValue(L"Warn"));
        CreateOutput(L"\n");
        errorOutput.clear();
    }

    while (!IsConsoleClosed() && js->alive()) {
        if (isPaused) {
            AdvSleep(1);
            continue;
        }

        CreateOutput(L"cjs> ");
        std::wstring inputData = CreateInput();
        if (IsCodeEmpty(inputData)) continue;

        JSINFO result = js->eval(inputData);
        if (!result.isValid) continue;
        if (result.isSuccess) {
            if (!isShowReturnValue) continue;
            if (isShowReturnDetail) {
                for (const auto& [code, color] : result.detail) {
                    CreateOutput(code, color);
                }
            }
            else {
                GMT processedText = GetCodeColor(result.message);
                for (const auto& [codeSegment, colorType] : processedText) {
                    CreateOutput(codeSegment + L"\n", TextLightColorValue[colorType]);
                }
            }
        }
        else {
            CreateOutput(result.errorFront + L":Uncaught " + result.message + L"\n", GetColorValue(L"Error"));
            OutputStack(result.errorStack);
        }
    }
    js = nullptr;
    return EXIT_SUCCESS;
}
int FileMain() {
    mode = "file";

    if (isShowConsole) {

        int consoleResult = CreateConsole(L"CGI.JS - r" + AY_CJS_CPP_VW + L"");
        if (consoleResult == -1) {
            return EXIT_SUCCESS;
        }
        else if (consoleResult == 0) {
            return EXIT_FAILURE;
        }

        if (!SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE)) {
            CreateOutput(L"Error: Failed to initialize console. Program will exit.");
            system("pause");
            return EXIT_FAILURE;
        }

    }

    JS js = nullptr;
    try {
        js = std::make_shared<JavaScript>();
    }
    catch (...) {}
    if (js == nullptr || !js->init()) {
        CreateOutput(L"Error: Failed to initialize JavaScript engine. Program will exit.", TextLightColorValue[L"Error"]);
        system("pause");
        return EXIT_FAILURE;
    }

    CreateOutput(L"Welcome to Cgi.js r" + AY_CJS_CPP_VW + L"\n");
    CreateOutput(L"Executing file: ");
    CreateOutput(L"'" + commandStartFilePath + L"'", GetColorValue(L"Function"));
    CreateOutput(L"\n");
    CreateOutput(L"\n");

    if (!isWTConsole) CreateOutput(L"For a better experience, please use the new Windows Terminal.\n\n");

    if (!errorOutput.empty()) {
        CreateOutput(errorOutput, GetColorValue(L"Warn"));
        CreateOutput(L"\n");
        errorOutput.clear();
    }

    FileController fc = FileController(commandStartFilePath, apppath(0));
    BYTEBUFFER fileContent = {};

    if (!fc.exists()) {
        CreateOutput(L"Execution failed: \n", GetColorValue(L"Error"));
        CreateOutput(L"The file does not exist.\n", GetColorValue(L"Error"));
        goto EndProcess;
    }
    if (!fc.read(0, fc.size(), &fileContent)) {
        CreateOutput(L"Execution failed: \n", GetColorValue(L"Error"));
        CreateOutput(L"Cannot to read the file.\n", GetColorValue(L"Error"));
        goto EndProcess;
    }
    else {

        std::wstring code = GetTextFromBYTEBUFFER(&fileContent);

        JavaScriptMethod::SetAttribute(js->getContextThis(), JavaScriptMethod::GetProperty(js->getContextThis(), JavaScriptMethod::NewGlobalObject(js->getContextThis()), "system"), "workDirectory", wstringToString(GetFilePathWithoutName(commandStartFilePath)));

        JSINFO result = js->eval(code, commandStartFilePath, isTotalOutput);

        if (!isTotalOutput) CreateOutput(L"\n");

        if (!result.isValid) {
            CreateOutput(L"Execution failed: \n", GetColorValue(L"Error"));
            CreateOutput(L"Internal Error.\n", GetColorValue(L"Error"));
            goto EndProcess;
        }
        else if (result.isSuccess) {
            if (!isShowReturnValue) {
                if (result.output.empty())
                    CreateOutput(L"Executed successfully.\n", GetColorValue(L"Success"));
                else {
                    CreateOutput(L"Executed successfully: \n", GetColorValue(L"Success"));

                    if (!result.output.empty() && isTotalOutput) {
                        CreateOutput(L"Output: \n", GetColorValue(L"Info"));
                        for (const auto& [code, color] : result.output) {
                            CreateOutput(code, color);
                        }
                        CreateOutput(L"\n");
                    }
                }

                CreateOutput(L"\n");

                goto EndProcess;
            }
            if (isShowReturnDetail) {
                CreateOutput(L"Executed successfully: \n", GetColorValue(L"Success"));

                if (!result.output.empty() && isTotalOutput) {
                    CreateOutput(L"Output: \n", GetColorValue(L"Info"));
                    for (const auto& [code, color] : result.output) {
                        CreateOutput(code, color);
                    }
                    CreateOutput(L"\n");
                }

                CreateOutput(L"Return detail: \n", GetColorValue(L"Info"));
                for (const auto& [code, color] : result.detail) {
                    CreateOutput(code, color);
                }

                CreateOutput(L"\n");

                goto EndProcess;
            }
            else {
                CreateOutput(L"Executed successfully: \n", GetColorValue(L"Success"));

                if (!result.output.empty() && isTotalOutput) {
                    CreateOutput(L"Output: \n", GetColorValue(L"Info"));
                    for (const auto& [code, color] : result.output) {
                        CreateOutput(code, color);
                    }
                    CreateOutput(L"\n");
                }

                CreateOutput(L"Return value: \n", GetColorValue(L"Info"));
                GMT processedText = GetCodeColor(result.message);
                for (const auto& [codeSegment, colorType] : processedText) {
                    CreateOutput(codeSegment + L"\n", TextLightColorValue[colorType]);
                }

                CreateOutput(L"\n");

                goto EndProcess;
            }
        }
        else {
            CreateOutput(L"Execution failed: \n", GetColorValue(L"Error"));

            if (!result.output.empty() && isTotalOutput) {
                CreateOutput(L"Output: \n", GetColorValue(L"Info"));
                for (const auto& [code, color] : result.output) {
                    CreateOutput(code, color);
                }
                CreateOutput(L"\n");
            }

            CreateOutput(L"Reason: \n", GetColorValue(L"Info"));
            CreateOutput(result.errorFront + L":Uncaught " + result.message + L"\n", GetColorValue(L"Error"));
            OutputStack(result.errorStack);

            CreateOutput(L"\n");

            goto EndProcess;
        }

    }

EndProcess:;

    if (isAlwaysPauseWhenQuit && isConsoleEnv && console) system("pause");
    js = nullptr;
    return EXIT_SUCCESS;
}
int FastCgiMain() {
    mode = "fcgi";

    _putenv_s("FCGI_TIMEOUT", std::to_string(timeout).c_str());

    FCGX_Request request;
    if (FCGX_Init() < 0 || FCGX_InitRequest(&request, 0, 0) < 0) {
        return EXIT_FAILURE;
    }

    while (FCGX_Accept_r(&request) >= 0) {

        bool isSuccess = false;
        std::string fileContent = "";
        std::wstring scriptPath = L"";
        {
            const char* cScriptPath = FCGX_GetParam("SCRIPT_FILENAME", request.envp);
            if (cScriptPath == nullptr) goto EndProcessFilePath;
            scriptPath = stringToWstring(cScriptPath);
            if (std::filesystem::exists(scriptPath) && std::filesystem::is_regular_file(scriptPath)) {
                std::ifstream fileStream(scriptPath, std::ios::in | std::ios::binary);
                if (fileStream.is_open()) {
                    fileStream.seekg(0, std::ios::end);
                    const std::streamsize fileSize = fileStream.tellg();
                    fileStream.seekg(0, std::ios::beg);
                    if (fileSize > 0) {
                        fileContent.reserve(static_cast<std::size_t>(fileSize));
                        fileContent.assign(
                            std::istreambuf_iterator<char>(fileStream),
                            std::istreambuf_iterator<char>()
                        );
                    }
                    fileStream.close();
                    isSuccess = true;
                }
                else {
                    goto EndProcessFilePath;
                }
                goto EndProcessFilePath;
            }
            else {
                goto EndProcessFilePath;
            }
        }
    EndProcessFilePath:;
        JavaScript* js = nullptr;
        if (isSuccess) {
            js = NewInstance<JavaScript>();
            if (js == nullptr) goto ErrorProcess;
            if (!js->init()) {
                goto ErrorProcess;
            }

            JavaScriptMethod* jsm = js->getMethodThis();
            JSContext* ctx = js->getContextThis();
            if (jsm == nullptr || ctx == nullptr) {
                goto ErrorProcess;
            }

            std::string network_request_method_string = GetEnv("REQUEST_METHOD", request.envp);
            {

                JSV global = jsm->NewGlobalObject(ctx);
                JSV network_request = jsm->GetProperty(ctx, global, {
                    {"network"},
                    {"request"},
                    });
                JSV network_response = jsm->GetProperty(ctx, global, {
                    {"network"},
                    {"response"},
                    });
                jsm->SetAttribute(ctx, jsm->GetProperty(ctx, global, "system"), "workDirectory", wstringToString(GetFilePathWithoutName(scriptPath)));
                jsm->SetAttribute(ctx, network_request, "method", network_request_method_string);
                jsm->SetAttribute(ctx, network_request, "url", GetEnv("REQUEST_URI", request.envp));
                jsm->SetAttribute(ctx, network_request, "path", GetEnv("SCRIPT_FILENAME", request.envp));

                OBJECT requestHeaderObject = GetObjectFromHeader(stringToWstring(GetRequestHeader(&request)));
                JSV network_request_header = jsm->NewObject(ctx, requestHeaderObject);
                jsm->SetAttribute(ctx, network_request, "header", network_request_header);
                JSV network_request_advhHeader = jsm->NewObject(ctx);
                jsm->SetAttribute(ctx, network_request, "advHeader", network_request_advhHeader);
                jsm->SetAttribute(ctx, network_request_advhHeader, "query", GetEnv("QUERY_STRING", request.envp));
                jsm->SetAttribute(ctx, network_request_advhHeader, "contentLength", GetEnv("CONTENT_LENGTH", request.envp));
                jsm->SetAttribute(ctx, network_request_advhHeader, "remoteIp", GetEnv("REMOTE_ADDR", request.envp));
                jsm->SetAttribute(ctx, network_request_advhHeader, "remotePort", GetEnv("REMOTE_PORT", request.envp));
                jsm->SetAttribute(ctx, network_request_advhHeader, "host", GetEnv("HTTP_HOST", request.envp));
                jsm->SetAttribute(ctx, network_request_advhHeader, "userAgent", GetEnv("HTTP_USER_AGENT", request.envp));
                jsm->SetAttribute(ctx, network_request_advhHeader, "protocol", GetEnv("SERVER_PROTOCOL", request.envp));
                std::string realIp = GetEnv("HTTP_X_FORWARDED_FOR", request.envp);
                jsm->SetAttribute(ctx, network_request_advhHeader, "realIp", realIp.empty() ? GetEnv("REMOTE_ADDR", request.envp) : realIp);
                std::string scheme = GetEnv("HTTP_X_FORWARDED_PROTO", request.envp);
                if (scheme.empty()) {
                    scheme = (std::string(GetEnv("SERVER_PORT", request.envp)) == "443") ? "https" : "http";
                }
                jsm->SetAttribute(ctx, network_request_advhHeader, "scheme", scheme);
                jsm->SetAttribute(ctx, network_request_advhHeader, "referer", GetEnv("HTTP_REFERER", request.envp));
                jsm->SetAttribute(ctx, network_request_advhHeader, "contentType", GetEnv("CONTENT_TYPE", request.envp));
                jsm->SetAttribute(ctx, network_request_advhHeader, "documentRoot", GetEnv("DOCUMENT_ROOT", request.envp));


                BYTEBUFFER requestBodyBinary = {};
                if ((isModernMode && (network_request_method_string == "GET" || network_request_method_string == "HEAD" || network_request_method_string == "DELETE" || network_request_method_string == "OPTIONS" || network_request_method_string == "TRACE" || network_request_method_string == "CONNECT"))) {} else ReadRequestBody(&request, &requestBodyBinary);

                JSV requestBody = JSV(JS_NULL);
                if (requestBodyBinary.size()>0) requestBody = jsm->NewUint8Array(ctx, requestBodyBinary);
                jsm->SetAttribute(ctx, network_request, "body", requestBody);

                JSV document_cookie = jsm->GetProperty(ctx, global, {
                    {"document"},
                    {"cookie"},
                    });
                jsm->SetAttribute(ctx, document_cookie, "cookie", GetEnv("HTTP_COOKIE", request.envp));


                jsm->AppendMethod(ctx, network_response, "setResponseCode", [](JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues)->JSValue {
                    JSV js_code = (argumentCount >= 1) ? JSV(ctx, argumentValues[0]).cget(1).cset(1) : JavaScriptMethod::NewInt64(ctx, 200);
                    int64_t code = 200;
                    JavaScriptMethod::ReadJSValueAsInt64(ctx, js_code, code);
                    std::string msg = " ";
                    for (auto& [imsg, icode] : HttpResponseCode) {
                        if (icode == static_cast<int>(code)) {
                            msg = " " + wstringToString(imsg);
                            break;
                        }
                    }
                    JavaScriptMethod::SetAttribute(ctx, JavaScriptMethod::GetProperty(ctx, thisVal, "header"), "Status", JavaScriptMethod::NewString(ctx, std::to_string(code) + msg));
                    return JS_UNDEFINED;
                    });

            }

            JSINFO ji = js->eval(stringToWstring(fileContent), GetFileNameFromPath(scriptPath));
            if (!ji.isValid) {
                goto ErrorProcess;
            }
            if (!ji.isSuccess) {
                if (!isOutputError) {
                    goto ErrorProcess;
                }
                else {
                    ClearOutput();
                    ULL tsize = outputTemp.size();
                    OutputStack(ji.errorStack);
                    ULL csize = outputTemp.size();

                    std::string code = "<!DOCTYPE html><html lang=\"zh-cmn-Hans\"><head></head><body>";
                    code += "<p style=\"color: #FF4444\">" + wstringToString(ji.errorFront) + ":Uncaught " + wstringToString(ji.message) + "</p>";
                    for (ULL i = tsize; i < csize; ++i) {
                        std::wstring key = outputTemp.at(static_cast<size_t>(i)).first;
                        const std::wstring& value = outputTemp.at(static_cast<size_t>(i)).second;

                        size_t pos = 0;
                        while ((pos = key.find(L'&', pos)) != std::wstring::npos) {
                            key.replace(pos, 1, L"&amp;");
                            pos += 5;
                        }

                        pos = 0;
                        while ((pos = key.find(L'<', pos)) != std::wstring::npos) {
                            key.replace(pos, 1, L"&lt;");
                            pos += 4;
                        }

                        pos = 0;
                        while ((pos = key.find(L'>', pos)) != std::wstring::npos) {
                            key.replace(pos, 1, L"&gt;");
                            pos += 4;
                        }

                        pos = 0;
                        while ((pos = key.find(L'"', pos)) != std::wstring::npos) {
                            key.replace(pos, 1, L"&quot;");
                            pos += 6;
                        }

                        pos = 0;
                        while ((pos = key.find(L'\'', pos)) != std::wstring::npos) {
                            key.replace(pos, 1, L"&#39;");
                            pos += 5;
                        }

                        pos = 0;
                        while ((pos = key.find(L'\n', pos)) != std::wstring::npos) {
                            key.replace(pos, 1, L"<br>");
                            pos += 4;
                        }

                        pos = 0;
                        while ((pos = key.find(L' ', pos)) != std::wstring::npos) {
                            key.replace(pos, 1, L"&nbsp;");
                            pos += 6;
                        }

                        std::string key_str = wstringToString(key);
                        std::string color_str = wstringToString(value);

                        code += "<span style=\"color: " + color_str + "\">" + key_str + "</span>";
                    }
                    code += "</body></html>";

                    FCGX_FPrintF(request.out, "Status: 422 Unprocessable Content\r\n");
                    FCGX_FPrintF(request.out, "Content-Type: text/html; charset=utf-8\r\n\r\n");
                    FCGX_FPrintF(request.out, code.c_str());

                    goto EndProcess;
                }
            }
            else {
                OBJECT headerObject = {};
                BYTEBUFFER bodyBinary = {};

                {
                    JSV global = jsm->NewGlobalObject(ctx);

                    JSV response = jsm->GetProperty(ctx, global, {
                        {"network"},
                        {"response"},
                        });

                    JSV response_header = jsm->GetProperty(ctx, response, "header");
                    headerObject = {
                     {L"Status",{OBJECTStruct{static_cast<std::wstring>(L"200 OK")}}},
                     {L"Allow",{OBJECTStruct{static_cast<std::wstring>(L"GET, HEAD, OPTIONS")}}},
                     {L"Content-Type",{OBJECTStruct{static_cast<std::wstring>(L"text/plain; charset=UTF-8")}}},
                    };
                    OBJECT headerTemp = {};
                    jsm->ReadJSValueAsObject(ctx, response_header, headerTemp);
                    for (const auto& pair : headerTemp) {
                        headerObject[pair.first] = pair.second;
                    }

                    if (!GetAcceptAllowList(wstringToString(headerObject[L"Allow"].get<std::wstring>())).count(network_request_method_string)) {
                        headerObject[L"Status"] = OBJECTStruct{ static_cast<std::wstring>(L"405 Method Not Allowed") };
                    }

                    JSV response_body = jsm->GetProperty(ctx, response, "body");
                    JSValue bodyTemp = response_body.get(0);
                    int32_t int32Temp = 0;
                    int64_t int64Temp = 0;
                    uint64_t uint64Temp = 0;
                    bool boolTemp = false;
                    std::string stringTemp = "";
                    if (jsm->ReadJSValueAsUint8Array(ctx, response_body, bodyBinary) || jsm->ReadJSValueAsUint16Array(ctx, response_body, bodyBinary) || jsm->ReadJSValueAsUint32Array(ctx, response_body, bodyBinary)
                        || jsm->ReadJSValueAsInt8Array(ctx, response_body, bodyBinary) || jsm->ReadJSValueAsInt16Array(ctx, response_body, bodyBinary) || jsm->ReadJSValueAsInt32Array(ctx, response_body, bodyBinary)) {
                        headerObject[L"Content-Type"] = OBJECTStruct{ static_cast<std::wstring>(L"application/octet-stream") };
                        headerObject[L"Content-Length"] = OBJECTStruct{ std::to_wstring(bodyBinary.size()) };
                    }
                    else if (jsm->ReadJSValueAsInt32(ctx, response_body, int32Temp) || jsm->ReadJSValueAsInt64(ctx, response_body, int64Temp)) {
                        if (int32Temp != 0 && int64Temp == 0) int64Temp = static_cast<uint64_t>(int32Temp);
                        bodyBinary = ToBinary(std::to_wstring(int64Temp));
                    }
                    else if (jsm->ReadJSValueAsUint64(ctx, response_body, uint64Temp)) {
                        bodyBinary = ToBinary(std::to_wstring(uint64Temp));
                    }
                    else if (jsm->ReadJSValueAsBool(ctx, response_body, boolTemp)) {
                        bodyBinary = ToBinary((boolTemp) ? L"true" : L"false");
                    }
                    else if (jsm->ReadJSValueAsString(ctx, response_body, stringTemp)) {
                        bodyBinary = ToBinary(stringToWstring(stringTemp));
                    }
                    else if (JS_IsNull(bodyTemp)) {
                        bodyBinary = ToBinary(L"null");
                    }
                    else if (JS_IsUndefined(bodyTemp)) {
                        bodyBinary = ToBinary(L"");
                    }
                    else {
                        bodyBinary = ToBinary(L"[object " + stringToWstring(GetPrototypeName(ctx, bodyTemp)) + L"]");
                    }

                }
                std::string responseHeader = wstringToString(GetResponseHeader(headerObject));
                int responseCode = GetStatusCode(responseHeader);
                FCGX_FPrintF(request.out, responseHeader.c_str());
                FCGX_FPrintF(request.out, "\r\n");
                if ((isStrictStandard && ((responseCode >= 100 && responseCode <= 199) || responseCode == 204 || responseCode == 205 || responseCode == 304 || network_request_method_string == "HEAD")) || (isModernMode && (network_request_method_string == "TRACE"))) {}
                else FCGX_PutStr(reinterpret_cast<const char*>(bodyBinary.data()), static_cast<int>(bodyBinary.size()), request.out);

                goto EndProcess;
            }
            goto ErrorProcess;

        }
        else {
            goto ErrorProcess;
        }

        if (false) {
        ErrorProcess:;
            FCGX_FPrintF(request.out, "Status: 500 Internal Server Error\r\n");
            FCGX_FPrintF(request.out, "Content-Type: text/plain; charset=utf-8\r\n\r\n");
        }
    EndProcess:;
        if (js != nullptr) {
            delete js;
            js = nullptr;
        }
        if (isFlushNamedPipe) FCGX_FFlush(request.out);
        FCGX_Finish_r(&request);

        ClearOutput();
    }

    return EXIT_SUCCESS;
}

const static std::unordered_map<std::wstring, std::wstring> supportArgList = {
    {L"config", L""},
    {L"extension", L""},
    {L"new", L""},
    {L"restarted", L""},
};
int APIENTRY wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPWSTR lpCmdLine, _In_ int nCmdShow) {

    SetCurrentDirectoryW(apppath(0).c_str());

    init();

    hInst = hInstance;
    commandArgList = GetCommandArgList();
    commandStartFilePath = GetStartFilePath();

    std::wstring tempOutput = L"";
    bool isDisabledConfig = false;
    bool isDisabledExtension = false;
    bool isKeepWTMode = false;
    
    if (!commandArgList.empty()) {
        for (auto& [arg, value] : commandArgList) {
            if (!supportArgList.count(arg)) {
                tempOutput += L"Warning: Invalid command line parameter '" + arg + L"'\n";
            }
        }
    }
    
    if (commandArgList.count(L"config")) {
        if (commandArgList[L"config"] == L"disabled") {
            isDisabledConfig = true;
        }
        else if (commandArgList[L"config"] == L"enabled") {
            isDisabledConfig = false;
        }
        else {
            tempOutput += L"Warning: The value '" + commandArgList[L"config"] + L"' of command line parameter '" + L"config" + L"' is invalid\n";
        }
    }
    if (commandArgList.count(L"extension")) {
        if (commandArgList[L"extension"] == L"disabled") {
            isDisabledExtension = true;
        }
        else if (commandArgList[L"extension"] == L"enabled") {
            isDisabledExtension = false;
        }
        else {
            tempOutput += L"Warning: The value '" + commandArgList[L"extension"] + L"' of command line parameter '" + L"extension" + L"' is invalid\n";
        }
    }
    if (commandArgList.count(L"new")) {
        isKeepWTMode = true;
        isWTConsole = true;
    }

    configObject = {
        {L"fastcgi",{
            OBJECT{
                { L"timeout", { static_cast<double>(1 * 3600 * 1000) } },
                { L"isFlushNamedPipe", { static_cast<bool>(false) } },
                { L"isOutputError", { static_cast<bool>(false) } },
                { L"isStrictStandard", { static_cast<bool>(true) } },
                { L"isModernMode", { static_cast<bool>(true) } },
            }
        }},
        {L"shell",{
            OBJECT{
                { L"isShowReturnValue", { static_cast<bool>(true) } },
                { L"isShowReturnDetail", { static_cast<bool>(true) } },
                { L"isAlwaysPauseWhenQuit", { static_cast<bool>(true) } },
            }
        }},
        {L"file",{
            OBJECT{
                { L"isShowConsole", { static_cast<bool>(true) } },
                { L"isTotalOutput", { static_cast<bool>(false) } },
            }
        }},
        {L"general",{
            OBJECT{
                { L"isModuleMode", { static_cast<bool>(true) } },
            }
        }},
    };

    if (!isDisabledConfig) {
        FileController* fc = NewInstance<FileController>(L"./config.json", apppath(0));
        if (fc == nullptr) goto ProcessConfigEnd;
        if (!fc->exists()) {
            goto ProcessConfigEnd;
        }
        BYTEBUFFER result = {};
        fc->read(0, ULLONG_MAX, &result);
        delete fc;
        try {
            std::wstring json = GetTextFromBYTEBUFFER(&result);
            if (json.empty()) goto ProcessConfigEnd;
            OBJECT config = JSON.parse(json);
            for (const auto& pair : config) {
                configObject[pair.first] = pair.second;
            }
        }catch(std::exception& ec){
            tempOutput += L"Warning: The config file is invalid JSON. Configurations do not take effect. (Reason: '" + stringToWstring(std::string(ec.what())) + L"')\n";
        }
    }
ProcessConfigEnd:;

    if (!isDisabledExtension) {
        FileController* fc = NewInstance<FileController>(L"./Extension/", apppath(0));
        if (!fc->exists()) {
            delete fc;
            goto ProcessExtensionEnd;
        }
        extensionList = fc->list();
        delete fc;
    }
ProcessExtensionEnd:;

    isStartByFastCgi = IsStartByFastCgi();
    updateConfig();

    int result = 0;
    if (isStartByFastCgi && commandStartFilePath.empty()){
        result = FastCgiMain();
    }
    else if (!commandStartFilePath.empty()) {
        errorOutput = tempOutput;
        result = FileMain();
    }
    else {
        errorOutput = tempOutput;
        result = Main();
    }
    return result;
}


#endif // defined(_WIN32)
#endif // AY_CJS_CPP