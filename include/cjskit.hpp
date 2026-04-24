
#ifndef AY_CJSKIT_HPP
#define AY_CJSKIT_HPP

#define _WIN32_WINNT 0x0602
#define NTDDI_VERSION NTDDI_WINBLUE
#define WINVER 0x0602

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <WinSock2.h>
#include <Shlwapi.h>
#include <shellapi.h>
#include <ws2tcpip.h>
#include <mmsystem.h>
#include <winhttp.h>
#include <wininet.h>
#include <gdiplus.h>

#include <string>
#include <vector>
#include <unordered_map>
#include <stdexcept>
#include <iostream>
#include <cstdio>
#include <Shlobj.h>
#include <codecvt>
#include <cwctype>
#include <regex>
#include <cstdlib>
#include <algorithm>
#include <variant>
#include <functional>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <fstream>
#include <unordered_set>
#include <bcrypt.h>
#include <mutex>
#include <queue>
#include <atomic>
#include <any>
#include <future>
#include <random>

#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "kernel32.lib")

#pragma warning(push)
#pragma warning(disable: 4244)
#pragma warning(disable: 6001)

#define CRYPTOPP_SHA512_224_256_AVAILABLE 1

extern "C" {
#include "./thirdParty/quickjs-ng/include/quickjs.h"

#include "./thirdParty/fastcgi/include/fastcgi.h"
#include "./thirdParty/fastcgi/include/fcgi_config.h"
#include "./thirdParty/fastcgi/include/fcgi_stdio.h"
#include "./thirdParty/fastcgi/include/fcgiapp.h"
#include "./thirdParty/fastcgi/include/fcgimisc.h"
#include "./thirdParty/fastcgi/include/fcgio.h"
#include "./thirdParty/fastcgi/include/fcgios.h"

#include "./thirdParty/zlib/include/zlib.h"
}

#include "./thirdParty/cryptopp/include/aes.h"
#include "./thirdParty/cryptopp/include/chacha.h"
#include "./thirdParty/cryptopp/include/chachapoly.h"
#include "./thirdParty/cryptopp/include/modes.h"
#include "./thirdParty/cryptopp/include/gcm.h"
#include "./thirdParty/cryptopp/include/rsa.h"
#include "./thirdParty/cryptopp/include/eccrypto.h"
#include "./thirdParty/cryptopp/include/ecp.h"
#include "./thirdParty/cryptopp/include/xed25519.h"
#include "./thirdParty/cryptopp/include/sha.h"
#include "./thirdParty/cryptopp/include/sha3.h"
#include "./thirdParty/cryptopp/include/hmac.h"
#include "./thirdParty/cryptopp/include/pssr.h"
#include "./thirdParty/cryptopp/include/pkcspad.h"
#include "./thirdParty/cryptopp/include/oaep.h"
#include "./thirdParty/cryptopp/include/dh.h"
#include "./thirdParty/cryptopp/include/osrng.h"
#include "./thirdParty/cryptopp/include/cryptlib.h"
#include "./thirdParty/cryptopp/include/filters.h"
#include "./thirdParty/cryptopp/include/queue.h"
#include "./thirdParty/cryptopp/include/secblock.h"
#include "./thirdParty/cryptopp/include/integer.h"
#include "./thirdParty/cryptopp/include/authenc.h"
#include "./thirdParty/cryptopp/include/pubkey.h"
#include "./thirdParty/cryptopp/include/pwdbased.h"


#undef FILE
#define FILE _iobuf
#undef freopen_s
#define freopen_s ::freopen_s
#undef stdout
#define stdout (__acrt_iob_func(1))
#undef stderr
#define stderr (__acrt_iob_func(2))
#undef stdin
#define stdin  (__acrt_iob_func(0))
#undef fflush
#define fflush ::fflush
#undef fopen
#define fopen ::fopen
#undef fprintf
#define fprintf ::fprintf
#undef fclose
#define fclose ::fclose

#pragma warning(pop)
#pragma warning(disable: 26800)
#pragma warning(disable: 6258)
#pragma warning(disable: 26110)
#pragma warning(disable: 26495)
#pragma warning(disable: 6262)
#pragma warning(disable: 6386)

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winhttp.lib")
#if defined(_WIN64)
#if defined(_DEBUG)
#pragma comment(lib, "\"" __FILE__ "/../thirdParty/quickjs-ng/lib/x64/Debug/qjs.lib\"")
#pragma comment(lib, "\"" __FILE__ "/../thirdParty/fastcgi/lib/x64/Debug/fcgi.lib\"")
#pragma comment(lib, "\"" __FILE__ "/../thirdParty/cryptopp/lib/x64/Debug/cryptopp.lib\"")
#pragma comment(lib, "\"" __FILE__ "/../thirdParty/zlib/lib/x64/Debug/zlib.lib\"")
#else
#pragma comment(lib, "\"" __FILE__ "/../thirdParty/quickjs-ng/lib/x64/Release/qjs.lib\"")
#pragma comment(lib, "\"" __FILE__ "/../thirdParty/fastcgi/lib/x64/Release/fcgi.lib\"")
#pragma comment(lib, "\"" __FILE__ "/../thirdParty/cryptopp/lib/x64/Release/cryptopp.lib\"")
#pragma comment(lib, "\"" __FILE__ "/../thirdParty/zlib/lib/x64/Release/zlib.lib\"")
#endif
#elif defined(_WIN32)
#if defined(_DEBUG)
#pragma comment(lib, "\"" __FILE__ "/../thirdParty/quickjs-ng/lib/x86/Debug/qjs.lib\"")
#pragma comment(lib, "\"" __FILE__ "/../thirdParty/fastcgi/lib/x86/Debug/fcgi.lib\"")
#pragma comment(lib, "\"" __FILE__ "/../thirdParty/cryptopp/lib/x86/Debug/cryptopp.lib\"")
#pragma comment(lib, "\"" __FILE__ "/../thirdParty/zlib/lib/x86/Debug/zlib.lib\"")
#else
#pragma comment(lib, "\"" __FILE__ "/../thirdParty/quickjs-ng/lib/x86/Release/qjs.lib\"")
#pragma comment(lib, "\"" __FILE__ "/../thirdParty/fastcgi/lib/x86/Release/fcgi.lib\"")
#pragma comment(lib, "\"" __FILE__ "/../thirdParty/cryptopp/lib/x86/Release/cryptopp.lib\"")
#pragma comment(lib, "\"" __FILE__ "/../thirdParty/zlib/lib/x86/Release/zlib.lib\"")
#endif
#endif
#undef min
#undef max

#ifndef CP_UTF16
#define CP_UTF16 1200
#endif

namespace CryptoPP {

    template<>
    const byte PKCS_DigestDecoration<SHA1>::decoration[] = {
        0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
        0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14
    };
    template<>
    const unsigned int PKCS_DigestDecoration<SHA1>::length =
        sizeof(PKCS_DigestDecoration<SHA1>::decoration);

    template<>
    const byte PKCS_DigestDecoration<SHA224>::decoration[] = {
        0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
        0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05,
        0x00, 0x04, 0x1c
    };
    template<>
    const unsigned int PKCS_DigestDecoration<SHA224>::length =
        sizeof(PKCS_DigestDecoration<SHA224>::decoration);

    template<>
    const byte PKCS_DigestDecoration<SHA256>::decoration[] = {
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
        0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
        0x00, 0x04, 0x20
    };
    template<>
    const unsigned int PKCS_DigestDecoration<SHA256>::length =
        sizeof(PKCS_DigestDecoration<SHA256>::decoration);

    template<>
    const byte PKCS_DigestDecoration<SHA384>::decoration[] = {
        0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
        0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
        0x00, 0x04, 0x30
    };
    template<>
    const unsigned int PKCS_DigestDecoration<SHA384>::length =
        sizeof(PKCS_DigestDecoration<SHA384>::decoration);

    template<>
    const byte PKCS_DigestDecoration<SHA512>::decoration[] = {
        0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
        0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
        0x00, 0x04, 0x40
    };
    template<>
    const unsigned int PKCS_DigestDecoration<SHA512>::length =
        sizeof(PKCS_DigestDecoration<SHA512>::decoration);

    template<>
    const byte PKCS_DigestDecoration<SHA3_224>::decoration[] = {
        0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
        0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07, 0x05,
        0x00, 0x04, 0x1c
    };
    template<>
    const unsigned int PKCS_DigestDecoration<SHA3_224>::length =
        sizeof(PKCS_DigestDecoration<SHA3_224>::decoration);

    template<>
    const byte PKCS_DigestDecoration<SHA3_256>::decoration[] = {
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
        0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08, 0x05,
        0x00, 0x04, 0x20
    };
    template<>
    const unsigned int PKCS_DigestDecoration<SHA3_256>::length =
        sizeof(PKCS_DigestDecoration<SHA3_256>::decoration);

    template<>
    const byte PKCS_DigestDecoration<SHA3_384>::decoration[] = {
        0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
        0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09, 0x05,
        0x00, 0x04, 0x30
    };
    template<>
    const unsigned int PKCS_DigestDecoration<SHA3_384>::length =
        sizeof(PKCS_DigestDecoration<SHA3_384>::decoration);

    template<>
    const byte PKCS_DigestDecoration<SHA3_512>::decoration[] = {
        0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
        0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0a, 0x05,
        0x00, 0x04, 0x40
    };
    template<>
    const unsigned int PKCS_DigestDecoration<SHA3_512>::length =
        sizeof(PKCS_DigestDecoration<SHA3_512>::decoration);

}

namespace cjs {

    std::wstring apppath(int mode = 0) {
        wchar_t buffer[MAX_PATH];
        if (mode == 0) {
            GetModuleFileName(NULL, buffer, MAX_PATH);
            std::wstring executablePath(buffer);
            size_t lastSlash = executablePath.find_last_of(L"\\/");
            if (lastSlash == std::wstring::npos) {
                return L"";
            }
            std::wstring programDirectory = executablePath.substr(0, lastSlash + 1);
            return programDirectory;
        }
        else if (mode == -1) {
            GetModuleFileName(NULL, buffer, MAX_PATH);
            std::wstring executablePath(buffer);
            return executablePath;
        }
        else if (mode == 2) {
            GetModuleFileName(NULL, buffer, MAX_PATH);
            std::wstring executablePath(buffer);
            size_t lastSlash = executablePath.find_last_of(L"\\/");
            if (lastSlash == std::wstring::npos) {
                return L"";
            }
            std::wstring programDirectory = executablePath.substr(0, lastSlash + 1);
            return programDirectory + L"\\Temp\\";
        }
        return L"";
    }

    typedef uint64_t ULL;

#if defined(_WIN64)
    std::string platform = "win-x64";
#elif defined(_WIN32)
    std::string platform = "win-x32";
#elif defined(__linux__)
    std::string platform = "linux";
#elif defined(__APPLE__)
    std::string platform = "macos";
#else
    std::string platform = "unknown";
#endif

#if defined(_DEBUG)
    std::wstring cplatform = L"d";
#else
    std::wstring cplatform = L"r";
#endif

    std::string mode = "";
    HWND console = NULL;
    std::atomic<bool> isWTConsole = false;
    std::atomic<bool> isConsoleEnv = false;
    std::atomic<bool> isQuit = false;
    BOOL WINAPI ConsoleCtrlHandler(DWORD dwCtrlType) {
        switch (dwCtrlType) {
        case CTRL_C_EVENT:
            isQuit = true;
            break;
        case CTRL_BREAK_EVENT:
            isQuit = true;
            break;
        case CTRL_CLOSE_EVENT:
        case CTRL_LOGOFF_EVENT:
        case CTRL_SHUTDOWN_EVENT:
            isQuit = true;
            FreeConsole();
            Sleep(1000);
            break;
        default:
            break;
        }
        if (isQuit == true && dwCtrlType != CTRL_CLOSE_EVENT && dwCtrlType != CTRL_LOGOFF_EVENT && dwCtrlType != CTRL_SHUTDOWN_EVENT) FreeConsole();
        return TRUE;
    }
    bool IsConsoleClosed() {
        return isQuit.load(std::memory_order_acquire);
    }

    bool init() {
        HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
        return true;
    }
    void unInit() {
        CoUninitialize();
    }

    static std::unordered_map<std::wstring, std::wstring> TextLightColorValue = {
        {L"",             L"#D6D6D6"},
        {L"Gray",         L"#ADADAD"},
        {L"DarkGray",     L"#7D7D7D"},
        {L"LightGray",    L"#DDDDDD"},
        {L"SlateGray",    L"#91A0B3"},
        {L"Silver",       L"#D6D6D6"},
        {L"Green",        L"#73F867"},
        {L"ForestGreen",  L"#63E857"},
        {L"LimeGreen",    L"#83F877"},
        {L"Red",          L"#FF9191"},
        {L"Crimson",      L"#F58181"},
        {L"Tomato",       L"#FFA1A1"},
        {L"Yellow",       L"#FFFA7F"},
        {L"Gold",         L"#FFFA6B"},
        {L"Khaki",        L"#FFF48F"},
        {L"Blue",         L"#7FE5FF"},
        {L"RoyalBlue",    L"#6FD5FF"},
        {L"SkyBlue",      L"#8FE5FF"},
        {L"Cyan",         L"#77FFFF"},
        {L"Teal",         L"#67FFFF"},
        {L"Magenta",      L"#F387EF"},
        {L"Fuchsia",      L"#E377EF"},
        {L"Orchid",       L"#FF91FF"},
        {L"Orange",       L"#FAC8B1"},
        {L"Chocolate",    L"#EAB19F"},
        {L"Peach",        L"#FFC8B1"},
        {L"Purple",       L"#E5E0FF"},
        {L"Violet",       L"#DBDAFF"},
        {L"Indigo",       L"#F5EAFF"},
        {L"DarkGreen",    L"#55F847"},
        {L"DarkRed",      L"#FF7272"},
        {L"DarkBlue",     L"#5FD5FF"},
        {L"Error",        L"#FF4444"},
        {L"Warn",         L"#FFFF44"},
        {L"Warning",      L"#FFFF44"},
        {L"Success",      L"#44FF44"},
        {L"Info",         L"#87CEEB"},
        {L"Keyword",      L"#7FE5FF"},
        {L"Operator",     L"#D6D6D6"},
        {L"String",       L"#FAC8B1"},
        {L"Number",       L"#B8D8A8"},
        {L"Boolean",      L"#7FE5FF"},
        {L"NullUndefined",L"#E5E0FF"},
        {L"Punctuator",   L"#ADADAD"},
        {L"Comment",      L"#73F867"},
        {L"BuiltInObject",L"#77FFFF"},
        {L"BuiltInFunction",L"#67FFFF"},
        {L"Class",        L"#77FFFF"},
        {L"Function",     L"#83F877"},
        {L"Method",       L"#73F867"},
        {L"Property",     L"#80C8FF"},
        {L"Variable",     L"#80C8FF"},
        {L"Constant",     L"#E5E0FF"},
        {L"Module",       L"#7FE5FF"},
        {L"Promise",      L"#E5E0FF"},
        {L"RegExp",       L"#FAC8B1"},
        {L"Symbol",       L"#77FFFF"},
        {L"Type",         L"#7FE5FF"},
        {L"Debug",        L"#83F877"},
        {L"Highlight",    L"#FFFA7F"},
        {L"Default",      L"#D6D6D6"},
        {L"Black",        L"#2B2B2B"},
        {L"White",        L"#FFFFFF"},
        {L"Date",         L"#7FE5FF"},
        {L"Array",        L"#77FFFF"},
        {L"Object",       L"#80C8FF"}
    };
    std::wstring GetColorValue(const std::wstring& key) {
        auto it = TextLightColorValue.find(key);
        return (it != TextLightColorValue.end()) ? it->second : TextLightColorValue[L"Default"];
    }

    std::string wstringToString(const std::wstring& str) noexcept {
        if (str.empty()) {
            return {};
        }
        if (str.size() > INT_MAX) {
            return {};
        }
        int requiredSize = WideCharToMultiByte(
            CP_UTF8,               // 目标编码：UTF-8
            0,                     // 转换标志：0（不处理无效字符）
            str.data(),            // 输入宽字符串
            static_cast<int>(str.size()), // 输入长度（不含\0）
            nullptr,               // 输出缓冲区：先不传
            0,                     // 输出缓冲区大小：0（仅获取所需大小）
            nullptr,               // 默认字符：NULL（遇到无效字符失败）
            nullptr                // 是否使用默认字符：NULL
        );
        if (requiredSize == 0) {
            return {};
        }
        std::string result(requiredSize, '\0');
        int convertedSize = WideCharToMultiByte(
            CP_UTF8,
            0,
            str.data(),
            static_cast<int>(str.size()),
            result.data(),
            requiredSize,
            nullptr,
            nullptr
        );
        if (convertedSize == 0) {
            return {};
        }
        result.resize(convertedSize);
        return result;
    }

    std::wstring stringToWstring(const std::string& str) noexcept {
        if (str.empty()) {
            return {};
        }
        if (str.size() > INT_MAX) {
            return {};
        }
        int requiredSize = MultiByteToWideChar(
            CP_UTF8,               // 源编码：UTF-8
            0,                     // 转换标志：0
            str.data(),            // 输入多字节字符串
            static_cast<int>(str.size()), // 输入长度
            nullptr,               // 输出缓冲区：先不传
            0                      // 输出缓冲区大小：0
        );
        if (requiredSize == 0) {
            return {};
        }
        std::wstring result(requiredSize, L'\0');
        int convertedSize = MultiByteToWideChar(
            CP_UTF8,
            0,
            str.data(),
            static_cast<int>(str.size()),
            result.data(),
            requiredSize
        );
        if (convertedSize == 0) {
            return {};
        }
        result.resize(convertedSize);
        return result;
    }

    bool isMemoryOnHeap(void* pAddress)
    {
        if (pAddress == nullptr)
        {
            return false;
        }

        std::vector<HANDLE> heapHandles;
        DWORD heapCount = GetProcessHeaps(0, nullptr);
        if (heapCount == 0)
        {
            return false;
        }

        heapHandles.resize(heapCount);
        heapCount = GetProcessHeaps(heapCount, heapHandles.data());
        if (heapCount == 0)
        {
            return false;
        }

        for (DWORD i = 0; i < heapCount; ++i)
        {
            HANDLE hHeap = heapHandles[i];
            if (hHeap == nullptr)
            {
                continue;
            }
            if (HeapValidate(hHeap, 0, pAddress))
            {
                return true;
            }
        }

        return false;
    }

#ifdef _MSC_VER
#define FORCE_INLINE __forceinline
#define NOINLINE __declspec(noinline)
#define PREFETCH(x) _mm_prefetch((const char*)(x), _MM_HINT_T0)
#else
#define FORCE_INLINE inline __attribute__((always_inline))
#define NOINLINE __attribute__((noinline))
#define PREFETCH(x) __builtin_prefetch(x, 0, 3)
#endif
    using ThreadId = DWORD;
    class RecursiveMutex {
    private:
        SRWLOCK            m_srwLock{ SRWLOCK_INIT };
        alignas(8) std::atomic<ThreadId> m_owner{ 0 };
        alignas(4) std::atomic<int32_t>  m_count{ 0 };
        RecursiveMutex(const RecursiveMutex&) = delete;
        RecursiveMutex& operator=(const RecursiveMutex&) = delete;
        RecursiveMutex(RecursiveMutex&&) = delete;
        RecursiveMutex& operator=(RecursiveMutex&&) = delete;
        NOINLINE void lock_slow_path(ThreadId tid) noexcept {
            AcquireSRWLockExclusive(&m_srwLock);
            m_owner.store(tid, std::memory_order_release);
            m_count.store(1, std::memory_order_relaxed);
        }
        NOINLINE bool try_lock_slow_path(ThreadId tid) noexcept {
            if (TryAcquireSRWLockExclusive(&m_srwLock)) {
                m_owner.store(tid, std::memory_order_release);
                m_count.store(1, std::memory_order_relaxed);
                return true;
            }
            return false;
        }

    public:
        FORCE_INLINE RecursiveMutex() noexcept = default;
        FORCE_INLINE ~RecursiveMutex() noexcept {
#ifdef _DEBUG
            if (m_owner.load(std::memory_order_acquire) != 0) {
                __debugbreak();
            }
#endif
        }
        FORCE_INLINE void lock() noexcept {
            PREFETCH(&m_owner);
            PREFETCH(&m_count);
            const ThreadId tid = GetCurrentThreadId();
            const ThreadId owner = m_owner.load(std::memory_order_relaxed);
            if (owner != static_cast<ThreadId>(0xFFFFFFFFFFFFFFFF) && owner == tid) {
                m_count.fetch_add(1, std::memory_order_relaxed);
                return;
            }
            lock_slow_path(tid);
        }
        FORCE_INLINE void unlock() noexcept {
            const int32_t old_count = m_count.fetch_sub(1, std::memory_order_acq_rel);

#ifdef _DEBUG
            const ThreadId tid = GetCurrentThreadId();
            if (old_count <= 0 || m_owner.load(std::memory_order_acquire) != tid) {
                __debugbreak();
            }
#endif
            if (old_count == 1) {
                m_owner.store(0, std::memory_order_relaxed);
                ReleaseSRWLockExclusive(&m_srwLock);
            }
        }
        FORCE_INLINE bool try_lock() noexcept {
            PREFETCH(&m_owner);
            const ThreadId tid = GetCurrentThreadId();
            const ThreadId owner = m_owner.load(std::memory_order_relaxed);
            if (owner != static_cast<ThreadId>(0xFFFFFFFFFFFFFFFF) && owner == tid) {
                m_count.fetch_add(1, std::memory_order_relaxed);
                return true;
            }
            return try_lock_slow_path(tid);
        }
    };
#undef FORCE_INLINE
#undef NOINLINE
#undef PREFETCH

    template <typename K, typename V>
    class ordered_map {
    private:
        std::vector<std::pair<K, V>> m_data;
        std::unordered_map<K, size_t> m_index_map;
        mutable RecursiveMutex m_mutex;

    public:
        using key_type = K;
        using mapped_type = V;
        using value_type = std::pair<K, V>;
        using size_type = size_t;
        using difference_type = ptrdiff_t;
        using iterator = typename std::vector<value_type>::iterator;
        using const_iterator = typename std::vector<value_type>::const_iterator;
        using reverse_iterator = typename std::vector<value_type>::reverse_iterator;
        using const_reverse_iterator = typename std::vector<value_type>::const_reverse_iterator;
        using reference = value_type&;
        using const_reference = const value_type&;

        ordered_map() = default;
        ordered_map(std::initializer_list<value_type> init) {
            for (const auto& pair : init) {
                insert(pair);
            }
        }

        template <typename InputIt>
        ordered_map(InputIt first, InputIt last) {
            insert(first, last);
        }

        ordered_map(const ordered_map& other) {
            std::lock_guard<decltype(other.m_mutex)> lock(other.m_mutex);
            m_data = other.m_data;
            m_index_map = other.m_index_map;
        }

        ordered_map(ordered_map&& other) noexcept {
            std::lock_guard<decltype(other.m_mutex)> lock(other.m_mutex);
            m_data = std::move(other.m_data);
            m_index_map = std::move(other.m_index_map);
        }

        ordered_map& operator=(const ordered_map& other) {
            if (this != &other) {
                std::scoped_lock lock(m_mutex, other.m_mutex);
                m_data = other.m_data;
                m_index_map = other.m_index_map;
            }
            return *this;
        }

        ordered_map& operator=(ordered_map&& other) noexcept {
            if (this != &other) {
                std::scoped_lock lock(m_mutex, other.m_mutex);
                m_data = std::move(other.m_data);
                m_index_map = std::move(other.m_index_map);
            }
            return *this;
        }

        ordered_map& operator=(std::initializer_list<value_type> init) {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            clear();
            insert(init);
            return *this;
        }

        ~ordered_map() = default;

        void lock() const { m_mutex.lock(); }
        void unlock() const { m_mutex.unlock(); }
        bool try_lock() const { return m_mutex.try_lock(); }

        iterator begin() noexcept { return m_data.begin(); }
        const_iterator begin() const noexcept { return m_data.cbegin(); }
        const_iterator cbegin() const noexcept { return m_data.cbegin(); }
        iterator end() noexcept { return m_data.end(); }
        const_iterator end() const noexcept { return m_data.cend(); }
        const_iterator cend() const noexcept { return m_data.cend(); }

        reverse_iterator rbegin() noexcept { return m_data.rbegin(); }
        const_reverse_iterator rbegin() const noexcept { return m_data.crbegin(); }
        const_reverse_iterator crbegin() const noexcept { return m_data.crbegin(); }
        reverse_iterator rend() noexcept { return m_data.rend(); }
        const_reverse_iterator rend() const noexcept { return m_data.crend(); }
        const_reverse_iterator crend() const noexcept { return m_data.crend(); }

        bool empty() const noexcept {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            return m_data.empty();
        }

        size_type size() const noexcept {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            return m_data.size();
        }

        size_type max_size() const noexcept {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            return std::min(m_data.max_size(), m_index_map.max_size());
        }

        V& operator[](const K& key) {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            auto it = m_index_map.find(key);
            if (it != m_index_map.end()) {
                return m_data[it->second].second;
            }
            m_data.emplace_back(std::piecewise_construct,
                std::forward_as_tuple(key),
                std::forward_as_tuple(V{}));
            m_index_map[key] = m_data.size() - 1;
            return m_data.back().second;
        }

        V& operator[](K&& key) {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            auto it = m_index_map.find(key);
            if (it != m_index_map.end()) {
                return m_data[it->second].second;
            }
            m_data.emplace_back(std::piecewise_construct,
                std::forward_as_tuple(std::move(key)),
                std::forward_as_tuple(V{}));
            m_index_map[m_data.back().first] = m_data.size() - 1;
            return m_data.back().second;
        }

        V& at(const K& key) {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            auto it = m_index_map.find(key);
            if (it == m_index_map.end()) {
                throw std::out_of_range("ordered_map::at: key not found");
            }
            return m_data[it->second].second;
        }

        const V& at(const K& key) const {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            auto it = m_index_map.find(key);
            if (it == m_index_map.end()) {
                throw std::out_of_range("ordered_map::at: key not found");
            }
            return m_data[it->second].second;
        }

        reference at(size_type idx) {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            if (idx >= m_data.size()) {
                throw std::out_of_range("ordered_map::at: index out of range");
            }
            return m_data[idx];
        }

        const_reference at(size_type idx) const {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            if (idx >= m_data.size()) {
                throw std::out_of_range("ordered_map::at: index out of range");
            }
            return m_data[idx];
        }

        iterator find(const K& key) {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            auto it = m_index_map.find(key);
            return (it != m_index_map.end()) ? m_data.begin() + it->second : end();
        }

        const_iterator find(const K& key) const {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            auto it = m_index_map.find(key);
            return (it != m_index_map.end()) ? m_data.cbegin() + it->second : cend();
        }

        size_type count(const K& key) const {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            return m_index_map.count(key);
        }

        bool contains(const K& key) const noexcept {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            return m_index_map.contains(key);
        }

        iterator lower_bound(const K& key) {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            auto it = find(key);
            return it != end() ? it : end();
        }

        const_iterator lower_bound(const K& key) const {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            auto it = find(key);
            return it != cend() ? it : cend();
        }

        iterator upper_bound(const K& key) {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            auto it = find(key);
            return it != end() ? std::next(it) : end();
        }

        const_iterator upper_bound(const K& key) const {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            auto it = find(key);
            return it != cend() ? std::next(it) : cend();
        }

        std::pair<iterator, iterator> equal_range(const K& key) {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            return { lower_bound(key), upper_bound(key) };
        }

        std::pair<const_iterator, const_iterator> equal_range(const K& key) const {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            return { lower_bound(key), upper_bound(key) };
        }

        std::pair<iterator, bool> insert(const value_type& pair) {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            auto it = m_index_map.find(pair.first);
            if (it != m_index_map.end()) {
                m_data[it->second].second = pair.second;
                return { m_data.begin() + it->second, false };
            }
            m_data.push_back(pair);
            m_index_map[pair.first] = m_data.size() - 1;
            return { std::prev(m_data.end()), true };
        }

        std::pair<iterator, bool> insert(value_type&& pair) {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            auto it = m_index_map.find(pair.first);
            if (it != m_index_map.end()) {
                m_data[it->second].second = std::move(pair.second);
                return { m_data.begin() + it->second, false };
            }
            m_data.push_back(std::move(pair));
            m_index_map[m_data.back().first] = m_data.size() - 1;
            return { std::prev(m_data.end()), true };
        }

        iterator insert(const_iterator hint, const value_type& pair) {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            (void)hint;
            return insert(pair).first;
        }

        iterator insert(const_iterator hint, value_type&& pair) {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            (void)hint;
            return insert(std::move(pair)).first;
        }

        template <typename InputIt>
        void insert(InputIt first, InputIt last) {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            for (; first != last; ++first) {
                insert(*first);
            }
        }

        void insert(std::initializer_list<value_type> init) {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            for (const auto& p : init) {
                insert(p);
            }
        }

        template <typename... Args>
        std::pair<iterator, bool> emplace(Args&&... args) {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            value_type temp_pair(std::forward<Args>(args)...);
            auto idx_it = m_index_map.find(temp_pair.first);

            if (idx_it != m_index_map.end()) {
                return { m_data.begin() + idx_it->second, false };
            }

            m_data.push_back(std::move(temp_pair));
            size_type new_idx = m_data.size() - 1;
            m_index_map[m_data.back().first] = new_idx;
            return { m_data.begin() + new_idx, true };
        }

        template <typename... Args>
        iterator emplace_hint(const_iterator hint, Args&&... args) {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            (void)hint;
            return emplace(std::forward<Args>(args)...).first;
        }

        size_type erase(const K& key) {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            auto it = m_index_map.find(key);
            if (it == m_index_map.end()) {
                return 0;
            }
            size_type idx = it->second;
            m_data.erase(m_data.begin() + idx);
            m_index_map.erase(it);
            for (auto& [k, i] : m_index_map) {
                if (i > idx) {
                    --i;
                }
            }
            return 1;
        }

        iterator erase(iterator pos) {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            if (pos == end()) {
                return end();
            }
            const K& key = pos->first;
            size_type idx = std::distance(begin(), pos);
            m_index_map.erase(key);
            iterator ret = m_data.erase(pos);
            for (auto& [k, i] : m_index_map) {
                if (i > idx) {
                    --i;
                }
            }
            return ret;
        }

        iterator erase(const_iterator pos) {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            return erase(begin() + std::distance(cbegin(), pos));
        }

        iterator erase(iterator first, iterator last) {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            if (first == last) {
                return last;
            }
            std::vector<K> keys_to_erase;
            size_type start_idx = std::distance(begin(), first);
            size_type erase_count = std::distance(first, last);
            for (auto it = first; it != last; ++it) {
                keys_to_erase.push_back(it->first);
            }
            iterator ret = m_data.erase(first, last);
            for (const K& key : keys_to_erase) {
                m_index_map.erase(key);
            }
            for (auto& [k, i] : m_index_map) {
                if (i >= start_idx) {
                    i -= erase_count;
                }
            }
            return ret;
        }

        void swap(ordered_map& other) noexcept {
            if (this != &other) {
                std::scoped_lock lock(m_mutex, other.m_mutex);
                m_data.swap(other.m_data);
                m_index_map.swap(other.m_index_map);
            }
        }

        void clear() noexcept {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            m_data.clear();
            m_index_map.clear();
        }

        friend void swap(ordered_map& lhs, ordered_map& rhs) noexcept {
            lhs.swap(rhs);
        }

        friend bool operator==(const ordered_map& lhs, const ordered_map& rhs) {
            std::scoped_lock lock(lhs.m_mutex, rhs.m_mutex);
            return lhs.m_data == rhs.m_data;
        }
        friend bool operator!=(const ordered_map& lhs, const ordered_map& rhs) {
            return !(lhs == rhs);
        }
        friend bool operator<(const ordered_map& lhs, const ordered_map& rhs) {
            std::scoped_lock lock(lhs.m_mutex, rhs.m_mutex);
            return lhs.m_data < rhs.m_data;
        }
        friend bool operator<=(const ordered_map& lhs, const ordered_map& rhs) {
            return !(rhs < lhs);
        }
        friend bool operator>(const ordered_map& lhs, const ordered_map& rhs) {
            return rhs < lhs;
        }
        friend bool operator>=(const ordered_map& lhs, const ordered_map& rhs) {
            return !(lhs < rhs);
        }
    };
    template <typename K, typename V>
    class ordered_multimap {
    private:
        std::vector<std::pair<K, V>> m_data;
        std::unordered_map<K, std::vector<size_t>> m_index_map;
        mutable RecursiveMutex m_mutex;

    public:
        using key_type = K;
        using mapped_type = V;
        using value_type = std::pair<K, V>;
        using size_type = size_t;
        using difference_type = ptrdiff_t;
        using iterator = typename std::vector<value_type>::iterator;
        using const_iterator = typename std::vector<value_type>::const_iterator;
        using reverse_iterator = typename std::vector<value_type>::reverse_iterator;
        using const_reverse_iterator = typename std::vector<value_type>::const_reverse_iterator;
        using reference = value_type&;
        using const_reference = const value_type&;
        using key_compare = std::less<K>;

        ordered_multimap() = default;
        ordered_multimap(std::initializer_list<value_type> init) {
            insert(init);
        }

        template <typename InputIt>
        ordered_multimap(InputIt first, InputIt last) {
            insert(first, last);
        }

        ordered_multimap(const ordered_multimap& other) {
            std::lock_guard<decltype(other.m_mutex)> lock(other.m_mutex);
            m_data = other.m_data;
            m_index_map = other.m_index_map;
        }

        ordered_multimap(ordered_multimap&& other) noexcept {
            std::lock_guard<decltype(other.m_mutex)> lock(other.m_mutex);
            m_data = std::move(other.m_data);
            m_index_map = std::move(other.m_index_map);
        }

        ordered_multimap& operator=(const ordered_multimap& other) {
            if (this != &other) {
                std::scoped_lock lock(m_mutex, other.m_mutex);
                m_data = other.m_data;
                m_index_map = other.m_index_map;
            }
            return *this;
        }

        ordered_multimap& operator=(ordered_multimap&& other) noexcept {
            if (this != &other) {
                std::scoped_lock lock(m_mutex, other.m_mutex);
                m_data = std::move(other.m_data);
                m_index_map = std::move(other.m_index_map);
            }
            return *this;
        }

        ordered_multimap& operator=(std::initializer_list<value_type> init) {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            clear();
            insert(init);
            return *this;
        }

        ~ordered_multimap() = default;

        void lock() const { m_mutex.lock(); }
        void unlock() const { m_mutex.unlock(); }
        bool try_lock() const { return m_mutex.try_lock(); }

        iterator begin() noexcept { return m_data.begin(); }
        const_iterator begin() const noexcept { return m_data.cbegin(); }
        const_iterator cbegin() const noexcept { return m_data.cbegin(); }
        iterator end() noexcept { return m_data.end(); }
        const_iterator end() const noexcept { return m_data.cend(); }
        const_iterator cend() const noexcept { return m_data.cend(); }

        reverse_iterator rbegin() noexcept { return m_data.rbegin(); }
        const_reverse_iterator rbegin() const noexcept { return m_data.crbegin(); }
        const_reverse_iterator crbegin() const noexcept { return m_data.crbegin(); }
        reverse_iterator rend() noexcept { return m_data.rend(); }
        const_reverse_iterator rend() const noexcept { return m_data.crend(); }
        const_reverse_iterator crend() const noexcept { return m_data.crend(); }

        bool empty() const noexcept {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            return m_data.empty();
        }

        size_type size() const noexcept {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            return m_data.size();
        }

        size_type max_size() const noexcept {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            return std::min(m_data.max_size(), m_index_map.max_size());
        }

        V& operator[](const K& key) {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            m_data.emplace_back(key, V{});
            size_type new_idx = m_data.size() - 1;
            m_index_map[key].push_back(new_idx);
            return m_data.back().second;
        }

        V& operator[](K&& key) {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            m_data.emplace_back(std::move(key), V{});
            size_type new_idx = m_data.size() - 1;
            m_index_map[m_data.back().first].push_back(new_idx);
            return m_data.back().second;
        }

        V& at(const K& key) {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            auto it = m_index_map.find(key);
            if (it == m_index_map.end() || it->second.empty()) {
                throw std::out_of_range("ordered_multimap::at: key not found");
            }
            return m_data[it->second.front()].second;
        }

        const V& at(const K& key) const {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            auto it = m_index_map.find(key);
            if (it == m_index_map.end() || it->second.empty()) {
                throw std::out_of_range("ordered_multimap::at: key not found");
            }
            return m_data[it->second.front()].second;
        }

        reference at(size_type idx) {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            if (idx >= m_data.size()) {
                throw std::out_of_range("ordered_multimap::at: index out of range");
            }
            return m_data[idx];
        }

        const_reference at(size_type idx) const {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            if (idx >= m_data.size()) {
                throw std::out_of_range("ordered_multimap::at: index out of range");
            }
            return m_data[idx];
        }

        iterator find(const K& key) {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            auto it = m_index_map.find(key);
            if (it == m_index_map.end() || it->second.empty()) {
                return end();
            }
            return m_data.begin() + it->second.front();
        }

        const_iterator find(const K& key) const {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            auto it = m_index_map.find(key);
            if (it == m_index_map.end() || it->second.empty()) {
                return cend();
            }
            return m_data.cbegin() + it->second.front();
        }

        size_type count(const K& key) const {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            auto it = m_index_map.find(key);
            return (it != m_index_map.end()) ? it->second.size() : 0;
        }

        bool contains(const K& key) const noexcept {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            auto it = m_index_map.find(key);
            return (it != m_index_map.end()) && !it->second.empty();
        }

        iterator lower_bound(const K& key) {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            return find(key);
        }

        const_iterator lower_bound(const K& key) const {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            return find(key);
        }

        iterator upper_bound(const K& key) {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            auto it = m_index_map.find(key);
            if (it == m_index_map.end() || it->second.empty()) {
                return end();
            }
            return m_data.begin() + it->second.back() + 1;
        }

        const_iterator upper_bound(const K& key) const {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            auto it = m_index_map.find(key);
            if (it == m_index_map.end() || it->second.empty()) {
                return cend();
            }
            return m_data.cbegin() + it->second.back() + 1;
        }

        std::pair<iterator, iterator> equal_range(const K& key) {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            return { lower_bound(key), upper_bound(key) };
        }

        std::pair<const_iterator, const_iterator> equal_range(const K& key) const {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            return { lower_bound(key), upper_bound(key) };
        }

        iterator insert(const value_type& pair) {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            size_type new_idx = m_data.size();
            m_data.push_back(pair);
            m_index_map[pair.first].push_back(new_idx);
            return m_data.begin() + new_idx;
        }

        iterator insert(value_type&& pair) {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            size_type new_idx = m_data.size();
            m_data.push_back(std::move(pair));
            m_index_map[m_data.back().first].push_back(new_idx);
            return m_data.begin() + new_idx;
        }

        iterator insert(const_iterator hint, const value_type& pair) {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            (void)hint;
            return insert(pair);
        }

        iterator insert(const_iterator hint, value_type&& pair) {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            (void)hint;
            return insert(std::move(pair));
        }

        template <typename InputIt>
        void insert(InputIt first, InputIt last) {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            for (; first != last; ++first) {
                insert(*first);
            }
        }

        void insert(std::initializer_list<value_type> init) {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            for (const auto& p : init) {
                insert(p);
            }
        }

        template <typename... Args>
        iterator emplace(Args&&... args) {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            size_type new_idx = m_data.size();
            m_data.emplace_back(std::forward<Args>(args)...);
            m_index_map[m_data.back().first].push_back(new_idx);
            return m_data.begin() + new_idx;
        }

        template <typename... Args>
        iterator emplace_hint(const_iterator hint, Args&&... args) {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            (void)hint;
            return emplace(std::forward<Args>(args)...);
        }

        size_type erase(const K& key) {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            auto it = m_index_map.find(key);
            if (it == m_index_map.end() || it->second.empty()) {
                return 0;
            }

            std::vector<size_type> indices = it->second;
            std::sort(indices.rbegin(), indices.rend());

            size_type erase_count = indices.size();
            for (size_type idx : indices) {
                m_data.erase(m_data.begin() + idx);
            }

            m_index_map.erase(it);

            for (auto& [k, idx_list] : m_index_map) {
                for (size_t& i : idx_list) {
                    for (size_type erased_idx : indices) {
                        if (i > erased_idx) {
                            --i;
                        }
                    }
                }
            }

            return erase_count;
        }

        iterator erase(iterator pos) {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            if (pos == end()) {
                return end();
            }

            const K& key = pos->first;
            size_type idx = std::distance(begin(), pos);

            auto it = m_index_map.find(key);
            if (it != m_index_map.end()) {
                auto& idx_list = it->second;
                auto idx_it = std::find(idx_list.begin(), idx_list.end(), idx);
                if (idx_it != idx_list.end()) {
                    idx_list.erase(idx_it);
                }
                if (idx_list.empty()) {
                    m_index_map.erase(it);
                }
            }

            iterator ret = m_data.erase(pos);

            size_type erased_idx = idx;
            for (auto& [k, idx_list] : m_index_map) {
                for (size_t& i : idx_list) {
                    if (i > erased_idx) {
                        --i;
                    }
                }
            }

            return ret;
        }

        iterator erase(const_iterator pos) {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            return erase(begin() + std::distance(cbegin(), pos));
        }

        iterator erase(iterator first, iterator last) {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            if (first == last) {
                return last;
            }

            std::vector<K> keys_to_update;
            std::vector<size_type> indices_to_erase;
            size_type start_idx = std::distance(begin(), first);
            size_type erase_count = std::distance(first, last);

            for (auto it = first; it != last; ++it) {
                keys_to_update.push_back(it->first);
                indices_to_erase.push_back(std::distance(begin(), it));
            }

            std::sort(indices_to_erase.rbegin(), indices_to_erase.rend());
            for (size_type idx : indices_to_erase) {
                m_data.erase(m_data.begin() + idx);
            }

            for (const K& key : keys_to_update) {
                auto it = m_index_map.find(key);
                if (it != m_index_map.end()) {
                    auto& idx_list = it->second;
                    for (size_type erased_idx : indices_to_erase) {
                        auto idx_it = std::find(idx_list.begin(), idx_list.end(), erased_idx);
                        if (idx_it != idx_list.end()) {
                            idx_list.erase(idx_it);
                        }
                    }
                    if (idx_list.empty()) {
                        m_index_map.erase(it);
                    }
                }
            }

            for (auto& [k, idx_list] : m_index_map) {
                for (size_t& i : idx_list) {
                    if (i >= start_idx) {
                        i -= erase_count;
                    }
                }
            }

            return begin() + start_idx;
        }

        void swap(ordered_multimap& other) noexcept {
            if (this != &other) {
                std::scoped_lock lock(m_mutex, other.m_mutex);
                m_data.swap(other.m_data);
                m_index_map.swap(other.m_index_map);
            }
        }

        void clear() noexcept {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            m_data.clear();
            m_index_map.clear();
        }

        friend void swap(ordered_multimap& lhs, ordered_multimap& rhs) noexcept {
            lhs.swap(rhs);
        }

        friend bool operator==(const ordered_multimap& lhs, const ordered_multimap& rhs) {
            std::scoped_lock lock(lhs.m_mutex, rhs.m_mutex);
            return lhs.m_data == rhs.m_data;
        }

        friend bool operator!=(const ordered_multimap& lhs, const ordered_multimap& rhs) {
            return !(lhs == rhs);
        }

        friend bool operator<(const ordered_multimap& lhs, const ordered_multimap& rhs) {
            std::scoped_lock lock(lhs.m_mutex, rhs.m_mutex);
            return lhs.m_data < rhs.m_data;
        }

        friend bool operator<=(const ordered_multimap& lhs, const ordered_multimap& rhs) {
            return !(rhs < lhs);
        }

        friend bool operator>(const ordered_multimap& lhs, const ordered_multimap& rhs) {
            return rhs < lhs;
        }

        friend bool operator>=(const ordered_multimap& lhs, const ordered_multimap& rhs) {
            return !(lhs < rhs);
        }

        key_compare key_comp() const {
            return key_compare();
        }
    };
    using GMT = ordered_map<std::wstring, std::wstring>;
    using GMMT = ordered_multimap<std::wstring, std::wstring>;
    typedef std::vector<unsigned char> BYTEBUFFER, * BYTEBUFFER_PTR;

    template <typename Key,
        typename Value,
        typename Hash = std::hash<Key>,
        typename KeyEqual = std::equal_to<Key>,
        typename Allocator = std::allocator<std::pair<const Key, Value>>>
    class unordered_map_lock {
    private:
        using map_type = std::unordered_map<Key, Value, Hash, KeyEqual, Allocator>;
        map_type m_map;
        mutable RecursiveMutex m_mutex;

    public:
        // 类型别名（完全匹配标准容器）
        using key_type = Key;
        using mapped_type = Value;
        using value_type = std::pair<const Key, Value>;
        using size_type = typename map_type::size_type;
        using difference_type = typename map_type::difference_type;
        using hasher = Hash;
        using key_equal = KeyEqual;
        using allocator_type = Allocator;
        using reference = value_type&;
        using const_reference = const value_type&;
        using pointer = typename std::allocator_traits<Allocator>::pointer;
        using const_pointer = typename std::allocator_traits<Allocator>::const_pointer;
        using iterator = typename map_type::iterator;
        using const_iterator = typename map_type::const_iterator;
        using local_iterator = typename map_type::local_iterator;
        using const_local_iterator = typename map_type::const_local_iterator;

        // 构造函数
        unordered_map_lock() = default;
        explicit unordered_map_lock(size_type n) : m_map(n) {}
        unordered_map_lock(size_type n, const hasher& hf) : m_map(n, hf) {}
        unordered_map_lock(size_type n, const hasher& hf, const key_equal& eql) : m_map(n, hf, eql) {}

        template <typename InputIt>
        unordered_map_lock(InputIt first, InputIt last) : m_map(first, last) {}
        template <typename InputIt>
        unordered_map_lock(InputIt first, InputIt last, size_type n) : m_map(first, last, n) {}
        template <typename InputIt>
        unordered_map_lock(InputIt first, InputIt last, size_type n, const hasher& hf) : m_map(first, last, n, hf) {}
        template <typename InputIt>
        unordered_map_lock(InputIt first, InputIt last, size_type n, const hasher& hf, const key_equal& eql) : m_map(first, last, n, hf, eql) {}

        unordered_map_lock(std::initializer_list<value_type> init) : m_map(init) {}

        // 拷贝构造
        unordered_map_lock(const unordered_map_lock& other) {
            std::lock_guard<decltype(other.m_mutex)> lock(other.m_mutex);
            m_map = other.m_map;
        }

        // 移动构造
        unordered_map_lock(unordered_map_lock&& other) noexcept {
            std::lock_guard<decltype(other.m_mutex)> lock(other.m_mutex);
            m_map = std::move(other.m_map);
        }

        // 析构函数
        ~unordered_map_lock() = default;

        // 赋值操作
        unordered_map_lock& operator=(const unordered_map_lock& other) {
            if (this != &other) {
                std::scoped_lock lock(m_mutex, other.m_mutex);
                m_map = other.m_map;
            }
            return *this;
        }

        unordered_map_lock& operator=(unordered_map_lock&& other) noexcept {
            if (this != &other) {
                std::scoped_lock lock(m_mutex, other.m_mutex);
                m_map = std::move(other.m_map);
            }
            return *this;
        }

        unordered_map_lock& operator=(std::initializer_list<value_type> init) {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            m_map = init;
            return *this;
        }

        // --- 手动锁控制接口 ---
        void lock() const { m_mutex.lock(); }
        void unlock() const { m_mutex.unlock(); }
        bool try_lock() const { return m_mutex.try_lock(); }

        // --- 自动加锁的接口 ---

        // 元素访问
        mapped_type& operator[](const key_type& key) {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            return m_map[key];
        }
        mapped_type& operator[](key_type&& key) {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            return m_map[std::move(key)];
        }

        mapped_type& at(const key_type& key) {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            return m_map.at(key);
        }
        const mapped_type& at(const key_type& key) const {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            return m_map.at(key);
        }

        // 容量
        bool empty() const {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            return m_map.empty();
        }
        size_type size() const {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            return m_map.size();
        }
        size_type max_size() const {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            return m_map.max_size();
        }

        // 修改器
        void clear() noexcept {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            m_map.clear();
        }

        std::pair<iterator, bool> insert(const value_type& value) {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            return m_map.insert(value);
        }
        std::pair<iterator, bool> insert(value_type&& value) {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            return m_map.insert(std::move(value));
        }
        iterator insert(const_iterator hint, const value_type& value) {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            return m_map.insert(hint, value);
        }
        iterator insert(const_iterator hint, value_type&& value) {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            return m_map.insert(hint, std::move(value));
        }

        template <typename InputIt>
        void insert(InputIt first, InputIt last) {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            m_map.insert(first, last);
        }
        void insert(std::initializer_list<value_type> init) {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            m_map.insert(init);
        }

        template <typename... Args>
        std::pair<iterator, bool> emplace(Args&&... args) {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            return m_map.emplace(std::forward<Args>(args)...);
        }
        template <typename... Args>
        iterator emplace_hint(const_iterator hint, Args&&... args) {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            return m_map.emplace_hint(hint, std::forward<Args>(args)...);
        }

        size_type erase(const key_type& key) {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            return m_map.erase(key);
        }
        iterator erase(iterator pos) {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            return m_map.erase(pos);
        }
        iterator erase(const_iterator pos) {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            return m_map.erase(pos);
        }
        iterator erase(iterator first, iterator last) {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            return m_map.erase(first, last);
        }
        iterator erase(const_iterator first, const_iterator last) {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            return m_map.erase(first, last);
        }

        void swap(unordered_map_lock& other) {
            if (this != &other) {
                std::scoped_lock lock(m_mutex, other.m_mutex);
                m_map.swap(other.m_map);
            }
        }

        // 查找
        iterator find(const key_type& key) {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            return m_map.find(key);
        }
        const_iterator find(const key_type& key) const {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            return m_map.find(key);
        }

        size_type count(const key_type& key) const {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            return m_map.count(key);
        }

        std::pair<iterator, iterator> equal_range(const key_type& key) {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            return m_map.equal_range(key);
        }
        std::pair<const_iterator, const_iterator> equal_range(const key_type& key) const {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            return m_map.equal_range(key);
        }

        // 哈希策略
        hasher hash_function() const {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            return m_map.hash_function();
        }
        key_equal key_eq() const {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            return m_map.key_eq();
        }

        // 桶接口
        size_type bucket_count() const {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            return m_map.bucket_count();
        }
        size_type max_bucket_count() const {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            return m_map.max_bucket_count();
        }
        size_type bucket_size(size_type n) const {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            return m_map.bucket_size(n);
        }
        size_type bucket(const key_type& key) const {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            return m_map.bucket(key);
        }

        // 负载因子
        float load_factor() const {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            return m_map.load_factor();
        }
        float max_load_factor() const {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            return m_map.max_load_factor();
        }
        void max_load_factor(float z) {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            m_map.max_load_factor(z);
        }

        void rehash(size_type n) {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            m_map.rehash(n);
        }
        void reserve(size_type n) {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            m_map.reserve(n);
        }

        // 非标准实用接口
        bool find(const key_type& key, mapped_type& outValue) const {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            auto it = m_map.find(key);
            if (it != m_map.end()) {
                outValue = it->second;
                return true;
            }
            return false;
        }

        std::optional<mapped_type> try_get(const key_type& key) const {
            std::lock_guard<decltype(m_mutex)> lock(m_mutex);
            auto it = m_map.find(key);
            return it != m_map.end() ? std::optional<mapped_type>(it->second) : std::nullopt;
        }

        // --- 不加锁的接口 ---

        map_type* getPtr() {
            return &m_map;
        }

        // 迭代器
        iterator begin() noexcept { return m_map.begin(); }
        const_iterator begin() const noexcept { return m_map.begin(); }
        const_iterator cbegin() const noexcept { return m_map.cbegin(); }

        iterator end() noexcept { return m_map.end(); }
        const_iterator end() const noexcept { return m_map.end(); }
        const_iterator cend() const noexcept { return m_map.cend(); }

        local_iterator begin(size_type n) { return m_map.begin(n); }
        const_local_iterator begin(size_type n) const { return m_map.begin(n); }
        const_local_iterator cbegin(size_type n) const { return m_map.cbegin(n); }

        local_iterator end(size_type n) { return m_map.end(n); }
        const_local_iterator end(size_type n) const { return m_map.end(n); }
        const_local_iterator cend(size_type n) const { return m_map.cend(n); }
    };

    template <typename T,
        typename Allocator = std::allocator<T>>
        class vector_lock {
        private:
            using vector_type = std::vector<T, Allocator>;
            vector_type m_vector;
            mutable RecursiveMutex m_mutex;

        public:
            using value_type = T;
            using allocator_type = Allocator;
            using size_type = typename vector_type::size_type;
            using difference_type = typename vector_type::difference_type;
            using reference = value_type&;
            using const_reference = const value_type&;
            using pointer = typename std::allocator_traits<Allocator>::pointer;
            using const_pointer = typename std::allocator_traits<Allocator>::const_pointer;
            using iterator = typename vector_type::iterator;
            using const_iterator = typename vector_type::const_iterator;
            using reverse_iterator = typename vector_type::reverse_iterator;
            using const_reverse_iterator = typename vector_type::const_reverse_iterator;

            vector_lock() = default;
            explicit vector_lock(const Allocator& alloc) : m_vector(alloc) {}
            explicit vector_lock(size_type count, const Allocator& alloc = Allocator{}) : m_vector(count, alloc) {}
            vector_lock(size_type count, const T& value, const Allocator& alloc = Allocator{}) : m_vector(count, value, alloc) {}

            template <typename InputIt>
            vector_lock(InputIt first, InputIt last, const Allocator& alloc = Allocator{}) : m_vector(first, last, alloc) {}

            vector_lock(const vector_lock& other) {
                std::lock_guard<decltype(other.m_mutex)> lock(other.m_mutex);
                m_vector = other.m_vector;
            }

            vector_lock(const vector_lock& other, const Allocator& alloc) {
                std::lock_guard<decltype(other.m_mutex)> lock(other.m_mutex);
                m_vector = vector_type(other.m_vector, alloc);
            }

            vector_lock(vector_lock&& other) noexcept {
                std::lock_guard<decltype(other.m_mutex)> lock(other.m_mutex);
                m_vector = std::move(other.m_vector);
            }

            vector_lock(vector_lock&& other, const Allocator& alloc) {
                std::lock_guard<decltype(other.m_mutex)> lock(other.m_mutex);
                m_vector = vector_type(std::move(other.m_vector), alloc);
            }

            vector_lock(std::initializer_list<T> init, const Allocator& alloc = Allocator{}) : m_vector(init, alloc) {}

            operator std::vector<T>() const {
                std::lock_guard<decltype(m_mutex)> lock(m_mutex);
                return m_vector;
            }

            ~vector_lock() = default;

            vector_lock& operator=(const vector_lock& other) {
                if (this != &other) {
                    std::scoped_lock lock(m_mutex, other.m_mutex);
                    m_vector = other.m_vector;
                }
                return *this;
            }

            vector_lock& operator=(vector_lock&& other) noexcept {
                if (this != &other) {
                    std::scoped_lock lock(m_mutex, other.m_mutex);
                    m_vector = std::move(other.m_vector);
                }
                return *this;
            }

            vector_lock& operator=(std::initializer_list<T> init) {
                std::lock_guard<decltype(m_mutex)> lock(m_mutex);
                m_vector = init;
                return *this;
            }

            void lock() const { m_mutex.lock(); }
            void unlock() const { m_mutex.unlock(); }
            bool try_lock() const { return m_mutex.try_lock(); }

            iterator begin() noexcept { return m_vector.begin(); }
            const_iterator begin() const noexcept { return m_vector.begin(); }
            const_iterator cbegin() const noexcept { return m_vector.cbegin(); }

            iterator end() noexcept { return m_vector.end(); }
            const_iterator end() const noexcept { return m_vector.end(); }
            const_iterator cend() const noexcept { return m_vector.cend(); }

            reverse_iterator rbegin() noexcept { return m_vector.rbegin(); }
            const_reverse_iterator rbegin() const noexcept { return m_vector.rbegin(); }
            const_reverse_iterator crbegin() const noexcept { return m_vector.crbegin(); }

            reverse_iterator rend() noexcept { return m_vector.rend(); }
            const_reverse_iterator rend() const noexcept { return m_vector.rend(); }
            const_reverse_iterator crend() const noexcept { return m_vector.crend(); }

            bool empty() const {
                std::lock_guard<decltype(m_mutex)> lock(m_mutex);
                return m_vector.empty();
            }

            size_type size() const {
                std::lock_guard<decltype(m_mutex)> lock(m_mutex);
                return m_vector.size();
            }

            size_type max_size() const {
                std::lock_guard<decltype(m_mutex)> lock(m_mutex);
                return m_vector.max_size();
            }

            void resize(size_type count) {
                std::lock_guard<decltype(m_mutex)> lock(m_mutex);
                m_vector.resize(count);
            }

            void resize(size_type count, const T& value) {
                std::lock_guard<decltype(m_mutex)> lock(m_mutex);
                m_vector.resize(count, value);
            }

            size_type capacity() const {
                std::lock_guard<decltype(m_mutex)> lock(m_mutex);
                return m_vector.capacity();
            }

            void reserve(size_type new_cap) {
                std::lock_guard<decltype(m_mutex)> lock(m_mutex);
                m_vector.reserve(new_cap);
            }

            void shrink_to_fit() {
                std::lock_guard<decltype(m_mutex)> lock(m_mutex);
                m_vector.shrink_to_fit();
            }

            reference operator[](size_type pos) {
                std::lock_guard<decltype(m_mutex)> lock(m_mutex);
                return m_vector[pos];
            }

            const_reference operator[](size_type pos) const {
                std::lock_guard<decltype(m_mutex)> lock(m_mutex);
                return m_vector[pos];
            }

            reference at(size_type pos) {
                std::lock_guard<decltype(m_mutex)> lock(m_mutex);
                return m_vector.at(pos);
            }

            const_reference at(size_type pos) const {
                std::lock_guard<decltype(m_mutex)> lock(m_mutex);
                return m_vector.at(pos);
            }

            reference front() {
                std::lock_guard<decltype(m_mutex)> lock(m_mutex);
                return m_vector.front();
            }

            const_reference front() const {
                std::lock_guard<decltype(m_mutex)> lock(m_mutex);
                return m_vector.front();
            }

            reference back() {
                std::lock_guard<decltype(m_mutex)> lock(m_mutex);
                return m_vector.back();
            }

            const_reference back() const {
                std::lock_guard<decltype(m_mutex)> lock(m_mutex);
                return m_vector.back();
            }

            T* data() noexcept {
                std::lock_guard<decltype(m_mutex)> lock(m_mutex);
                return m_vector.data();
            }

            const T* data() const noexcept {
                std::lock_guard<decltype(m_mutex)> lock(m_mutex);
                return m_vector.data();
            }

            void assign(size_type count, const T& value) {
                std::lock_guard<decltype(m_mutex)> lock(m_mutex);
                m_vector.assign(count, value);
            }

            template <typename InputIt>
            void assign(InputIt first, InputIt last) {
                std::lock_guard<decltype(m_mutex)> lock(m_mutex);
                m_vector.assign(first, last);
            }

            void assign(std::initializer_list<T> init) {
                std::lock_guard<decltype(m_mutex)> lock(m_mutex);
                m_vector.assign(init);
            }

            void push_back(const T& value) {
                std::lock_guard<decltype(m_mutex)> lock(m_mutex);
                m_vector.push_back(value);
            }

            void push_back(T&& value) {
                std::lock_guard<decltype(m_mutex)> lock(m_mutex);
                m_vector.push_back(std::move(value));
            }

            template <typename... Args>
            reference emplace_back(Args&&... args) {
                std::lock_guard<decltype(m_mutex)> lock(m_mutex);
                return m_vector.emplace_back(std::forward<Args>(args)...);
            }

            void pop_back() {
                std::lock_guard<decltype(m_mutex)> lock(m_mutex);
                m_vector.pop_back();
            }

            iterator insert(const_iterator pos, const T& value) {
                std::lock_guard<decltype(m_mutex)> lock(m_mutex);
                return m_vector.insert(pos, value);
            }

            iterator insert(const_iterator pos, T&& value) {
                std::lock_guard<decltype(m_mutex)> lock(m_mutex);
                return m_vector.insert(pos, std::move(value));
            }

            iterator insert(const_iterator pos, size_type count, const T& value) {
                std::lock_guard<decltype(m_mutex)> lock(m_mutex);
                return m_vector.insert(pos, count, value);
            }

            template <typename InputIt>
            iterator insert(const_iterator pos, InputIt first, InputIt last) {
                std::lock_guard<decltype(m_mutex)> lock(m_mutex);
                return m_vector.insert(pos, first, last);
            }

            iterator insert(const_iterator pos, std::initializer_list<T> init) {
                std::lock_guard<decltype(m_mutex)> lock(m_mutex);
                return m_vector.insert(pos, init);
            }

            template <typename... Args>
            iterator emplace(const_iterator pos, Args&&... args) {
                std::lock_guard<decltype(m_mutex)> lock(m_mutex);
                return m_vector.emplace(pos, std::forward<Args>(args)...);
            }

            iterator erase(const_iterator pos) {
                std::lock_guard<decltype(m_mutex)> lock(m_mutex);
                return m_vector.erase(pos);
            }

            iterator erase(const_iterator first, const_iterator last) {
                std::lock_guard<decltype(m_mutex)> lock(m_mutex);
                return m_vector.erase(first, last);
            }

            void swap(vector_lock& other) {
                if (this != &other) {
                    std::scoped_lock lock(m_mutex, other.m_mutex);
                    m_vector.swap(other.m_vector);
                }
            }

            void clear() noexcept {
                std::lock_guard<decltype(m_mutex)> lock(m_mutex);
                m_vector.clear();
            }

            bool get_at(size_type pos, T& outValue) const {
                std::lock_guard<decltype(m_mutex)> lock(m_mutex);
                if (pos >= m_vector.size()) {
                    return false;
                }
                outValue = m_vector[pos];
                return true;
            }

            std::optional<T> try_get(size_type pos) const {
                std::lock_guard<decltype(m_mutex)> lock(m_mutex);
                if (pos >= m_vector.size()) {
                    return std::nullopt;
                }
                return m_vector[pos];
            }
            vector_type* getPtr() {
                return &m_vector;
            }

            const vector_type* getPtr() const {
                return &m_vector;
            }
    };
    template <typename T, typename Alloc>
    void swap(vector_lock<T, Alloc>& lhs, vector_lock<T, Alloc>& rhs) {
        lhs.swap(rhs);
    }

    struct OBJECTStruct;
    using OBJECT = ordered_map<std::wstring, OBJECTStruct>;
    using ARRAY = std::vector<OBJECTStruct>;
    struct OBJECTStruct {
        using DataVariant = std::variant<
            std::wstring, bool, int, long, long long, double,
            unsigned int, unsigned long, unsigned long long, nullptr_t, ARRAY, OBJECT
        >;
        DataVariant data;
        static constexpr size_t ARRAY_TYPE_INDEX = std::variant_size_v<DataVariant> -2;
        static constexpr size_t OBJECT_TYPE_INDEX = std::variant_size_v<DataVariant> -1;

        OBJECTStruct() = default;
        OBJECTStruct(const std::string& str) {
            data = stringToWstring(str);
        }
        OBJECTStruct& operator=(const std::string& str) {
            data = stringToWstring(str);
            return *this;
        }
        OBJECTStruct(const std::wstring& str) {
            data = str;
        }
        OBJECTStruct& operator=(const std::wstring& str) {
            data = str;
            return *this;
        }
        template <typename T,
            std::enable_if_t<!std::is_same_v<std::decay_t<T>, std::string> &&
            !std::is_same_v<std::decay_t<T>, std::wstring>&&
            std::is_constructible_v<DataVariant, T>, bool> = true>
        OBJECTStruct(T&& val) : data(std::forward<T>(val)) {}
        template <typename T,
            std::enable_if_t<!std::is_same_v<std::decay_t<T>, std::string> &&
            !std::is_same_v<std::decay_t<T>, std::wstring>&&
            std::is_assignable_v<DataVariant&, T>, bool> = true>
        OBJECTStruct& operator=(T&& val) {
            data = std::forward<T>(val);
            return *this;
        }
        bool isObject() const { return data.index() == OBJECT_TYPE_INDEX; }
        bool isArray() const { return std::holds_alternative<ARRAY>(data); }
        bool isString() const { return std::holds_alternative<std::wstring>(data); }
        bool isBool() const { return std::holds_alternative<bool>(data); }
        bool isInt() const { return std::holds_alternative<int>(data); }
        bool isLong() const { return std::holds_alternative<long>(data); }
        bool isLongLong() const { return std::holds_alternative<long long>(data); }
        bool isDouble() const { return std::holds_alternative<double>(data); }
        bool isUInt() const { return std::holds_alternative<unsigned int>(data); }
        bool isULong() const { return std::holds_alternative<unsigned long>(data); }
        bool isULongLong() const { return std::holds_alternative<unsigned long long>(data); }
        bool isNull() const { return std::holds_alternative<nullptr_t>(data); }
        OBJECTStruct& operator[](const std::string& key) {
            return (*this)[stringToWstring(key)];
        }
        OBJECTStruct& operator[](const char* key) {
            return (*this)[std::string(key)];
        }
        const OBJECTStruct& operator[](const std::string& key) const {
            return (*this)[stringToWstring(key)];
        }
        const OBJECTStruct& operator[](const char* key) const {
            return (*this)[std::string(key)];
        }
        OBJECTStruct& operator[](const std::wstring& key) {
            if (!isObject()) {
                data = OBJECT{};
            }
            OBJECT& nestedObj = std::get<OBJECT>(this->data);
            return nestedObj[key];
        }
        const OBJECTStruct& operator[](const std::wstring& key) const {
            if (!isObject()) {
                throw std::runtime_error("Current OBJECTStruct is not an OBJECT type");
            }
            const OBJECT& nestedObj = std::get<OBJECT>(this->data);
            return nestedObj.at(key);
        }
        OBJECTStruct& operator[](size_t index) {
            if (!isArray()) {
                data = ARRAY{};
            }
            ARRAY& arr = std::get<ARRAY>(this->data);
            if (index >= arr.size()) {
                arr.resize(index + 1);
            }
            return arr[index];
        }
        const OBJECTStruct& operator[](size_t index) const {
            if (!isArray()) {
                throw std::runtime_error("Current OBJECTStruct is not an ARRAY type");
            }
            const ARRAY& arr = std::get<ARRAY>(this->data);
            if (index >= arr.size()) {
                throw std::out_of_range("Array index out of bounds");
            }
            return arr[index];
        }
        OBJECT* operator->() {
            if (!isObject()) {
                data = OBJECT{};
            }
            return &std::get<OBJECT>(this->data);
        }
        const OBJECT* operator->() const {
            if (!isObject()) {
                throw std::runtime_error("Current OBJECTStruct is not an OBJECT type");
            }
            return &std::get<OBJECT>(this->data);
        }
        template <typename T>
        T get(T default_val = T{}) const {
            if (std::holds_alternative<T>(data)) {
                return std::get<T>(data);
            }
            return default_val;
        }
        template <>
        std::string get<std::string>(std::string default_val) const {
            if (std::holds_alternative<std::wstring>(data)) {
                const std::wstring& wstr = std::get<std::wstring>(data);
                return wstringToString(wstr);
            }
            return default_val;
        }
        size_t size() const {
            if (isArray()) {
                return std::get<ARRAY>(data).size();
            }
            else if (isObject()) {
                return std::get<OBJECT>(data).size();
            }
            throw std::runtime_error("Current OBJECTStruct is not an ARRAY or OBJECT type");
        }
    };

    typedef std::function<OBJECTStruct(std::wstring, OBJECTStruct)> JSONPARSEREVIVER;
    struct JSONStruct {

        static std::wstring stringify(OBJECT object,
            std::variant<std::monostate, std::vector<std::wstring>, JSONPARSEREVIVER> replacer = std::monostate(),
            std::variant<std::monostate, int, std::wstring> space = std::monostate()) {

            std::function<std::wstring(const OBJECTStruct&, int)> stringifyValue = [&](const OBJECTStruct& val, int level) -> std::wstring {
                std::wstring result;
                std::visit([&](auto&& arg) {
                    using T = std::decay_t<decltype(arg)>;

                    if constexpr (std::is_same_v<T, std::wstring>) {
                        std::wstring e; e.reserve(arg.length() * 2);
                        for (wchar_t c : arg) {
                            if (c == L'"')e += L"\\\"";
                            else if (c == L'\\')e += L"\\\\";
                            else if (c == L'\b')e += L"\\b";
                            else if (c == L'\f')e += L"\\f";
                            else if (c == L'\n')e += L"\\n";
                            else if (c == L'\r')e += L"\\r";
                            else if (c == L'\t')e += L"\\t";
                            else if (c >= 0x00 && c <= 0x1F) {
                                wchar_t b[7] = { 0 };
                                swprintf_s(b, L"\\u%04X", (unsigned int)c);
                                e += b;
                            }
                            else e += c;
                        }
                        result = L"\"" + e + L"\"";
                    }
                    else if constexpr (std::is_same_v<T, bool>) {
                        result = arg ? L"true" : L"false";
                    }
                    else if constexpr (std::is_same_v<T, std::nullptr_t> || std::is_same_v<T, std::monostate>) {
                        result = L"null";
                    }
                    else if constexpr (std::is_same_v<T, int>) {
                        wchar_t b[32] = { 0 };
                        swprintf_s(b, L"%d", arg);
                        result = b;
                    }
                    else if constexpr (std::is_same_v<T, long>) {
                        wchar_t b[32] = { 0 };
                        swprintf_s(b, L"%ld", arg);
                        result = b;
                    }
                    else if constexpr (std::is_same_v<T, long long>) {
                        wchar_t b[64] = { 0 };
                        swprintf_s(b, L"%lld", arg);
                        result = b;
                    }
                    else if constexpr (std::is_same_v<T, unsigned int>) {
                        wchar_t b[32] = { 0 };
                        swprintf_s(b, L"%u", arg);
                        result = b;
                    }
                    else if constexpr (std::is_same_v<T, unsigned long>) {
                        wchar_t b[32] = { 0 };
                        swprintf_s(b, L"%lu", arg);
                        result = b;
                    }
                    else if constexpr (std::is_same_v<T, unsigned long long>) {
                        wchar_t b[64] = { 0 };
                        swprintf_s(b, L"%llu", arg);
                        result = b;
                    }
                    else if constexpr (std::is_same_v<T, double>) {
                        if (std::isnan(arg) || std::isinf(arg)) {
                            result = L"null";
                        }
                        else {
                            wchar_t b[128] = { 0 };
                            swprintf_s(b, L"%.15g", arg);
                            result = b;
                        }
                    }
                    else if constexpr (std::is_same_v<T, OBJECT>) {
                        std::wstring indent, indentNext;
                        bool hasIndent = false;
                        if (std::holds_alternative<int>(space)) {
                            int s = std::min(std::get<int>(space), 10);
                            indent = std::wstring((size_t)s * level, L' ');
                            indentNext = std::wstring((size_t)s * (level + 1), L' ');
                            hasIndent = s > 0;
                        }
                        else if (std::holds_alternative<std::wstring>(space)) {
                            std::wstring ss = std::get<std::wstring>(space).substr(0, 10);
                            indent = std::wstring(level, ss[0]);
                            indentNext = std::wstring(level + 1, ss[0]);
                            hasIndent = !ss.empty();
                        }

                        result += L"{";
                        bool firstItem = true;
                        std::vector<std::wstring> items;

                        for (const auto& p : arg) {
                            OBJECTStruct fl = p.second;
                            if (std::holds_alternative<std::vector<std::wstring>>(replacer)) {
                                const auto& ks = std::get<std::vector<std::wstring>>(replacer);
                                if (std::find(ks.begin(), ks.end(), p.first) == ks.end()) {
                                    fl = OBJECTStruct{ nullptr };
                                }
                            }
                            else if (std::holds_alternative<JSONPARSEREVIVER>(replacer)) {
                                fl = std::get<JSONPARSEREVIVER>(replacer)(p.first, p.second);
                            }
                            if (std::holds_alternative<std::nullptr_t>(fl.data)) {
                                continue;
                            }

                            std::wstring keyEscaped;
                            keyEscaped.reserve(p.first.length() * 2);
                            for (wchar_t c : p.first) {
                                if (c == L'"') keyEscaped += L"\\\"";
                                else if (c == L'\\') keyEscaped += L"\\\\";
                                else if (c == L'\b') keyEscaped += L"\\b";
                                else if (c == L'\f') keyEscaped += L"\\f";
                                else if (c == L'\n') keyEscaped += L"\\n";
                                else if (c == L'\r') keyEscaped += L"\\r";
                                else if (c == L'\t') keyEscaped += L"\\t";
                                else if (c >= 0x00 && c <= 0x1F) {
                                    wchar_t b[7] = { 0 };
                                    swprintf_s(b, L"\\u%04X", (unsigned int)c);
                                    keyEscaped += b;
                                }
                                else {
                                    keyEscaped += c;
                                }
                            }

                            std::wstring item;
                            if (hasIndent) {
                                item += L"\n" + indentNext;
                            }
                            item += L"\"" + keyEscaped + L"\":";
                            if (hasIndent) item += L" ";
                            item += stringifyValue(fl, level + 1);
                            items.push_back(item);
                            firstItem = false;
                        }

                        if (!items.empty()) {
                            if (hasIndent) {
                                for (size_t i = 0; i < items.size(); i++) {
                                    if (i > 0) {
                                        result += L",";
                                    }
                                    result += items[i];
                                }
                            }
                            else {
                                for (size_t i = 0; i < items.size(); i++) {
                                    if (i > 0) {
                                        result += L", ";
                                    }
                                    result += items[i];
                                }
                            }
                        }

                        if (hasIndent && !items.empty()) {
                            result += L"\n" + indent;
                        }
                        result += L"}";

                        if (level == 0 && hasIndent && !items.empty()) {
                            result += L"\n";
                        }
                    }
                    else if constexpr (std::is_same_v<T, ARRAY>) {
                        std::wstring indent, indentNext;
                        bool hasIndent = false;
                        if (std::holds_alternative<int>(space)) {
                            int s = std::min(std::get<int>(space), 10);
                            indent = std::wstring((size_t)s * level, L' ');
                            indentNext = std::wstring((size_t)s * (level + 1), L' ');
                            hasIndent = s > 0;
                        }
                        else if (std::holds_alternative<std::wstring>(space)) {
                            std::wstring ss = std::get<std::wstring>(space).substr(0, 10);
                            indent = std::wstring(level, ss[0]);
                            indentNext = std::wstring(level + 1, ss[0]);
                            hasIndent = !ss.empty();
                        }

                        result += L"[";
                        std::vector<std::wstring> items;

                        for (size_t i = 0; i < arg.size(); ++i) {
                            const auto& elem = arg[i];
                            OBJECTStruct fl = elem;
                            if (std::holds_alternative<JSONPARSEREVIVER>(replacer)) {
                                fl = std::get<JSONPARSEREVIVER>(replacer)(std::to_wstring(i), elem);
                            }
                            if (std::holds_alternative<std::nullptr_t>(fl.data)) {
                                continue;
                            }

                            std::wstring item;
                            if (hasIndent) {
                                item += L"\n" + indentNext;
                            }
                            item += stringifyValue(fl, level + 1);
                            items.push_back(item);
                        }

                        if (!items.empty()) {
                            if (hasIndent) {
                                for (size_t i = 0; i < items.size(); i++) {
                                    if (i > 0) {
                                        result += L",";
                                    }
                                    result += items[i];
                                }
                                result += L"\n" + indent;
                            }
                            else {
                                for (size_t i = 0; i < items.size(); i++) {
                                    if (i > 0) {
                                        result += L", ";
                                    }
                                    result += items[i];
                                }
                            }
                        }
                        result += L"]";
                    }
                    else {
                        throw std::invalid_argument("Do not know how to serialize a BigInt");
                    }
                    }, val.data);
                return result;
                };

            OBJECTStruct root;
            root.data = std::move(object);
            return stringifyValue(root, 0);
        }
        static OBJECT parse(std::wstring jsonText, JSONPARSEREVIVER reviver = nullptr) {
            size_t pos = 0;
            const wchar_t* ptr = jsonText.c_str();
            size_t len = jsonText.size();

            std::function<OBJECTStruct(std::wstring)> parseValue = [&](std::wstring key) -> OBJECTStruct {
                while (pos < len && ptr[pos] != L'\0' && std::iswspace(ptr[pos])) pos++;
                if (pos >= len || ptr[pos] == L'\0') {
                    throw std::invalid_argument("Unexpected end of JSON input");
                }
                OBJECTStruct res;
                if (ptr[pos] == L'{') {
                    pos++;
                    while (pos < len && ptr[pos] != L'\0' && std::iswspace(ptr[pos])) pos++;
                    OBJECT obj;

                    if (ptr[pos] == L'}') {
                        pos++;
                        res.data = obj;
                    }
                    else {
                        while (true) {
                            while (pos < len && ptr[pos] != L'\0' && std::iswspace(ptr[pos])) pos++;
                            if (ptr[pos] != L'"') {
                                throw std::invalid_argument("Unexpected token in JSON at position " + std::to_string(pos));
                            }

                            pos++;
                            std::wstring sk;
                            while (pos < len && ptr[pos] != L'\0') {
                                if (ptr[pos] == L'"') {
                                    pos++;
                                    break;
                                }
                                if (ptr[pos] == L'\\') {
                                    pos++;
                                    if (pos >= len || ptr[pos] == L'\0') {
                                        throw std::invalid_argument("Unexpected end of JSON input");
                                    }
                                    if (ptr[pos] == L'"') sk += L'"';
                                    else if (ptr[pos] == L'\\') sk += L'\\';
                                    else if (ptr[pos] == L'/') sk += L'/';
                                    else if (ptr[pos] == L'b') sk += L'\b';
                                    else if (ptr[pos] == L'f') sk += L'\f';
                                    else if (ptr[pos] == L'n') sk += L'n';
                                    else if (ptr[pos] == L'r') sk += L'\r';
                                    else if (ptr[pos] == L't') sk += L'\t';
                                    else if (ptr[pos] == L'u') {
                                        pos++;
                                        if (pos + 3 >= len) {
                                            throw std::invalid_argument("Unexpected end of JSON input");
                                        }
                                        wchar_t u[5] = { 0 };
                                        for (int i = 0; i < 4; i++) {
                                            u[i] = ptr[pos + i];
                                            if (!std::iswxdigit(u[i])) {
                                                throw std::invalid_argument("Invalid Unicode escape sequence in JSON at position " + std::to_string(pos + i));
                                            }
                                        }
                                        unsigned int c = std::wcstoul(u, nullptr, 16);
                                        sk += (wchar_t)c;
                                        pos += 4;
                                        continue;
                                    }
                                    else {
                                        throw std::invalid_argument("Invalid escape character in JSON at position " + std::to_string(pos));
                                    }
                                    pos++;
                                }
                                else {
                                    sk += ptr[pos];
                                    pos++;
                                }
                            }

                            while (pos < len && ptr[pos] != L'\0' && std::iswspace(ptr[pos])) pos++;
                            if (ptr[pos] != L':') {
                                throw std::invalid_argument("Expected ':' in JSON at position " + std::to_string(pos));
                            }
                            pos++;
                            OBJECTStruct sv = parseValue(sk);
                            obj[sk] = sv;

                            while (pos < len && ptr[pos] != L'\0' && std::iswspace(ptr[pos])) pos++;
                            if (ptr[pos] == L'}') {
                                pos++;
                                break;
                            }
                            if (ptr[pos] != L',') {
                                throw std::invalid_argument("Expected ',' in JSON at position " + std::to_string(pos));
                            }
                            pos++;
                        }
                        res.data = obj;
                    }
                }
                else if (ptr[pos] == L'[') {
                    pos++;
                    while (pos < len && ptr[pos] != L'\0' && std::iswspace(ptr[pos])) pos++;
                    ARRAY arr;

                    if (ptr[pos] == L']') {
                        pos++;
                        res.data = arr;
                    }
                    else {
                        while (true) {
                            OBJECTStruct elem = parseValue(L"");
                            arr.push_back(elem);

                            while (pos < len && ptr[pos] != L'\0' && std::iswspace(ptr[pos])) pos++;
                            if (ptr[pos] == L']') {
                                pos++;
                                break;
                            }
                            if (ptr[pos] != L',') {
                                throw std::invalid_argument("Expected ',' in JSON at position " + std::to_string(pos));
                            }
                            pos++;
                            while (pos < len && ptr[pos] != L'\0' && std::iswspace(ptr[pos])) pos++;
                        }
                        res.data = arr;
                    }
                }
                else if (ptr[pos] == L'"') {
                    pos++;
                    std::wstring s;
                    while (pos < len && ptr[pos] != L'\0') {
                        if (ptr[pos] == L'"') {
                            pos++;
                            break;
                        }
                        if (ptr[pos] == L'\\') {
                            pos++;
                            if (pos >= len || ptr[pos] == L'\0') {
                                throw std::invalid_argument("Unexpected end of JSON input");
                            }
                            if (ptr[pos] == L'"') s += L'"';
                            else if (ptr[pos] == L'\\') s += L'\\';
                            else if (ptr[pos] == L'/') s += L'/';
                            else if (ptr[pos] == L'b') s += L'\b';
                            else if (ptr[pos] == L'f') s += L'\f';
                            else if (ptr[pos] == L'n') s += L'n';
                            else if (ptr[pos] == L'r') s += L'r';
                            else if (ptr[pos] == L't') s += L't';
                            else if (ptr[pos] == L'u') {
                                pos++;
                                if (pos + 3 >= len) {
                                    throw std::invalid_argument("Unexpected end of JSON input");
                                }
                                wchar_t u[5] = { 0 };
                                for (int i = 0; i < 4; i++) {
                                    u[i] = ptr[pos + i];
                                    if (!std::iswxdigit(u[i])) {
                                        throw std::invalid_argument("Invalid Unicode escape sequence in JSON at position " + std::to_string(pos + i));
                                    }
                                }
                                unsigned int c = std::wcstoul(u, nullptr, 16);
                                s += (wchar_t)c;
                                pos += 4;
                                continue;
                            }
                            else {
                                throw std::invalid_argument("Invalid escape character in JSON at position " + std::to_string(pos));
                            }
                            pos++;
                        }
                        else {
                            s += ptr[pos];
                            pos++;
                        }
                    }
                    res.data = s;
                }
                else if (ptr[pos] == L't') {
                    if (pos + 3 >= len || !(ptr[pos + 1] == L'r' && ptr[pos + 2] == L'u' && ptr[pos + 3] == L'e')) {
                        throw std::invalid_argument("Unexpected token in JSON at position " + std::to_string(pos));
                    }
                    pos += 4;
                    res.data = true;
                }
                else if (ptr[pos] == L'f') {
                    if (pos + 4 >= len || !(ptr[pos + 1] == L'a' && ptr[pos + 2] == L'l' && ptr[pos + 3] == L's' && ptr[pos + 4] == L'e')) {
                        throw std::invalid_argument("Unexpected token in JSON at position " + std::to_string(pos));
                    }
                    pos += 5;
                    res.data = false;
                }
                else if (ptr[pos] == L'n') {
                    if (pos + 3 >= len || !(ptr[pos + 1] == L'u' && ptr[pos + 2] == L'l' && ptr[pos + 3] == L'l')) {
                        throw std::invalid_argument("Unexpected token in JSON at position " + std::to_string(pos));
                    }
                    pos += 4;
                    res.data = nullptr;
                }
                else if (std::iswdigit(ptr[pos]) || ptr[pos] == L'-') {
                    size_t st = pos;
                    if (ptr[pos] == L'-') pos++;
                    while (pos < len && std::iswdigit(ptr[pos])) pos++;
                    bool hasDecimal = false;
                    if (pos < len && ptr[pos] == L'.') {
                        hasDecimal = true;
                        pos++;
                        if (pos >= len || !std::iswdigit(ptr[pos])) {
                            throw std::invalid_argument("Unexpected token in JSON at position " + std::to_string(pos));
                        }
                        while (pos < len && std::iswdigit(ptr[pos])) pos++;
                    }
                    bool hasExponent = false;
                    if (pos < len && (ptr[pos] == L'e' || ptr[pos] == L'E')) {
                        hasExponent = true;
                        pos++;
                        if (pos < len && (ptr[pos] == L'+' || ptr[pos] == L'-')) pos++;
                        if (pos >= len || !std::iswdigit(ptr[pos])) {
                            throw std::invalid_argument("Unexpected token in JSON at position " + std::to_string(pos));
                        }
                        while (pos < len && std::iswdigit(ptr[pos])) pos++;
                    }
                    std::wstring ns(ptr + st, pos - st);
                    if (hasDecimal || hasExponent) {
                        double v = std::stod(wstringToString(ns));
                        res.data = v;
                    }
                    else {
                        bool isUnsigned = ns[0] != L'-';
                        unsigned long long ull = std::stoull(wstringToString(ns));
                        long long ll = std::stoll(wstringToString(ns));
                        if (isUnsigned) {
                            if (ull <= std::numeric_limits<unsigned int>::max()) {
                                res.data = (unsigned int)ull;
                            }
                            else if (ull <= std::numeric_limits<unsigned long>::max()) {
                                res.data = (unsigned long)ull;
                            }
                            else {
                                res.data = ull;
                            }
                        }
                        else {
                            if (ll >= std::numeric_limits<int>::min() && ll <= std::numeric_limits<int>::max()) {
                                res.data = (int)ll;
                            }
                            else if (ll >= std::numeric_limits<long>::min() && ll <= std::numeric_limits<long>::max()) {
                                res.data = (long)ll;
                            }
                            else {
                                res.data = ll;
                            }
                        }
                    }
                }
                else {
                    throw std::invalid_argument("Unexpected token " + wstringToString(std::wstring(1, ptr[pos])) + " in JSON at position " + std::to_string(pos));
                }

                if (reviver) {
                    res = reviver(key, res);
                }
                return res;
                };

            while (pos < len && ptr[pos] != L'\0' && std::iswspace(ptr[pos])) pos++;
            if (pos >= len || (ptr[pos] != L'{' && ptr[pos] != L'[')) {
                throw std::invalid_argument("Unexpected token in JSON at position " + std::to_string(pos));
            }

            OBJECTStruct root = parseValue(L"");
            if (root.isArray()) {
                OBJECT wrapper;
                wrapper[L""] = root;
                return wrapper;
            }
            if (!std::holds_alternative<OBJECT>(root.data)) {
                throw std::invalid_argument("Unexpected token in JSON at position 0");
            }
            return std::get<OBJECT>(root.data);
        }

    };
    JSONStruct JSON;


#undef ERROR
    typedef struct BLOB {
        std::string mimeType = "application/octet-stream";
        BYTEBUFFER data = {};
    } *BLOB_PTR;
    std::unordered_map<std::wstring, BLOB> URLDataList = {};
    using StdExceptionVariant = std::variant<
        std::exception, std::logic_error, std::domain_error, std::invalid_argument,
        std::length_error, std::out_of_range, std::runtime_error, std::range_error,
        std::overflow_error, std::underflow_error, std::bad_alloc, std::bad_cast,
        std::bad_typeid, std::bad_exception
    >;
    struct ERROR {
        std::wstring message = L"";
        std::wstring name = L"";
        StdExceptionVariant cause;
    };
    struct URLINFO {
        std::wstring href = L"";  // 完整 URL
        std::wstring protocol = L"";  // 协议，例如 "http:"、"https:"
        std::wstring host = L"";  // 主机名 + 端口（非默认端口时）
        std::wstring hostname = L"";  // 主机名（域名或IP）
        int port = -1;   // 端口号（-1 表示未指定）
        std::wstring path = L"";
        std::wstring pathname = L"";  // 路径部分，例如 "/index.html"
        std::wstring search = L"";  // 查询字符串，例如 "?id=123"
        std::wstring hash = L"";  // 锚点部分，例如 "#section"
        std::wstring origin = L"";  // 协议 + 主机 + 端口，例如 "https://example.com:8080"
        std::wstring username = L"";  // 用户名（如果 URL 中包含）
        std::wstring password = L"";  // 密码（如果 URL 中包含）
    };
    URLINFO GetURLINFOFromUrl(std::wstring url) noexcept {
        URLINFO info;
        if (url.empty()) return info;
        const wchar_t* p = url.c_str(), * end = p + url.size();
        const wchar_t* blob_protocol = L"blob:";
        const size_t blob_protocol_len = wcslen(blob_protocol);
        if (wcsncmp(p, blob_protocol, blob_protocol_len) == 0) {
            info.protocol = blob_protocol; p += blob_protocol_len;
            const wchar_t* host_end = wcschr(p, L'/');
            if (host_end) {
                info.hostname.assign(p, host_end - p); info.host = info.hostname;
                info.path.assign(host_end, end - host_end); info.pathname = info.path;
                if (info.path.empty()) { info.path = L"/"; info.pathname = L"/"; }
                p = host_end;
            }
            else {
                info.hostname.assign(p, end - p); info.host = info.hostname;
                info.path = L"/"; info.pathname = L"/";
            }
            info.origin = info.protocol + info.hostname; info.href = std::move(url);
            return info;
        }
        const wchar_t* protocol_end = std::wcsstr(p, L"://");
        if (protocol_end) {
            info.protocol.assign(p, protocol_end - p + 1); p = protocol_end + 3;
        }
        else { info.href = std::move(url); return info; }
        const wchar_t* at_sign = std::wcschr(p, L'@');
        if (at_sign) {
            const wchar_t* colon = std::wcschr(p, L':');
            if (colon && colon < at_sign) {
                info.username.assign(p, colon - p);
                info.password.assign(colon + 1, at_sign - (colon + 1));
            }
            else info.username.assign(p, at_sign - p);
            p = at_sign + 1;
        }
        const wchar_t* host_start = p;
        const wchar_t* host_end = std::wcsstr(p, L"/");
        if (!host_end) host_end = end;
        const wchar_t* port_start = std::wcschr(p, L':');
        if (port_start && port_start < host_end) {
            info.hostname.assign(p, port_start - p);
            try { info.port = std::stoi(std::wstring(port_start + 1, host_end - (port_start + 1))); }
            catch (...) { info.port = -1; }
        }
        else {
            info.hostname.assign(p, host_end - p);
            if (info.protocol == L"http:") info.port = 80;
            else if (info.protocol == L"https:") info.port = 443;
            else if (info.protocol == L"ftp:") info.port = 21;
        }
        if (info.port != -1) {
            bool is_default = (info.protocol == L"http:" && info.port == 80) || (info.protocol == L"https:" && info.port == 443) || (info.protocol == L"ftp:" && info.port == 21);
            info.host = is_default ? info.hostname : info.hostname + L":" + std::to_wstring(info.port);
        }
        else info.host = info.hostname;
        info.origin = info.protocol + L"//" + info.host;
        if (host_end < end) {
            const wchar_t* path_end = std::wcsstr(host_end, L"?");
            if (!path_end) path_end = std::wcsstr(host_end, L"#");
            if (!path_end) path_end = end;
            info.pathname.assign(host_end, path_end - host_end);
            if (info.pathname.empty()) info.pathname = L"/";
            info.path.assign(host_end, end - host_end);
            if (info.path.empty()) info.path = L"/";
        }
        else { info.path = L"/"; info.pathname = L"/"; }
        const wchar_t* search_start = std::wcsstr(host_end, L"?");
        if (search_start) {
            const wchar_t* search_end = std::wcsstr(search_start, L"#");
            if (!search_end) search_end = end;
            info.search.assign(search_start, search_end - search_start);
        }
        const wchar_t* hash_start = std::wcsstr(host_end, L"#");
        if (hash_start) info.hash.assign(hash_start, end - hash_start);
        info.href = std::move(url);
        return info;
    }
    std::wstring GetRandomBlobURL() {
        static std::mt19937 g_RandomEngine([]() {
            unsigned int seed = static_cast<unsigned int>(
                std::chrono::system_clock::now().time_since_epoch().count()
                );
            return std::mt19937(seed);
            }());

        const std::wstring blobPrefix = L"blob:null/";
        std::wstring blobURL;
        const wchar_t hexChars[] = L"0123456789abcdef";
        const wchar_t variantChars[] = L"89ab";
        std::uniform_int_distribution<int> hexDist(0, 15);
        std::uniform_int_distribution<int> variantDist(0, 3);

        do {
            std::wstring uuid;
            uuid.reserve(36);

            for (size_t i = 0; i < 8; ++i) {
                uuid += hexChars[hexDist(g_RandomEngine)];
            }
            uuid += L"-";

            for (size_t i = 0; i < 4; ++i) {
                uuid += hexChars[hexDist(g_RandomEngine)];
            }
            uuid += L"-";

            uuid += L"4";
            for (size_t i = 0; i < 3; ++i) {
                uuid += hexChars[hexDist(g_RandomEngine)];
            }
            uuid += L"-";

            uuid += variantChars[variantDist(g_RandomEngine)];
            for (size_t i = 0; i < 3; ++i) {
                uuid += hexChars[hexDist(g_RandomEngine)];
            }
            uuid += L"-";

            for (size_t i = 0; i < 12; ++i) {
                uuid += hexChars[hexDist(g_RandomEngine)];
            }

            blobURL = blobPrefix + uuid;

        } while (URLDataList.count(blobURL) > 0);

        return blobURL;
    }
    std::runtime_error GetError(ERROR error) {
        std::wstring fullErrorMsgW;
        if (!error.name.empty()) {
            fullErrorMsgW = error.name + L": " + error.message;
        }
        else {
            fullErrorMsgW = error.message.empty() ? L"Unknown error" : error.message;
        }
        std::string fullErrorMsg = wstringToString(fullErrorMsgW);
        return std::runtime_error(fullErrorMsg);
    }

    class URLInstanceClass;
    typedef URLInstanceClass URL_T, * URL_T_PTR;

    class URLInstanceClass {
    public:
        URLInstanceClass() {
        };
        URLInstanceClass(const std::wstring url) {
            ProcessURL(url);
            UpdateInfo();
        };
        URLInstanceClass(const std::wstring path, const std::wstring baseUrl) {
            ProcessURL(baseUrl + path);
            UpdateInfo();
        };

        ~URLInstanceClass() = default;

        std::wstring href = L"";  // 完整 URL
        std::wstring protocol = L"";  // 协议，例如 "http:"、"https:"
        std::wstring host = L"";  // 主机名 + 端口（非默认端口时）
        std::wstring hostname = L"";  // 主机名（域名或IP）
        int port = -1;   // 端口号（-1 表示未指定）
        std::wstring path = L"";
        std::wstring pathname = L"";  // 路径部分，例如 "/index.html"
        std::wstring search = L"";  // 查询字符串，例如 "?id=123"
        std::wstring hash = L"";  // 锚点部分，例如 "#section"
        std::wstring origin = L"";  // 协议 + 主机 + 端口，例如 "https://example.com:8080"
        std::wstring username = L"";  // 用户名（如果 URL 中包含）
        std::wstring password = L"";  // 密码（如果 URL 中包含）

    private:
        void UpdateInfo() {
            href = info.href;
            protocol = info.protocol;
            host = info.host;
            hostname = info.hostname;
            port = info.port;
            path = info.path;
            pathname = info.pathname;
            search = info.search;
            hash = info.hash;
            origin = info.origin;
            username = info.username;
            password = info.password;
        };

        void ProcessURL(const std::wstring url) {
            URLINFO urlInfo = GetURLINFOFromUrl(url);

            bool isUrlValid = !urlInfo.protocol.empty() &&
                urlInfo.protocol.back() == L':' &&
                !urlInfo.hostname.empty() &&
                (urlInfo.port == -1 || (urlInfo.port >= 1 && urlInfo.port <= 65535));

            if (!isUrlValid) {
                ERROR error = {};
                error.name = L"TypeError";
                std::wstring errorDetails;
                if (urlInfo.protocol.empty()) {
                    errorDetails += L"URL协议为空（必须包含http:/https:/等带冒号的协议）；";
                }
                else if (urlInfo.protocol.back() != L':') {
                    errorDetails += L"URL协议格式无效 - 协议必须以冒号结尾（当前协议：" + urlInfo.protocol + L"）；";
                }
                if (urlInfo.hostname.empty()) {
                    errorDetails += L"URL主机名为空（必须包含域名/IP地址）；";
                }
                if (urlInfo.port != -1 && (urlInfo.port < 1 || urlInfo.port > 65535)) {
                    errorDetails += L"URL端口号非法 - 端口必须在1-65535范围内（当前端口：" + std::to_wstring(urlInfo.port) + L"）；";
                }
                error.message = L"Failed to construct 'URL': Invalid URL. " + errorDetails + L" 原始URL：" + url;
                throw GetError(error);
            }
            info = urlInfo;
        };

        URLINFO info = {};
    };

    class URLStaticClass {
    public:
        URLStaticClass(const URLStaticClass&) = delete;
        URLStaticClass& operator=(const URLStaticClass&) = delete;

        URLStaticClass() = default;
        ~URLStaticClass() = default;

        static std::wstring createObjectURL(const BLOB_PTR data) {
            std::wstring blobURL = GetRandomBlobURL();
            URLDataList[blobURL] = *data;
            return blobURL;
        }
        static bool revokeObjectURL(const std::wstring& url) {
            return URLDataList.count(url) && URLDataList.erase(url);
        }
    };

    URLStaticClass URL;

    OBJECT configObject = {};

    GMMT extensionList = {};
    HINSTANCE hInst = NULL;
    ordered_map<std::wstring, std::wstring> commandArgList = {};
    std::wstring commandStartFilePath = L"";
    std::wstring errorOutput = L"";
    GMMT outputTemp = {};
    bool isPaused = false;
    /////
    bool isKeepWTMode = false;
    /////
    bool isStartByFastCgi = false;

    double timeout = 0.0;
    bool isFlushNamedPipe = false;
    bool isOutputError = false;
    bool isStrictStandard = false;
    bool isModernMode = false;

    bool isShowReturnValue = false;
    bool isShowReturnDetail = false;
    bool isAlwaysPauseWhenQuit = false;

    bool isShowConsole = false;
    bool isTotalOutput = false;

    bool isModuleMode = false;

    void updateConfig() {

        try {
            isModuleMode = configObject[L"general"][L"isModuleMode"].get<bool>();
        }
        catch (...) {}

        if (!isStartByFastCgi) {
            try {
                isShowReturnValue = configObject[L"shell"][L"isShowReturnValue"].get<bool>();
                isShowReturnDetail = configObject[L"shell"][L"isShowReturnDetail"].get<bool>();
                isAlwaysPauseWhenQuit = configObject[L"shell"][L"isAlwaysPauseWhenQuit"].get<bool>();

                isShowConsole = configObject[L"file"][L"isShowConsole"].get<bool>();
                isTotalOutput = configObject[L"file"][L"isTotalOutput"].get<bool>();
            }
            catch (...) {}

        }
        else {

            try {
                timeout = configObject[L"fastcgi"][L"timeout"].get<double>();
                isFlushNamedPipe = configObject[L"fastcgi"][L"isFlushNamedPipe"].get<bool>();
                isOutputError = configObject[L"fastcgi"][L"isOutputError"].get<bool>();
                isStrictStandard = configObject[L"fastcgi"][L"isStrictStandard"].get<bool>();
                isModernMode = configObject[L"fastcgi"][L"isModernMode"].get<bool>();
            }
            catch (...) {}
        }

    }

    template<typename T, typename... Args>
    T* NewInstance(Args&&... args) {
        T* temp = nullptr;
        try {
            temp = new T(std::forward<Args>(args)...);
        }
        catch (...) {}
        return temp;
    }

    template <typename T>
    bool RemoveSameInVector(std::vector<T*>& vec) {
        // 记录已出现的指针值，用于快速判断重复
        std::unordered_set<T*> seen;
        // 标记是否有元素被移除
        bool has_removed = false;

        // 使用 erase-remove 惯用法，原地移除重复元素
        auto new_end = std::remove_if(
            vec.begin(), vec.end(),
            [&seen, &has_removed](T* ptr) {
                // 如果指针已存在，标记为重复并返回true（会被移除）
                if (seen.count(ptr)) {
                    has_removed = true;
                    return true;
                }
                // 否则将指针加入集合，返回false（保留）
                seen.insert(ptr);
                return false;
            }
        );

        // 清理向量中移除后的多余空间
        vec.erase(new_end, vec.end());

        return has_removed;
    }

    template <typename T>
    bool RemoveSameInVector(std::vector<T>& vec) {
        std::unordered_set<T> seen;
        bool has_removed = false;
        auto new_end = std::remove_if(
            vec.begin(), vec.end(),
            [&seen, &has_removed](const T& value) {
                if (seen.count(value)) {
                    has_removed = true;
                    return true;
                }
                seen.insert(value);
                return false;
            }
        );

        vec.erase(new_end, vec.end());

        return has_removed;
    }

    GMT GetCodeColor(std::wstring code) {
        GMT colorMap;
        if (code.empty()) return colorMap;
        const std::wregex specialValueRegex(
            LR"(\b(null|NaN|undefined)\b)",
            std::regex_constants::optimize | std::regex_constants::icase
        );
        const std::wregex funcRegex(
            LR"((function\s+(\w+)\s*\([\s\S]*?\)\s*\{[\s\S]*?\[native code\][\s\S]*?\}))",
            std::regex_constants::optimize
        );

        std::wsmatch match;
        std::wstring remainingCode = code;
        while (std::regex_search(remainingCode, match, specialValueRegex)) {
            if (match.position() > 0) {
                std::wstring unMatched = remainingCode.substr(0, match.position());
                colorMap[unMatched] = L"DarkGray";
            }
            std::wstring specialValue = match[1].str();
            colorMap[specialValue] = L"DarkGray";
            size_t matchEndPos = match.position() + match.length();
            remainingCode = remainingCode.substr(matchEndPos);
            if (remainingCode.empty()) break;
        }

        std::wsmatch funcMatch;
        while (std::regex_search(remainingCode, funcMatch, funcRegex)) {
            if (funcMatch.position() > 0) {
                std::wstring unMatched = remainingCode.substr(0, funcMatch.position());
                colorMap[unMatched] = L"Gray";
            }

            std::wstring fullFuncBlock = funcMatch[1].str();
            std::wstring funcName = funcMatch[2].str();
            std::wstring colorType = L"Function";

            if (funcName == L"Array" || funcName == L"Object" || funcName == L"String" ||
                funcName == L"Number" || funcName == L"Boolean" || funcName == L"Date" ||
                funcName == L"RegExp" || funcName == L"Map" || funcName == L"Set") {
                colorType = L"BuiltInObject";
            }
            else if (funcName == L"Promise") {
                colorType = L"Promise";
            }
            else if (funcName == L"Symbol") {
                colorType = L"Symbol";
            }
            else if (funcName == L"Error" || funcName == L"TypeError" ||
                funcName == L"RangeError" || funcName == L"SyntaxError") {
                colorType = L"Error";
            }
            else if (funcName == L"parseInt" || funcName == L"parseFloat" || funcName == L"eval" ||
                funcName == L"decodeURI" || funcName == L"encodeURI" || funcName == L"isNaN" ||
                funcName == L"isFinite") {
                colorType = L"BuiltInFunction";
            }
            else if (funcName == L"JSON" || funcName == L"console") {
                colorType = L"BuiltInObject";
            }

            colorMap[fullFuncBlock] = colorType;

            size_t matchEndPos = funcMatch.position() + funcMatch.length();
            remainingCode = remainingCode.substr(matchEndPos);
            if (remainingCode.empty()) break;
        }

        if (!remainingCode.empty()) {
            colorMap[remainingCode] = L"DarkGray";
        }

        return colorMap;
    }

    GMT GetCommandArgList() {
        GMT arg_map;
        int argc = 0;
        wchar_t** argv = CommandLineToArgvW(GetCommandLineW(), &argc);

        if (!argv || argc <= 1) {
            if (argv) LocalFree(argv);
            return arg_map;
        }

        for (int i = 1; i < argc; ++i) {
            const wchar_t* arg_ptr = argv[i];
            if (!arg_ptr || !*arg_ptr) continue;

            if (arg_ptr[0] != L'-') {
                continue;
            }

            size_t key_start = 0;
            if (arg_ptr[0] == L'-') {
                if (arg_ptr[1] == L'-') key_start = 2;
                else key_start = 1;
            }

            const wchar_t* kv_ptr = arg_ptr + key_start;
            if (!kv_ptr || !*kv_ptr) continue;

            const wchar_t* equal_ptr = wcschr(kv_ptr, L'=');
            std::wstring key, value;
            if (equal_ptr) {
                key = std::wstring(kv_ptr, equal_ptr - kv_ptr);
                value = std::wstring(equal_ptr + 1);
            }
            else {
                key = kv_ptr;
                value = L"";
            }

            if (!key.empty()) arg_map.insert({ key, value });
        }

        LocalFree(argv);
        return arg_map;
    }

    std::wstring GetStartFilePath() {
        int argc = 0;
        std::wstring file_path;
        wchar_t** argv = CommandLineToArgvW(GetCommandLineW(), &argc);

        if (!argv || argc <= 1) {
            if (argv) LocalFree(argv);
            return L"";
        }

        for (int i = 1; i < argc; ++i) {
            const wchar_t* arg_ptr = argv[i];
            if (!arg_ptr || !*arg_ptr) continue;

            if (!(arg_ptr[0] == L'-' && wcslen(arg_ptr) > 1)) {
                file_path = arg_ptr;
                break;
            }
        }

        LocalFree(argv);
        return file_path;
    }

    bool ClearOutput();

    void AdvSleep(double timeout);

    int CreateConsole(std::wstring title = L"console") {
        isConsoleEnv = true;

        const wchar_t* szWTRegPath = L"Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\wt.exe";
        HKEY hKey = nullptr;
        LONG lResult = RegOpenKeyExW(
            HKEY_CURRENT_USER,
            szWTRegPath,
            0,
            KEY_READ | KEY_WOW64_64KEY,
            &hKey
        );
        if (hKey != nullptr) {
            RegCloseKey(hKey);
        }
        if (!isKeepWTMode) isWTConsole = lResult == ERROR_SUCCESS;

        BOOL bAttachSuccess = AttachConsole(ATTACH_PARENT_PROCESS);
        if (bAttachSuccess) {

            wchar_t* szCmdLine = GetCommandLineW();
            if (wcsstr(szCmdLine, L"--restarted") == nullptr) {
                std::wstring szCmd = L"cmd.exe /c \"";
                szCmd += apppath(-1);
                szCmd += L"\" --restarted";
                _wsystem(szCmd.c_str());
                return -1;
            }

            SetConsoleTitleW(title.c_str());
            FILE* fp = nullptr;
            freopen_s(&fp, "CONOUT$", "w", stdout);
            freopen_s(&fp, "CONIN$", "r", stdin);

            HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
            SetConsoleMode(hIn, ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING);

            HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
            DWORD outMode = 0;
            GetConsoleMode(hOut, &outMode);
            SetConsoleMode(hOut, outMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);

            setlocale(LC_ALL, "");
            std::ios::sync_with_stdio(true);
            std::wcout.imbue(std::locale(""));
            std::wcin.imbue(std::locale(""));
            console = GetConsoleWindow();
            return 2;
        }

        if (isWTConsole) {
            STARTUPINFOW si = { 0 };
            PROCESS_INFORMATION pi = { 0 };
            si.cb = sizeof(STARTUPINFOW);
            SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), nullptr, FALSE };
            std::wstring szCmdBase = L"cmd.exe /q /d /k \"@echo. &pause>nul\"";
            wchar_t* szCmd = new wchar_t[szCmdBase.length() + 1];
            wcscpy_s(szCmd, szCmdBase.length() + 1, szCmdBase.c_str());
            if (!CreateProcessW(
                nullptr,
                szCmd,
                &sa,
                &sa,
                FALSE,
                CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT | HIGH_PRIORITY_CLASS,
                nullptr,
                nullptr,
                &si,
                &pi
            )) {
                delete[] szCmd;
                if (!AllocConsole()) return false;
                SetConsoleTitleW(title.c_str());
                console = GetConsoleWindow();
            }
            else {
                bool bReady = false;
                auto startTime = std::chrono::steady_clock::now();
                int detectInterval = 1;
                const int TOTAL_WAIT_MS = 60000;
                const int HIGH_FREQ_DURATION = 30000;

                while (!bReady) {
                    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() - startTime).count();
                    if (elapsed >= TOTAL_WAIT_MS) break;
                    if (elapsed > HIGH_FREQ_DURATION) detectInterval = 5;
                    if (AttachConsole(pi.dwProcessId)) {
                        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
                        if (hOut != INVALID_HANDLE_VALUE) {
                            CHAR buffer[64] = { 0 };
                            DWORD dwRead = 0;
                            if (ReadConsoleOutputCharacterA(hOut, buffer, 63, { 0,0 }, &dwRead)) {
                                if (strstr(buffer, " ")) {
                                    system("cls");
                                    bReady = true;
                                }
                            }
                        }
                        FreeConsole();
                    }

                    AdvSleep(detectInterval);
                }

                if (AttachConsole(pi.dwProcessId)) {
                    SetConsoleTitleW(title.c_str());
                    TerminateProcess(pi.hProcess, 0);
                    console = GetConsoleWindow();
                }
                else {
                    TerminateProcess(pi.hProcess, 0);
                    AllocConsole();
                    SetConsoleTitleW(title.c_str());
                    console = GetConsoleWindow();
                }

                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
                delete[] szCmd;
            }
        }
        else {
            if (!AllocConsole()) return false;
            SetConsoleTitleW(title.c_str());
            console = GetConsoleWindow();
        }

        FILE* fp = nullptr;
        freopen_s(&fp, "CONOUT$", "w", stdout);
        freopen_s(&fp, "CONIN$", "r", stdin);

        HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
        SetConsoleMode(hIn, ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING);

        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD outMode = 0;
        GetConsoleMode(hOut, &outMode);
        SetConsoleMode(hOut, outMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);

        setlocale(LC_ALL, "");
        std::ios::sync_with_stdio(true);
        std::wcout.imbue(std::locale(""));
        std::wcin.imbue(std::locale(""));
        console = GetConsoleWindow();
        ClearOutput();
        return 1;
    }

    bool CloseConsole() {

        FILE* fp = nullptr;
        freopen_s(&fp, "NUL", "w", stdout);
        freopen_s(&fp, "NUL", "r", stdin);
        std::ios::sync_with_stdio(false);

        if (console != NULL) {
            ShowWindow(console, SW_HIDE);
            DestroyWindow(console);
            console = NULL;
        }

        FreeConsole();

        isConsoleEnv = false;
        if (!isKeepWTMode) isWTConsole = false;

        HWND checkConsole = GetConsoleWindow();
        if (checkConsole != NULL) {
            SendMessage(checkConsole, WM_CLOSE, 0, 0);
        }

        return true;
    }

    std::wstring CreateInput() {
        if (!isConsoleEnv) return L"";
        HANDLE hStdIn = GetStdHandle(STD_INPUT_HANDLE);
        HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD dwOriginalInMode = 0;
        GetConsoleMode(hStdIn, &dwOriginalInMode);
        SetConsoleMode(hStdIn, ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT);
        std::wstring totalInput;
        const DWORD BUFFER_SIZE = 1024;

        while (true) {
            if (isQuit.load(std::memory_order_acquire)) {
                break;
            }

            std::wstring currentLine;
            WCHAR buffer[BUFFER_SIZE] = { 0 };
            DWORD dwRead = 0;

            DWORD dwAvail = 0;
            if (!GetNumberOfConsoleInputEvents(hStdIn, &dwAvail)) {
                break;
            }
            if (dwAvail == 0) {
                continue; // 无输入直接循环，无Sleep，无延迟
            }

            ZeroMemory(buffer, sizeof(buffer));
            if (!ReadConsoleW(hStdIn, buffer, BUFFER_SIZE - 1, &dwRead, nullptr)) {
                break;
            }
            currentLine.append(buffer, dwRead);

            if (isQuit.load(std::memory_order_acquire)) {
                break;
            }

            if (currentLine.find(L'\r') != std::wstring::npos || currentLine.find(L'\n') != std::wstring::npos) {
                if (((GetKeyState(VK_SHIFT) & 0x8000) == 0)) {
                    size_t lastPos = currentLine.find_last_of(L"\r\n");
                    while (lastPos != std::wstring::npos) {
                        currentLine.erase(lastPos, 1);
                        lastPos = currentLine.find_last_of(L"\r\n");
                    }
                    totalInput += currentLine;
                    break;
                }
                else {
                    totalInput += currentLine;
                    continue;
                }
            }
            totalInput += currentLine;
        }

        SetConsoleMode(hStdIn, dwOriginalInMode);

        return isQuit.load(std::memory_order_acquire) ? L"" : totalInput;
    }

    bool CancelInput() {
        // 1. 获取标准输入句柄，句柄无效直接返回失败
        HANDLE hStdIn = GetStdHandle(STD_INPUT_HANDLE);
        if (hStdIn == INVALID_HANDLE_VALUE) {
            return false;
        }

        // 2. 保存原始控制台输入模式，避免污染环境
        DWORD dwOriginalInMode = 0;
        if (!GetConsoleMode(hStdIn, &dwOriginalInMode)) {
            return false;
        }

        // 3. 临时设置基础输入模式，确保注入的回车事件能被识别
        if (!SetConsoleMode(hStdIn, ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT)) {
            return false;
        }

        // 4. 注入回车键事件（按下+松开），触发CreateInput的换行逻辑以结束输入
        INPUT_RECORD inputRecords[2] = { 0 };
        DWORD dwWritten = 0;

        // 按下回车键
        inputRecords[0].EventType = KEY_EVENT;
        inputRecords[0].Event.KeyEvent.bKeyDown = TRUE;
        inputRecords[0].Event.KeyEvent.wVirtualKeyCode = VK_RETURN;
        inputRecords[0].Event.KeyEvent.wVirtualScanCode = MapVirtualKeyW(VK_RETURN, MAPVK_VK_TO_VSC);
        inputRecords[0].Event.KeyEvent.uChar.UnicodeChar = L'\r';
        inputRecords[0].Event.KeyEvent.dwControlKeyState = 0;

        // 松开回车键
        inputRecords[1].EventType = KEY_EVENT;
        inputRecords[1].Event.KeyEvent.bKeyDown = FALSE;
        inputRecords[1].Event.KeyEvent.wVirtualKeyCode = VK_RETURN;
        inputRecords[1].Event.KeyEvent.wVirtualScanCode = MapVirtualKeyW(VK_RETURN, MAPVK_VK_TO_VSC);
        inputRecords[1].Event.KeyEvent.uChar.UnicodeChar = L'\r';
        inputRecords[1].Event.KeyEvent.dwControlKeyState = 0;

        // 写入事件到控制台输入流（核心：触发CreateInput退出）
        BOOL bWriteSuccess = WriteConsoleInputW(hStdIn, inputRecords, 2, &dwWritten);

        // 5. 必做：恢复控制台原始输入模式，避免影响后续操作
        SetConsoleMode(hStdIn, dwOriginalInMode);

        // 6. 返回操作结果：事件写入成功则返回true，否则false
        return (bWriteSuccess && dwWritten == 2);
    }

    struct RGBColor {
        int r = 0, g = 0, b = 0;
    };

    WORD ParseColor(const std::wstring& fgColor = L"#cccccc", const std::wstring& bgColor = L"#0c0c0c") {
        auto hex2rgb = [](const std::wstring& hex, bool isBackground = false) -> RGBColor {
            RGBColor rgb;
            // 非法格式直接返回默认值
            if (hex.size() != 7 || hex[0] != L'#') {
                return isBackground ? RGBColor{ 12, 12, 12 } : RGBColor{ 204, 204, 204 };
            }

            wchar_t* endPtr = nullptr;
            // 使用wcstoul（无符号）避免负数解析问题，增加空指针校验
            unsigned long rUL = std::wcstoul(hex.substr(1, 2).c_str(), &endPtr, 16);
            if (endPtr == hex.substr(1, 2).c_str()) return isBackground ? RGBColor{ 12,12,12 } : RGBColor{ 204,204,204 };

            unsigned long gUL = std::wcstoul(hex.substr(3, 2).c_str(), &endPtr, 16);
            if (endPtr == hex.substr(3, 2).c_str()) return isBackground ? RGBColor{ 12,12,12 } : RGBColor{ 204,204,204 };

            unsigned long bUL = std::wcstoul(hex.substr(5, 2).c_str(), &endPtr, 16);
            if (endPtr == hex.substr(5, 2).c_str()) return isBackground ? RGBColor{ 12,12,12 } : RGBColor{ 204,204,204 };

            // 强制转换为0-255范围（避免溢出）
            rgb.r = static_cast<int>(rUL & 0xFF);
            rgb.g = static_cast<int>(gUL & 0xFF);
            rgb.b = static_cast<int>(bUL & 0xFF);

            return rgb;
            };

        RGBColor fgRgb = hex2rgb(fgColor, false);
        RGBColor bgRgb = hex2rgb(bgColor, true);

        if (isWTConsole) {
            return 0x0F; // 白字黑底（0x0F = 背景0 + 前景15）
        }

        const RGBColor console16[16] = {
            {0,     0,     0},     // 0: 纯黑（Black）
            {0,     0,     128},   // 1: 深蓝（DarkBlue）
            {0,     128,   0},     // 2: 深绿（DarkGreen）
            {0,     128,   128},   // 3: 深青（DarkCyan）
            {128,   0,     0},     // 4: 深红（DarkRed）
            {128,   0,     128},   // 5: 深洋红（DarkMagenta）
            {128,   128,   0},     // 6: 深黄（DarkYellow）
            {192,   192,   192},   // 7: 浅灰（LightGray）
            {128,   128,   128},   // 8: 深灰（DarkGray）
            {0,     0,     255},   // 9: 亮蓝（BrightBlue）- 天蓝色匹配这个
            {0,     255,   0},     // 10: 亮绿（BrightGreen）
            {0,     255,   255},   // 11: 亮青（BrightCyan）
            {255,   0,     0},     // 12: 亮红（BrightRed）- 纯红匹配这个
            {255,   0,     255},   // 13: 亮洋红（BrightMagenta）
            {255,   255,   0},     // 14: 亮黄（BrightYellow）
            {255,   255,   255}    // 15: 纯白（White）
        };

        auto rgbDist = [](const RGBColor& c1, const RGBColor& c2) -> double {
            int dr = c1.r - c2.r;
            int dg = c1.g - c2.g;
            int db = c1.b - c2.b;
            return std::sqrt(0.299 * dr * dr + 0.587 * dg * dg + 0.114 * db * db);
            };

        int fgIdx = 7;
        double minFgDist = 1e9;
        for (int i = 0; i < 16; i++) {
            double dist = rgbDist(fgRgb, console16[i]);
            if (dist < minFgDist) {
                minFgDist = dist;
                fgIdx = i;
            }
        }

        // ========== 修复点2：重构灰度兜底逻辑，仅对“无明显色彩”的颜色生效 ==========
        // 1. 计算颜色的“彩度”（饱和度），判断是否为灰度系颜色
        auto getSaturation = [](const RGBColor& rgb) -> double {
            int maxVal = std::max({ rgb.r, rgb.g, rgb.b });
            int minVal = std::min({ rgb.r, rgb.g, rgb.b });
            if (maxVal == minVal) return 0.0; // 纯灰度
            double l = (maxVal + minVal) / 2.0 / 255.0;
            double s = (maxVal - minVal) / 255.0 / (1 - std::abs(2 * l - 1));
            return s; // 饱和度 0.0-1.0，0=纯灰，1=纯彩
            };

        // 2. 灰度兜底仅在两个条件同时满足时触发：
        //    - 饱和度 < 0.2（几乎无色彩）
        //    - 最小距离 > 100（与16色匹配度极低）
        double saturation = getSaturation(fgRgb);
        const double SATURATION_THRESHOLD = 0.2;
        const double DISTANCE_THRESHOLD = 100.0;

        if (saturation < SATURATION_THRESHOLD && minFgDist > DISTANCE_THRESHOLD) {
            // 仅对低饱和度的灰度色执行兜底
            int gray = (fgRgb.r * 299 + fgRgb.g * 587 + fgRgb.b * 114) / 1000;
            if (gray <= 40) fgIdx = 0;    // 近黑 → 0号
            else if (gray <= 120) fgIdx = 8; // 深灰 → 8号
            else if (gray <= 200) fgIdx = 7; // 浅灰 → 7号
            else fgIdx = 15;              // 近白 → 15号
        }

        int bgIdx = 0;
        double minBgDist = 1e9;
        for (int i = 0; i < 16; i++) {
            double dist = rgbDist(bgRgb, console16[i]);
            if (dist < minBgDist) {
                minBgDist = dist;
                bgIdx = i;
            }
        }

        WORD finalAttr = (static_cast<WORD>(bgIdx) << 4) | static_cast<WORD>(fgIdx);

        if (finalAttr == 0) finalAttr = 0x08;

        return finalAttr;
    }

    uint64_t wcout(const std::string& str) {
        HANDLE hConsoleOut = GetStdHandle(STD_OUTPUT_HANDLE);
        if (hConsoleOut == INVALID_HANDLE_VALUE) {
            return 0;
        }
        DWORD dwMode = 0;
        if (GetConsoleMode(hConsoleOut, &dwMode)) {
            SetConsoleMode(hConsoleOut, dwMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        }
        std::wstring wstr = stringToWstring(str);
        DWORD dwWritten = 0;
        WriteConsoleW(
            hConsoleOut,
            wstr.c_str(),
            static_cast<DWORD>(wstr.length()),
            &dwWritten,
            nullptr
        );
        return dwWritten;
    }
    uint64_t wcout(const std::wstring& wstr) {
        HANDLE hConsoleOut = GetStdHandle(STD_OUTPUT_HANDLE);
        if (hConsoleOut == INVALID_HANDLE_VALUE) {
            return 0;
        }
        DWORD dwMode = 0;
        if (GetConsoleMode(hConsoleOut, &dwMode)) {
            SetConsoleMode(hConsoleOut, dwMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        }
        DWORD dwWritten = 0;
        WriteConsoleW(
            hConsoleOut,
            wstr.c_str(),
            static_cast<DWORD>(wstr.length()),
            &dwWritten,
            nullptr
        );
        return dwWritten;
    }

    void CreateOutput(const std::wstring& outputData, WORD color) {
        if (!isConsoleEnv) {
            outputTemp[outputData] = L"";
            return;
        }
        HANDLE hConsole = CreateFileW(L"CONOUT$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hConsole == INVALID_HANDLE_VALUE) { wcout(outputData); return; }
        CONSOLE_SCREEN_BUFFER_INFO csbi = { 0 };
        WORD originalAttr = 0x0F;
        if (GetConsoleScreenBufferInfo(hConsole, &csbi)) originalAttr = csbi.wAttributes;
        SetConsoleTextAttribute(hConsole, color);
        wcout(outputData);
        SetConsoleTextAttribute(hConsole, originalAttr);
        CloseHandle(hConsole);
    }

    void CreateOutput(const std::wstring& outputData, const std::wstring& fgColor = L"", const std::wstring& bgColor = L"") {
        if (!isConsoleEnv) {
            outputTemp[outputData] = fgColor;
            return;
        }
        if (isWTConsole) {
            RGBColor fg = { 204,204,204 }, bg = { 12,12,12 };
            if (fgColor.size() == 7 && fgColor[0] == L'#') {
                wchar_t* end = nullptr;
                fg.r = static_cast<int>(std::wcstol(fgColor.substr(1, 2).c_str(), &end, 16));
                fg.g = static_cast<int>(std::wcstol(fgColor.substr(3, 2).c_str(), &end, 16));
                fg.b = static_cast<int>(std::wcstol(fgColor.substr(5, 2).c_str(), &end, 16));
            }
            if (bgColor.size() == 7 && bgColor[0] == L'#') {
                wchar_t* end = nullptr;
                bg.r = static_cast<int>(std::wcstol(bgColor.substr(1, 2).c_str(), &end, 16));
                bg.g = static_cast<int>(std::wcstol(bgColor.substr(3, 2).c_str(), &end, 16));
                bg.b = static_cast<int>(std::wcstol(bgColor.substr(5, 2).c_str(), &end, 16));
            }
            std::wstring ansi = L"\x1b[38;2;" + std::to_wstring(fg.r) + L";" + std::to_wstring(fg.g) + L";" + std::to_wstring(fg.b) + L"m"
                + L"\x1b[48;2;" + std::to_wstring(bg.r) + L";" + std::to_wstring(bg.g) + L";" + std::to_wstring(bg.b) + L"m";
            wcout(ansi); wcout(outputData); wcout(L"\x1b[0m");
        }
        else {
            CreateOutput(outputData, ParseColor(fgColor, bgColor));
        }
    }

    void CO(const std::wstring& outputData) {
        CreateOutput(outputData, TextLightColorValue[L"Default"]);
    }

    void OutputStack(std::vector<std::wstring>& Instack) {
        CreateOutput(L"@Stack: \n", GetColorValue(L"DarkGray"));
        ULL stackIndex = 0;
        for (const std::wstring& stack : Instack) {
            stackIndex += 4;
            CreateOutput(std::wstring(static_cast<size_t>(stackIndex), L' '), GetColorValue(L"LightGray"));
            CreateOutput(L"at: ", GetColorValue(L"SlateGray"));
            CreateOutput(stack + L"\n", GetColorValue(L"Info"));
        }
        CreateOutput(L"\n");
    }

    bool ClearOutput() {
        if (!isConsoleEnv) {
            outputTemp.clear();
            return true;
        }
        return system("cls") == 0;
    }

    void BackOutput(ULL size, ULL offset = 0) {
        if (!isConsoleEnv) {
            return;
        }
        // 获取控制台句柄
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        if (hConsole == INVALID_HANDLE_VALUE) return;

        // 获取当前光标位置
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        if (!GetConsoleScreenBufferInfo(hConsole, &csbi)) return;
        COORD pos = csbi.dwCursorPosition;

        // 1. 先向前移动光标 offset 个字符（处理偏移）
        for (ULL i = 0; i < offset; i++) {
            if (pos.X > 0) {
                pos.X--; // 列向前移
            }
            else if (pos.Y > 0) {
                pos.Y--; // 行向上移，列到最后一列
                pos.X = csbi.dwSize.X - 1;
            }
            else {
                break; // 到控制台开头，停止偏移
            }
        }

        // 2. 从当前偏移位置开始，删除 size 个字符（用空格覆盖）
        COORD delPos = pos;
        DWORD written;
        for (ULL i = 0; i < size; i++) {
            // 用空格覆盖字符（简单删除）
            FillConsoleOutputCharacterA(hConsole, ' ', 1, delPos, &written);

            // 向后移动删除位置（避免越界）
            if (delPos.X < csbi.dwSize.X - 1) {
                delPos.X++;
            }
            else if (delPos.Y < csbi.dwSize.Y - 1) {
                delPos.Y++;
                delPos.X = 0;
            }
            else {
                break; // 到控制台末尾，停止删除
            }
        }

        // 3. 将光标移到删除后的起始位置
        SetConsoleCursorPosition(hConsole, pos);
    }

    void UpOutput(ULL size, ULL offset) {
        // 获取控制台句柄
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        if (hConsole == INVALID_HANDLE_VALUE) return;

        // 获取控制台缓冲区信息
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        if (!GetConsoleScreenBufferInfo(hConsole, &csbi)) return;

        // 边界保护：offset 不能超过控制台最大行数
        if (offset >= csbi.dwSize.Y) return;

        // 从 offset 行的第0列开始，删除 size 列的字符
        COORD delPos;
        delPos.Y = (SHORT)offset; // 目标行
        DWORD written;
        for (ULL i = 0; i < size; i++) {
            delPos.X = (SHORT)i; // 第i列
            // 边界保护：列数不超过控制台最大列数
            if (delPos.X >= csbi.dwSize.X) break;

            // 用空格覆盖字符（删除）
            FillConsoleOutputCharacterA(hConsole, ' ', 1, delPos, &written);
        }

        // 光标移到删除区域的起始位置（可选）
        delPos.X = 0;
        SetConsoleCursorPosition(hConsole, delPos);
    }

    bool IsCodeEmpty(const std::wstring& code) {
        // 遍历字符串中的每一个宽字符
        for (wchar_t ch : code) {
            if (!std::iswspace(static_cast<wint_t>(ch))) {
                return false;
            }
        }
        return true;
    }

    std::wstring GetErrorFront(JSContext* jsContext, JSValue exception) {
        if (!jsContext || JS_IsUndefined(exception) || JS_IsNull(exception)) {
            return L"unknown:0:0 SyntaxError: unexpected token in expression: ''";
        }

        std::string coreErr;
        JSValue stackVal = JS_GetPropertyStr(jsContext, exception, "stack");
        if (JS_IsString(stackVal)) {
            const char* stackCStr = JS_ToCString(jsContext, stackVal);
            if (stackCStr && *stackCStr) {
                std::string stackStr = stackCStr;
                // 移除所有空白字符
                stackStr.erase(std::remove_if(stackStr.begin(), stackStr.end(), isspace), stackStr.end());

                const std::string atEvalPrefix = "at<eval>(";
                const std::string atPrefix = "at";

                // 第一步：找最末尾的 at<eval>(
                size_t lastAtEvalPos = stackStr.rfind(atEvalPrefix);
                if (lastAtEvalPos != std::string::npos) {
                    // 处理最后一个 at<eval>(...) 场景
                    // ( 从当前 at<eval>( 位置找第一个 (
                    size_t leftBrace = stackStr.find('(', lastAtEvalPos);
                    // ) 从字符串末尾找第一个 )
                    size_t rightBrace = stackStr.rfind(')');

                    if (leftBrace != std::string::npos && rightBrace != std::string::npos && leftBrace < rightBrace) {
                        coreErr = stackStr.substr(leftBrace + 1, rightBrace - leftBrace - 1);
                    }
                }
                else {
                    // 第二步：如果没有 at<eval>(，找最末尾的 at
                    size_t lastAtPos = stackStr.rfind(atPrefix);
                    if (lastAtPos != std::string::npos) {
                        // 确保找到的 "at" 不是其他字符串的子串（比如 "data" 中的 "at"），这里简单校验：
                        // 1. "at" 是独立的前缀（即前一个字符不存在或不是字母）
                        // 2. 只取最后一个 "at" 之后的所有内容
                        bool isValidAt = (lastAtPos == 0) || (!isalpha(stackStr[lastAtPos - 1]));
                        if (isValidAt) {
                            coreErr = stackStr.substr(lastAtPos + atPrefix.length());
                        }
                    }
                }
            }
            if (stackCStr) JS_FreeCString(jsContext, stackCStr);
        }
        JS_FreeValue(jsContext, stackVal);

        if (coreErr.empty()) {
            coreErr = "unknown:0:0";
        }

        return stringToWstring(coreErr);
    }

    std::vector<std::wstring> GetErrorFrontStack(JSContext* jsContext, JSValue exception) {
        std::vector<std::wstring> resultStack;

        // 入参合法性校验
        if (!jsContext || JS_IsUndefined(exception) || JS_IsNull(exception)) {
            resultStack.push_back(L"unknown:0:0 SyntaxError: unexpected token in expression: ''");
            return resultStack;
        }

        std::string stackStr;
        JSValue stackVal = JS_GetPropertyStr(jsContext, exception, "stack");
        if (JS_IsString(stackVal)) {
            const char* stackCStr = JS_ToCString(jsContext, stackVal);
            if (stackCStr && *stackCStr) {
                // 关键修改1：保留原始空格，不再移除任何空白字符
                stackStr = stackCStr;

                // 关键修改2：以 " at "（前后带空格）作为分隔符，正向拆分（保持原有顺序）
                std::vector<std::string> fragments;
                const std::string delimiter = " at "; // 带空格的分隔符，避免匹配单词内的at
                size_t startPos = 0;
                size_t delimiterPos = stackStr.find(delimiter, startPos);

                while (delimiterPos != std::string::npos) {
                    // 截取分隔符前的片段（非空则加入）
                    if (delimiterPos > startPos) {
                        std::string frag = stackStr.substr(startPos, delimiterPos - startPos);
                        // 去除片段首尾的空白（仅清理首尾，保留中间空格）
                        frag.erase(0, frag.find_first_not_of(" \t\n\r"));
                        frag.erase(frag.find_last_not_of(" \t\n\r") + 1);
                        if (!frag.empty()) {
                            fragments.push_back(frag);
                        }
                    }
                    // 移动起始位置到分隔符末尾，继续查找下一个
                    startPos = delimiterPos + delimiter.length();
                    delimiterPos = stackStr.find(delimiter, startPos);
                }

                // 截取最后一个分隔符后的剩余片段（非空则加入）
                if (startPos < stackStr.length()) {
                    std::string frag = stackStr.substr(startPos);
                    frag.erase(0, frag.find_first_not_of(" \t\n\r"));
                    frag.erase(frag.find_last_not_of(" \t\n\r") + 1);
                    if (!frag.empty()) {
                        fragments.push_back(frag);
                    }
                }

                for (const auto& frag : fragments) {
                    if (frag.empty()) continue;
                    resultStack.push_back(stringToWstring(frag));
                }
            }
            if (stackCStr) JS_FreeCString(jsContext, stackCStr);
        }
        JS_FreeValue(jsContext, stackVal);

        // 若处理后无内容，补充默认值
        if (resultStack.empty()) {
            resultStack.push_back(L"unknown:0:0");
        }

        return resultStack;
    }

    std::wstring RemoveSpaceAfterNumber(std::wstring number) {
        // 1. 查找小数点位置，npos表示无小数点（纯整数，直接返回）
        size_t dot_pos = number.find(L'.');
        if (dot_pos == std::wstring::npos) {
            return number;
        }

        // 2. 从末尾向前找第一个非0字符，定位有效数字的最后位置
        size_t last_non_zero = number.find_last_not_of(L'0');

        // 3. 核心修复：若最后一个非0字符在小数点前/就是小数点（如123.、123.000、0.）
        //    直接删除小数点及后续所有字符，得到纯整数（无额外.）
        if (last_non_zero <= dot_pos) {
            number.erase(dot_pos);
        }
        // 4. 若最后一个非0字符在小数点后（如123.4500、0.1020），仅删除其后多余0
        else {
            number.erase(last_non_zero + 1);
        }

        return number;
    }

    std::string GetTextFromBinary(BYTEBUFFER_PTR binaryPtr)
    {
        if (binaryPtr == nullptr)
        {
            return "";
        }
        const BYTEBUFFER& binaryBuf = *binaryPtr;
        if (binaryBuf.empty())
        {
            return "";
        }
        return std::string(reinterpret_cast<const char*>(binaryBuf.data()), binaryBuf.size());
    }

    __forceinline bool isDigit(wchar_t c) {
        return c >= L'0' && c <= L'9';
    }
    long long stollSafely(const std::wstring& value) {
        if (value.empty()) {
            return 0;
        }

        const wchar_t* p = value.c_str();
        const wchar_t* end = p + value.size();
        bool is_negative = false;

        // 优化：指针遍历跳过前缀无效字符
        while (p < end) {
            wchar_t c = *p;
            if (c == L'+' || c == L'-' || isDigit(c)) {
                break;
            }
            p++;
        }
        if (p >= end) {
            return 0;
        }

        // 处理正负号
        wchar_t first_valid_c = *p;
        if (first_valid_c == L'-') {
            is_negative = true;
            p++;
        }
        else if (first_valid_c == L'+') {
            p++;
        }

        if (p >= end) {
            return 0;
        }

        // 跳过符号后无效字符
        while (p < end) {
            if (isDigit(*p)) {
                break;
            }
            p++;
        }
        if (p >= end) {
            return 0;
        }

        // 标记有效数字结束位置
        const wchar_t* valid_end = p;
        while (valid_end < end && isDigit(*valid_end)) {
            valid_end++;
        }

        // 使用wcstoll解析
        wchar_t* end_ptr = nullptr;
        errno = 0; // 重置errno
        long long result = wcstoll(p, &end_ptr, 10);

        // 修复点3：统一转为 ptrdiff_t 类型比较
        ptrdiff_t parsed_len = end_ptr - p;
        ptrdiff_t valid_len = valid_end - p;
        if (end_ptr == p || parsed_len > valid_len) {
            return 0;
        }

        // 处理越界
        if (errno == ERANGE) {
            return is_negative ? LLONG_MIN : LLONG_MAX;
        }

        return is_negative ? -result : result;
    }
    unsigned long long stoullSafely(const std::wstring& value) {
        if (value.empty()) {
            return 0;
        }

        const wchar_t* p = value.c_str();
        const wchar_t* end = p + value.size();

        // 优化：指针遍历跳过前缀无效字符
        while (p < end) {
            wchar_t c = *p;
            if (c == L'+') {
                p++;
            }
            else if (c == L'-') { // 负号直接返回0
                return 0;
            }
            else if (isDigit(c)) {
                break;
            }
            else {
                p++;
            }
        }
        if (p >= end) {
            return 0;
        }

        // 跳过正号后无效字符
        while (p < end) {
            if (isDigit(*p)) {
                break;
            }
            p++;
        }
        if (p >= end) {
            return 0;
        }

        // 标记有效数字结束位置
        const wchar_t* valid_end = p;
        while (valid_end < end && isDigit(*valid_end)) {
            valid_end++;
        }

        // 使用wcstoull解析
        wchar_t* end_ptr = nullptr;
        errno = 0; // 重置errno
        unsigned long long result = wcstoull(p, &end_ptr, 10);

        // 修复点2：统一转为 ptrdiff_t 类型比较
        ptrdiff_t parsed_len = end_ptr - p;
        ptrdiff_t valid_len = valid_end - p;
        if (end_ptr == p || parsed_len > valid_len) {
            return 0;
        }

        // 处理越界
        if (result == ULLONG_MAX && errno == ERANGE) {
            return ULLONG_MAX;
        }

        return result;
    }

    template <typename T>
    typename std::enable_if<std::is_trivial<T>::value&& std::is_standard_layout<T>::value, void>::type
        ToBinaryImpl(const T& data, BYTEBUFFER& buffer) {
        const unsigned char* data_ptr = reinterpret_cast<const unsigned char*>(&data);
        buffer.insert(buffer.end(), data_ptr, data_ptr + sizeof(T));
    }
    inline void ToBinaryImpl(const std::string& str, BYTEBUFFER& buffer) {
        const unsigned char* str_ptr = reinterpret_cast<const unsigned char*>(str.data());
        buffer.insert(buffer.end(), str_ptr, str_ptr + str.size());
    }
    inline void ToBinaryImpl(const std::wstring& wstr, BYTEBUFFER& buffer) {
        std::string utf8_str = wstringToString(wstr);
        const unsigned char* str_ptr = reinterpret_cast<const unsigned char*>(utf8_str.data());
        buffer.insert(buffer.end(), str_ptr, str_ptr + utf8_str.size());
    }
    inline void ToBinaryImpl(const wchar_t* wstr_ptr, BYTEBUFFER& buffer) {
        if (wstr_ptr == nullptr) return;
        std::wstring wstr(wstr_ptr);
        ToBinaryImpl(wstr, buffer);
    }
    template <template <typename, typename...> class Container, typename T, typename... Args>
    typename std::enable_if<
        !std::is_same<Container<T, Args...>, std::string>::value &&
        !std::is_same<Container<T, Args...>, std::wstring>::value,
        void>::type
        ToBinaryImpl(const Container<T, Args...>& container, BYTEBUFFER& buffer) {
        for (const auto& elem : container) {
            ToBinaryImpl(elem, buffer);
        }
    }
    template <typename T>
    BYTEBUFFER ToBinary(const T& data) {
        BYTEBUFFER buffer;
        buffer.reserve(std::is_trivial<T>::value ? sizeof(T) : 16);
        ToBinaryImpl(data, buffer);
        return buffer;
    }
    std::string GetTextFromBinarySafely(BYTEBUFFER_PTR bp);

    std::wstring GetAbsolutePath(std::wstring path, std::wstring base = L"") {
        // 步骤1：统一路径分隔符为 /（先替换所有反斜杠为正斜杠）
        std::replace(path.begin(), path.end(), L'\\', L'/');
        if (!base.empty()) {
            std::replace(base.begin(), base.end(), L'\\', L'/');
        }

        // 步骤2：判断path是否已是绝对路径（Windows下：盘符开头 或 //开头）
        auto isAbsolutePath = [](const std::wstring& p) -> bool {
            // 情况1：盘符 + : 开头（兼容 C:test、C:/test 两种写法）
            if (p.size() >= 2 && iswalpha(p[0]) && p[1] == L':') {
                return true;
            }
            // 情况2：UNC路径（//server/share）
            if (p.size() >= 2 && p[0] == L'/' && p[1] == L'/') {
                return true;
            }
            return false;
            };

        // 步骤3：如果path是绝对路径，直接处理.和..；否则拼接base后处理
        std::wstring fullPath;
        if (isAbsolutePath(path)) {
            fullPath = path;
        }
        else {
            // 处理base：如果base为空，用当前进程的工作目录
            if (base.empty()) {
                wchar_t cwd[MAX_PATH] = { 0 };
                GetCurrentDirectoryW(MAX_PATH, cwd);
                base = std::wstring(cwd);
                std::replace(base.begin(), base.end(), L'\\', L'/');
            }

            // 拼接base和path：确保base末尾有/，避免拼接错误
            if (!base.empty() && base.back() != L'/') {
                base += L'/';
            }
            fullPath = base + path;
        }

        // 步骤4：处理.（当前目录）和..（上级目录），简化路径
        std::vector<std::wstring> components; // 存储路径片段
        std::wstring drivePrefix; // 存储盘符前缀（如 E:/）
        size_t start = 0;

        // 先提取盘符前缀（针对Windows路径）
        if (fullPath.size() >= 2 && iswalpha(fullPath[0]) && fullPath[1] == L':') {
            drivePrefix = fullPath.substr(0, 2); // 提取 E:
            start = 2;
            // 如果盘符后紧跟/，跳过/（如 E:/test → start=3）
            if (fullPath.size() >= 3 && fullPath[2] == L'/') {
                start = 3;
            }
        }
        // 处理UNC路径前缀
        else if (fullPath.size() >= 2 && fullPath[0] == L'/' && fullPath[1] == L'/') {
            drivePrefix = L"//";
            start = 2;
        }

        // 拆分路径片段并处理.和..
        size_t end = 0;
        while ((end = fullPath.find(L'/', start)) != std::wstring::npos) {
            std::wstring component = fullPath.substr(start, end - start);
            start = end + 1;

            if (component.empty() || component == L".") {
                continue; // 空片段（如//）或.，跳过
            }
            else if (component == L"..") {
                // ..表示上级目录，若components非空则弹出最后一个
                if (!components.empty()) {
                    components.pop_back();
                }
            }
            else {
                components.push_back(component);
            }
        }

        // 处理最后一个路径片段
        std::wstring lastComponent = fullPath.substr(start);
        if (!lastComponent.empty()) {
            if (lastComponent == L"..") {
                if (!components.empty()) {
                    components.pop_back();
                }
            }
            else if (lastComponent != L".") {
                components.push_back(lastComponent);
            }
        }

        // 步骤5：重组简化后的路径
        std::wstring result = drivePrefix;
        // 给盘符添加/（如 E: → E:/）
        if (!drivePrefix.empty() && drivePrefix != L"//") {
            result += L'/';
        }

        // 拼接路径片段
        for (size_t i = 0; i < components.size(); ++i) {
            if (i > 0) {
                result += L'/';
            }
            result += components[i];
        }

        // 处理空结果（如路径简化后为根目录）
        if (result.empty() || (drivePrefix.empty() && components.empty())) {
            result = L"/";
        }
        // 处理仅盘符的情况（如 E:/ → 保留 E:/）
        else if (result == drivePrefix) {
            result += L'/';
        }

        return result;
    }

    class FileController {
    public:
        FileController(std::wstring InPath, std::wstring base) {
            try {
                path = GetAbsolutePath(InPath, base);
                isValid = exists();

                if (isValid) {
                    hLockedHandle = LockPath(path);
                    isValid = (hLockedHandle != INVALID_HANDLE_VALUE);
                }
            }
            catch (...) {
                isValid = false;
                hLockedHandle = INVALID_HANDLE_VALUE;
            }
        }

        ~FileController() {
            try {
                ReleaseLock();
            }
            catch (...) {
            }
        }

        FileController(const FileController&) = delete;
        FileController& operator=(const FileController&) = delete;

        FileController(FileController&& other) noexcept {
            try {
                path = std::move(other.path);
                isValid = other.isValid;
                hLockedHandle = other.hLockedHandle;
                lockTempFilePath = std::move(other.lockTempFilePath);
                other.hLockedHandle = INVALID_HANDLE_VALUE;
                other.isValid = false;
            }
            catch (...) {
                hLockedHandle = INVALID_HANDLE_VALUE;
                isValid = false;
            }
        }

        FileController& operator=(FileController&& other) noexcept {
            if (this != &other) {
                try {
                    ReleaseLock();
                    path = std::move(other.path);
                    isValid = other.isValid;
                    hLockedHandle = other.hLockedHandle;
                    lockTempFilePath = std::move(other.lockTempFilePath);
                    other.hLockedHandle = INVALID_HANDLE_VALUE;
                    other.isValid = false;
                }
                catch (...) {
                    hLockedHandle = INVALID_HANDLE_VALUE;
                    isValid = false;
                }
            }
            return *this;
        }

        bool isValid = true;

        bool isFile() {
            try {
                return std::filesystem::is_regular_file(path) || std::filesystem::is_symlink(path);
            }
            catch (...) {
                return false;
            }
        }

        bool isDir() {
            try {
                return std::filesystem::is_directory(path);
            }
            catch (...) {
                return false;
            }
        }

        ULL count() {
            try {
                if (!std::filesystem::exists(path)) {
                    return 0;
                }
                std::uintmax_t count = 0;
                if (std::filesystem::is_regular_file(path) || std::filesystem::is_symlink(path)) {
                    return 0;
                }
                if (std::filesystem::is_directory(path)) {
                    for (const auto& entry : std::filesystem::recursive_directory_iterator(path)) {
                        count++;
                    }
                }
                return count;
            }
            catch (...) {
                return 0;
            }
        }

        ULL remove() {
            try {
                ReleaseLock();
                return std::filesystem::remove_all(path);
            }
            catch (...) {
                return 0;
            }
        }

        bool exists() {
            try {
                return std::filesystem::exists(path);
            }
            catch (...) {
                return false;
            }
        }

        ULL size() {
            try {
                if (!exists()) {
                    return 0;
                }

                ULL total_size = 0;

                if (std::filesystem::is_regular_file(path)) {
                    total_size = static_cast<ULL>(std::filesystem::file_size(path));
                }
                else if (std::filesystem::is_directory(path)) {
                    for (const auto& entry : std::filesystem::recursive_directory_iterator(
                        path,
                        std::filesystem::directory_options::skip_permission_denied)) {
                        if (std::filesystem::is_regular_file(entry)) {
                            total_size += static_cast<ULL>(std::filesystem::file_size(entry));
                        }
                    }
                }

                return total_size;
            }
            catch (...) {
                return 0;
            }
        }

        GMMT list() {
            try {
                if (std::filesystem::is_regular_file(path)) {
                    return {};
                }

                GMMT result_map;
                std::filesystem::path root_path(path);
                if (!std::filesystem::exists(root_path)) return result_map;

                std::filesystem::recursive_directory_iterator iter(
                    root_path,
                    std::filesystem::directory_options::skip_permission_denied
                );
                std::filesystem::recursive_directory_iterator end_iter;

                for (; iter != end_iter; ++iter) {
                    try {
                        const std::filesystem::directory_entry& entry = *iter;
                        const std::filesystem::path& entry_path = entry.path();
                        std::wstring item_name = entry_path.filename().wstring();
                        std::wstring full_path = entry_path.wstring();

                        std::replace(full_path.begin(), full_path.end(), L'\\', L'/');
                        if (entry.is_directory() && !full_path.empty() && full_path.back() != L'/') {
                            full_path += L'/';
                        }
                        result_map.emplace(item_name, full_path);
                    }
                    catch (...) {
                        continue;
                    }
                }
                return result_map;
            }
            catch (...) {
                return {};
            }
        }

        bool read(ULL base, ULL size, BYTEBUFFER_PTR out) {
            try {
                if (std::filesystem::is_directory(path)) {
                    return false;
                }

                if (out == nullptr || !exists()) {
                    return false;
                }

                std::ifstream file(path, std::ios::in | std::ios::binary);
                if (!file.is_open()) {
                    return false;
                }

                file.seekg(0, std::ios::end);
                const ULL file_total_size = static_cast<ULL>(file.tellg());
                file.seekg(0, std::ios::beg);

                const ULL read_start = (base >= file_total_size) ? file_total_size : base;
                ULL actual_read_size = 0;

                if (size == ULLONG_MAX) {
                    actual_read_size = file_total_size - read_start;
                }
                else {
                    actual_read_size = (read_start + size > file_total_size)
                        ? (file_total_size - read_start)
                        : size;
                }

                out->clear();
                if (actual_read_size > 0) {
                    out->resize(static_cast<size_t>(actual_read_size));
                    file.seekg(static_cast<std::streamoff>(read_start));
                    file.read(reinterpret_cast<char*>(out->data()), actual_read_size);
                }

                return !file.fail();
            }
            catch (...) {
                return false;
            }
        }

        ULL write(BYTEBUFFER_PTR buffer, ULL base = 0, bool append = false) {
            try {
                if (std::filesystem::is_directory(path)) {
                    return 0;
                }

                if (!buffer || buffer->empty()) {
                    return 0;
                }

                const ULL write_data_size = buffer->size();
                std::fstream file;
                ULL write_start = base;

                file.open(path, std::ios::in | std::ios::out | std::ios::binary);

                if (!file.is_open()) {
                    std::ofstream create_file(path, std::ios::out | std::ios::binary);
                    if (!create_file.is_open()) {
                        return 0;
                    }
                    create_file.close();

                    file.open(path, std::ios::in | std::ios::out | std::ios::binary);
                    if (!file.is_open()) {
                        return 0;
                    }
                }

                file.seekg(0, std::ios::end);
                if (file.fail()) {
                    file.close();
                    return 0;
                }
                const ULL file_total_size = static_cast<ULL>(file.tellg());
                if (file.fail()) {
                    file.close();
                    return 0;
                }

                if (append) {
                    write_start = (base == 0 || base >= file_total_size) ? file_total_size : base;
                }
                else {
                    write_start = base;
                }

                file.seekp(static_cast<std::streamoff>(write_start));
                if (file.fail()) {
                    file.close();
                    return 0;
                }

                file.write(reinterpret_cast<const char*>(buffer->data()), write_data_size);
                if (file.fail() || file.bad()) {
                    file.close();
                    return 0;
                }

                file.flush();
                file.close();

                return write_data_size;
            }
            catch (...) {
                return 0;
            }
        }

        bool clear() {
            try {
                std::fstream file;
                file.open(path, std::ios::out | std::ios::binary | std::ios::trunc);

                if (!file.is_open()) {
                    return false;
                }

                file.close();

                return !file.fail();
            }
            catch (...) {
                return false;
            }
        }

    private:
        HANDLE hLockedHandle = INVALID_HANDLE_VALUE;
        std::wstring lockTempFilePath;
        BYTEBUFFER writeDataTemp = {};
        std::wstring path = L"";

        std::wstring GetAbsolutePath(const std::wstring& InPath, const std::wstring& base) {
            try {
                std::filesystem::path base_path(base);
                std::filesystem::path input_path(InPath);
                return std::filesystem::absolute(base_path / input_path).wstring();
            }
            catch (...) {
                return InPath;
            }
        }

        HANDLE LockPath(const std::wstring& path) {
            try {
                if (isFile()) {
                    return CreateFileW(
                        path.c_str(),
                        GENERIC_READ,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        NULL,
                        OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL,
                        NULL
                    );
                }
                else if (isDir()) {
                    lockTempFilePath = path + L"\\.cjs.fc.lock" + std::to_wstring(GetCurrentProcessId()) + std::to_wstring(GetCurrentThreadId()) + L".tmp";
                    return CreateFileW(
                        lockTempFilePath.c_str(),
                        GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        NULL,
                        CREATE_ALWAYS,
                        FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM,
                        NULL
                    );
                }
                return INVALID_HANDLE_VALUE;
            }
            catch (...) {
                return INVALID_HANDLE_VALUE;
            }
        }

        void ReleaseLock() {
            try {
                if (hLockedHandle != INVALID_HANDLE_VALUE) {
                    CloseHandle(hLockedHandle);
                    hLockedHandle = INVALID_HANDLE_VALUE;
                }
                if (!lockTempFilePath.empty() && std::filesystem::exists(lockTempFilePath)) {
                    std::filesystem::remove(lockTempFilePath);
                    lockTempFilePath.clear();
                }
            }
            catch (...) {
            }
        }
    };

    enum XHRHttpErrorCode : int {
        OK = 0,
        NETWORK_ERROR = 1,
        TIMEOUT_ERROR = 2,
        ABORT_ERROR = 3,
        HTTP_ERROR = 4
    };
    enum XHRReadyState : int {
        UNSENT = 0,
        OPENED = 1,
        HEADERS_RECEIVED = 2,
        LOADING = 3,
        DONE = 4
    };
    struct XHRPROGRESSEVENT {
        std::wstring type;
        ULL loaded = 0;
        ULL total = 0;
        bool lengthComputable = false;

        std::wstring errorMessage = L"";
        ULL errorCode = NULL;
    };
    typedef std::function<void(XHRPROGRESSEVENT)> XHRPROGRESSCALLBACK;
    typedef std::function<void(bool, BYTEBUFFER)> FILECALLBACK;
    typedef std::function<void(void)> NONECALLBACK, * NONECALLBACK_PTR;
    static std::unordered_map<std::wstring, int> HttpResponseCode = {
    {L"Continue", 100},
    {L"SwitchingProtocols", 101},
    {L"Processing", 102},
    {L"EarlyHints", 103},
    {L"OK", 200},
    {L"Created", 201},
    {L"Accepted", 202},
    {L"NonAuthoritativeInformation", 203},
    {L"NoContent", 204},
    {L"ResetContent", 205},
    {L"PartialContent", 206},
    {L"MultiStatus", 207},
    {L"AlreadyReported", 208},
    {L"IMUsed", 226},
    {L"MultipleChoices", 300},
    {L"MovedPermanently", 301},
    {L"Found", 302},
    {L"SeeOther", 303},
    {L"NotModified", 304},
    {L"UseProxy", 305},
    {L"TemporaryRedirect", 307},
    {L"PermanentRedirect", 308},
    {L"BadRequest", 400},
    {L"Unauthorized", 401},
    {L"PaymentRequired", 402},
    {L"Forbidden", 403},
    {L"NotFound", 404},
    {L"MethodNotAllowed", 405},
    {L"NotAcceptable", 406},
    {L"ProxyAuthenticationRequired", 407},
    {L"RequestTimeout", 408},
    {L"Conflict", 409},
    {L"Gone", 410},
    {L"LengthRequired", 411},
    {L"PreconditionFailed", 412},
    {L"PayloadTooLarge", 413},
    {L"URITooLong", 414},
    {L"UnsupportedMediaType", 415},
    {L"RangeNotSatisfiable", 416},
    {L"ExpectationFailed", 417},
    {L"ImATeapot", 418},
    {L"MisdirectedRequest", 421},
    {L"UnprocessableEntity", 422},
    {L"Locked", 423},
    {L"FailedDependency", 424},
    {L"TooEarly", 425},
    {L"UpgradeRequired", 426},
    {L"PreconditionRequired", 428},
    {L"TooManyRequests", 429},
    {L"RequestHeaderFieldsTooLarge", 431},
    {L"UnavailableForLegalReasons", 451},
    {L"InternalServerError", 500},
    {L"NotImplemented", 501},
    {L"BadGateway", 502},
    {L"ServiceUnavailable", 503},
    {L"GatewayTimeout", 504},
    {L"HTTPVersionNotSupported", 505},
    {L"VariantAlsoNegotiates", 506},
    {L"InsufficientStorage", 507},
    {L"LoopDetected", 508},
    {L"NotExtended", 510},
    {L"NetworkAuthenticationRequired", 511}
    };
    std::wstring ToUpLetters(const std::wstring& str) noexcept {
        std::wstring result(str);
        wchar_t* ptr = result.data();
        const wchar_t* end = ptr + result.size();
        for (; ptr < end; ++ptr) {
            if (iswalpha(static_cast<wint_t>(*ptr))) {
                *ptr = static_cast<wchar_t>(towupper(static_cast<wint_t>(*ptr)));
            }
        }
        return result;
    }
    std::wstring ToDownLetters(const std::wstring& str) noexcept {
        std::wstring result(str);
        wchar_t* ptr = result.data();
        const wchar_t* end = ptr + result.size();
        for (; ptr < end; ++ptr) {
            if (iswalpha(static_cast<wint_t>(*ptr))) {
                *ptr = static_cast<wchar_t>(towlower(static_cast<wint_t>(*ptr)));
            }
        }
        return result;
    }
    std::wstring GetAcceptLanguageHeader() {
        LCID defaultLcid = GetUserDefaultUILanguage();
        WCHAR langCode[16] = { 0 }, countryCode[16] = { 0 };
        GetLocaleInfoW(defaultLcid, LOCALE_SISO639LANGNAME, langCode, _countof(langCode));
        GetLocaleInfoW(defaultLcid, LOCALE_SISO3166CTRYNAME, countryCode, _countof(countryCode));
        std::wstring mainLang;
        if (wcslen(langCode) > 0) {
            mainLang = langCode;
            if (wcslen(countryCode) > 0) mainLang += L"-" + std::wstring(countryCode);
        }
        std::wstringstream ss;
        if (!mainLang.empty()) ss << mainLang << L", " << langCode << L";q=0.9, en-US;q=0.8, en;q=0.7";
        else ss << L"en-US,en;q=0.9";
        return ss.str();
    }
    std::wstring GetErrorMessageFromErrorCode(DWORD errorCode) {
        WCHAR* errorMsgBuffer = nullptr;
        HMODULE hModule = nullptr;
        if (errorCode >= 12000 && errorCode <= 12156) {
            hModule = LoadLibraryW(L"winhttp.dll");
            if (hModule == nullptr) return L"Failed to load winhttp.dll.";
        }
        LCID defaultLangId = GetThreadLocale();
        DWORD msgLength = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_IGNORE_INSERTS, hModule, errorCode, defaultLangId, (LPWSTR)&errorMsgBuffer, 0, nullptr);
        std::wstring errorMsg;
        if (msgLength > 0 && errorMsgBuffer) { errorMsg = errorMsgBuffer; LocalFree(errorMsgBuffer); }
        else {
            WCHAR errorCodeBuf[32] = { 0 };
            wsprintfW(errorCodeBuf, L"Unknown error (0x%08X)", errorCode);
            errorMsg = errorCodeBuf;
        }
        if (hModule != nullptr) FreeLibrary(hModule);
        return errorMsg;
    }
    std::wstring GetHeadersFromHeaderList(const GMT& headerList) {
        std::vector<std::pair<std::wstring, std::wstring>> headerVec(headerList.begin(), headerList.end());
        for (auto& [key, val] : headerVec) {
            if (!key.empty()) {
                key[0] = towupper(key[0]);
                for (size_t i = 1; i < key.size(); ++i) key[i] = (key[i - 1] == L'-') ? towupper(key[i]) : towlower(key[i]);
            }
        }
        std::sort(headerVec.begin(), headerVec.end(), [](const auto& a, const auto& b) { return a.first < b.first; });
        std::wstring headerStr;
        size_t totalSize = 0;
        for (const auto& [k, v] : headerVec) totalSize += k.size() + v.size() + 4;
        totalSize += 2;
        if (totalSize > 0) headerStr.reserve(totalSize);
        for (const auto& [k, v] : headerVec) headerStr += k + L": " + v + L"\r\n";
        if (!headerVec.empty()) headerStr += L"\r\n";
        return headerStr;
    }
    std::wstring GetResponseMessageFromResponseCode(int statusCode, bool isFormat = false) {
        auto FormatResponseMsg = [](const std::wstring& rawMsg) -> std::wstring {
            if (rawMsg.size() <= 1) return rawMsg;
            std::wstring formatted; formatted.reserve(rawMsg.size() + 6);
            formatted += rawMsg[0];
            for (size_t i = 1; i < rawMsg.size(); ++i) {
                if (rawMsg[i] >= L'A' && rawMsg[i] <= L'Z') formatted += L" ";
                formatted += rawMsg[i];
            }
            return formatted;
            };
        for (const auto& [msg, code] : HttpResponseCode) {
            if (code == statusCode) return isFormat ? FormatResponseMsg(msg) : msg;
        }
        return L"UnknownResponseCode";
    }
    std::wstring getMimeTypeFromContentType(std::wstring ct) {
        size_t semicolonPos = ct.find(L';');
        if (semicolonPos != std::wstring::npos) ct = ct.substr(0, semicolonPos);
        size_t start = ct.find_first_not_of(L" \t\r\n"), end = ct.find_last_not_of(L" \t\r\n");
        if (start != std::wstring::npos && end != std::wstring::npos) ct = ct.substr(start, end - start + 1);
        return ct;
    }
    bool UnGzip(BYTEBUFFER_PTR bp) {
        if (!bp || bp->empty()) return false;
        z_stream strm{};
        int windowBits = 0;
        if (bp->size() >= 2 && (*bp)[0] == 0x1F && (*bp)[1] == 0x8B) windowBits = 16 + MAX_WBITS;
        else if (bp->size() >= 2) {
            unsigned char cmf = (*bp)[0], flg = (*bp)[1];
            windowBits = ((cmf & 0x0F) == 8 && (flg & 0x20) == 0) ? MAX_WBITS : -MAX_WBITS;
        }
        else windowBits = 16 + MAX_WBITS;
        if (inflateInit2(&strm, windowBits) != Z_OK) return false;
        strm.next_in = bp->data();
        strm.avail_in = static_cast<uInt>(bp->size());
        BYTEBUFFER outBuffer; outBuffer.reserve(bp->size() * 4);
        const size_t CHUNK = 16384;
        int ret;
        do {
            size_t oldSize = outBuffer.size();
            outBuffer.resize(oldSize + CHUNK);
            strm.next_out = outBuffer.data() + oldSize;
            strm.avail_out = CHUNK;
            ret = inflate(&strm, Z_NO_FLUSH);
            if (ret != Z_OK && ret != Z_STREAM_END) { inflateEnd(&strm); return false; }
            size_t have = CHUNK - strm.avail_out;
            if (have < CHUNK) outBuffer.resize(oldSize + have);
        } while (ret != Z_STREAM_END);
        inflateEnd(&strm);
        BYTEBUFFER utf8Buffer;
        if (outBuffer.size() >= 3 && outBuffer[0] == 0xEF && outBuffer[1] == 0xBB && outBuffer[2] == 0xBF) {
            utf8Buffer.assign(outBuffer.begin() + 3, outBuffer.end());
        }
        else if (outBuffer.size() >= 2 && outBuffer[0] == 0xFF && outBuffer[1] == 0xFE) {
            int wideLen = MultiByteToWideChar(CP_UTF16, 0, reinterpret_cast<const char*>(outBuffer.data() + 2), static_cast<int>((outBuffer.size() - 2) / 2), nullptr, 0);
            if (wideLen > 0) {
                std::wstring wideStr(wideLen, L'\0');
                MultiByteToWideChar(CP_UTF16, 0, reinterpret_cast<const char*>(outBuffer.data() + 2), static_cast<int>((outBuffer.size() - 2) / 2), &wideStr[0], wideLen);
                int utf8Len = WideCharToMultiByte(CP_UTF8, 0, wideStr.c_str(), wideLen, nullptr, 0, nullptr, nullptr);
                if (utf8Len > 0) {
                    utf8Buffer.resize(utf8Len);
                    WideCharToMultiByte(CP_UTF8, 0, wideStr.c_str(), wideLen, reinterpret_cast<char*>(utf8Buffer.data()), utf8Len, nullptr, nullptr);
                }
            }
        }
        else if (outBuffer.size() >= 2 && outBuffer[0] == 0xFE && outBuffer[1] == 0xFF) {
            BYTE* data = outBuffer.data() + 2;
            size_t len = outBuffer.size() - 2;
            for (size_t i = 0; i < len; i += 2) std::swap(data[i], data[i + 1]);
            int wideLen = MultiByteToWideChar(CP_UTF16, 0, reinterpret_cast<const char*>(data), static_cast<int>(len / 2), nullptr, 0);
            if (wideLen > 0) {
                std::wstring wideStr(wideLen, L'\0');
                MultiByteToWideChar(CP_UTF16, 0, reinterpret_cast<const char*>(data), static_cast<int>(len / 2), &wideStr[0], wideLen);
                int utf8Len = WideCharToMultiByte(CP_UTF8, 0, wideStr.c_str(), wideLen, nullptr, 0, nullptr, nullptr);
                if (utf8Len > 0) {
                    utf8Buffer.resize(utf8Len);
                    WideCharToMultiByte(CP_UTF8, 0, wideStr.c_str(), wideLen, reinterpret_cast<char*>(utf8Buffer.data()), utf8Len, nullptr, nullptr);
                }
            }
        }
        else {
            bool isUtf8 = true;
            for (size_t i = 0; i < outBuffer.size();) {
                unsigned char byte = outBuffer[i];
                int bytesToCheck;
                if ((byte & 0x80) == 0) bytesToCheck = 1;
                else if ((byte & 0xE0) == 0xC0) bytesToCheck = 2;
                else if ((byte & 0xF0) == 0xE0) bytesToCheck = 3;
                else if ((byte & 0xF8) == 0xF0) bytesToCheck = 4;
                else { isUtf8 = false; break; }
                if (i + bytesToCheck > outBuffer.size()) { isUtf8 = false; break; }
                for (int j = 1; j < bytesToCheck; j++) {
                    if ((outBuffer[i + j] & 0xC0) != 0x80) { isUtf8 = false; break; }
                }
                if (!isUtf8) break;
                i += bytesToCheck;
            }
            if (isUtf8) utf8Buffer = std::move(outBuffer);
            else {
                int wideLen = MultiByteToWideChar(936, 0, reinterpret_cast<const char*>(outBuffer.data()), static_cast<int>(outBuffer.size()), nullptr, 0);
                if (wideLen > 0) {
                    std::wstring wideStr(wideLen, L'\0');
                    MultiByteToWideChar(936, 0, reinterpret_cast<const char*>(outBuffer.data()), static_cast<int>(outBuffer.size()), &wideStr[0], wideLen);
                    int utf8Len = WideCharToMultiByte(CP_UTF8, 0, wideStr.c_str(), wideLen, nullptr, 0, nullptr, nullptr);
                    if (utf8Len > 0) {
                        utf8Buffer.resize(utf8Len);
                        WideCharToMultiByte(CP_UTF8, 0, wideStr.c_str(), wideLen, reinterpret_cast<char*>(utf8Buffer.data()), utf8Len, nullptr, nullptr);
                    }
                }
            }
        }
        *bp = std::move(utf8Buffer);
        return true;
    }

    enum filesystem_open_mode : int {
        FILE_MODE_NONE = 0x00,  // 无模式（异常返回值）
        FILE_MODE_READ = 0x01,  // 只读 r (2^0)
        FILE_MODE_WRITE = 0x02,  // 只写 w (2^1)
        FILE_MODE_APPEND = 0x04,  // 追加 a (2^2)
        FILE_MODE_BIN = 0x08,  // 二进制 b (2^3)
        FILE_MODE_RDWR = 0x10   // 读写扩展 + (2^4)
    };

    int GetFileControllerMode(std::string mode) {
        // 步骤1：统一转小写，兼容RB/R+/Wb+/+ab等大小写/顺序混合写法
        std::transform(mode.begin(), mode.end(), mode.begin(),
            [](unsigned char c) { return std::tolower(c); });

        // 步骤2：初始化模式为无，用于位运算组合（原生enum直接赋值，无转换）
        int file_mode = FILE_MODE_NONE;
        // 核心模式计数器：r/w/a 必须且仅能存在1个，否则为非法
        int core_mode_cnt = 0;

        // 步骤3：逐字符解析，直接位或（|=）组合模式，支持任意字符顺序
        for (char c : mode) {
            switch (c) {
            case 'r':
                file_mode |= FILE_MODE_READ;
                core_mode_cnt++;
                break;
            case 'w':
                file_mode |= FILE_MODE_WRITE;
                core_mode_cnt++;
                break;
            case 'a':
                file_mode |= FILE_MODE_APPEND;
                core_mode_cnt++;
                break;
            case 'b':
                file_mode |= FILE_MODE_BIN;
                break;
            case '+':
                file_mode |= FILE_MODE_RDWR;
                break;
            default:
                // 包含非法字符（如x/1/-/.等），直接返回0
                return 0;
            }
        }

        // 步骤4：严格合法性校验（拦截所有非法场景）
        if (mode.empty() || core_mode_cnt != 1) {
            return 0; // 空字符串/无核心模式/多个核心模式（如rw/ra/war），均非法
        }

        // 步骤5：合法模式返回位运算组合值，天然非0（1~INT_MAX）
        return file_mode;
    }

    std::wstring GetTextFromBYTEBUFFER(BYTEBUFFER_PTR byteBuffer)
    {
        if (!byteBuffer || byteBuffer->empty())
        {
            return L"";
        }

        const char* utf8_data = reinterpret_cast<const char*>(byteBuffer->data());
        int utf8_len = static_cast<int>(byteBuffer->size());

        int wchar_len = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8_data, utf8_len, nullptr, 0);
        if (wchar_len == 0)
        {
            // 获取错误码，便于调试（生产环境可根据需要记录日志）
            DWORD error = GetLastError();
            // 常见错误：ERROR_NO_UNICODE_TRANSLATION（无效UTF-8字符）
            // 即使转换失败，也返回空字符串保证函数稳定性
            return L"";
        }

        std::wstring result(wchar_len, L'\0');
        int converted_len = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8_data, utf8_len, &result[0], wchar_len);

        if (converted_len != wchar_len)
        {
            return L"";
        }

        return result;
    }
    std::wstring GetMIMETypeFromBYTEBUFFER(BYTEBUFFER_PTR byteBuffer) {
        // 空指针或空缓冲区，返回默认二进制类型
        if (!byteBuffer || byteBuffer->empty()) {
            return L"application/octet-stream";
        }

        // 取缓冲区数据，改为unsigned char避免冗余转换，提升安全性
        const unsigned char* data = byteBuffer->data();
        size_t dataSize = byteBuffer->size();

        // 辅助函数：快速比较文件头（兼容任意长度的头信息，自动判断缓冲区大小）
        auto compareHeader = [&](const unsigned char* header, size_t headerLen) -> bool {
            if (dataSize < headerLen || header == nullptr) return false;
            return std::memcmp(data, header, headerLen) == 0;
            };

        // 辅助函数：比较指定偏移量的文件头
        auto compareHeaderAtOffset = [&](size_t offset, const unsigned char* header, size_t headerLen) -> bool {
            if (dataSize < offset + headerLen || header == nullptr) return false;
            return std::memcmp(data + offset, header, headerLen) == 0;
            };

        // 辅助函数：判断是否为有效的UTF-8编码
        auto isUtf8Text = [&]() -> bool {
            size_t i = 0;
            while (i < dataSize) {
                unsigned char c = data[i];
                if ((c & 0x80) == 0) {
                    // 单字节：0xxxxxxx，允许ASCII可见字符和常见控制字符
                    if (c < 0x09) return false; // 排除除制表符外的控制字符
                    if (c == 0x0B || c == 0x0C) return false; // 排除垂直制表符、换页符
                    if (c >= 0x0E && c <= 0x1F) return false; // 排除其他控制字符
                    if (c == 0x7F) return false; // 排除DEL字符
                    i++;
                }
                else if ((c & 0xE0) == 0xC0) {
                    // 双字节：110xxxxx 10xxxxxx
                    if (i + 1 >= dataSize) return false;
                    if ((data[i + 1] & 0xC0) != 0x80) return false;
                    // 排除无效的UTF-8范围（如overlong编码）
                    if (c < 0xC2) return false;
                    i += 2;
                }
                else if ((c & 0xF0) == 0xE0) {
                    // 三字节：1110xxxx 10xxxxxx 10xxxxxx（中文字符主要在此范围）
                    if (i + 2 >= dataSize) return false;
                    if ((data[i + 1] & 0xC0) != 0x80 || (data[i + 2] & 0xC0) != 0x80) return false;
                    i += 3;
                }
                else if ((c & 0xF8) == 0xF0) {
                    // 四字节：11110xxx 10xxxxxx 10xxxxxx 10xxxxxx
                    if (i + 3 >= dataSize) return false;
                    if ((data[i + 1] & 0xC0) != 0x80 || (data[i + 2] & 0xC0) != 0x80 || (data[i + 3] & 0xC0) != 0x80) return false;
                    if (c > 0xF4) return false;
                    i += 4;
                }
                else {
                    // 无效的UTF-8起始字节
                    return false;
                }
            }
            return true;
            };

        // 辅助函数：判断是否为ASCII文本（兼容原逻辑，但放宽部分限制）
        auto isAsciiText = [&]() -> bool {
            size_t checkSize = std::min(dataSize, (size_t)1024);
            for (size_t i = 0; i < checkSize; ++i) {
                unsigned char c = data[i];
                // 允许ASCII可见字符、换行、回车、制表符、退格
                if (!((c >= 32 && c <= 126) || c == '\n' || c == '\r' || c == '\t' || c == '\b')) {
                    return false;
                }
            }
            return true;
            };

        // -------------------------- 1. 优先判断文本类型 --------------------------
        bool isText = false;
        bool isUtf8 = false;

        // 先检测是否为UTF-8文本（含中文）
        if (dataSize >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF) {
            // UTF-8 BOM，直接判定为UTF-8文本
            isText = true;
            isUtf8 = true;
        }
        else if (isUtf8Text()) {
            // 无BOM但有效UTF-8编码
            isText = true;
            isUtf8 = true;
        }
        else if (isAsciiText()) {
            // ASCII文本
            isText = true;
            isUtf8 = false;
        }

        if (isText) {
            // 读取前缀用于细分文本类型（使用string_view避免拷贝）
            auto getPrefix = [&](size_t len) -> std::string_view {
                return std::string_view(reinterpret_cast<const char*>(data), std::min(dataSize, len));
                };

            std::string_view prefix1 = getPrefix(1);
            std::string_view prefix2 = getPrefix(2);
            std::string_view prefix3 = getPrefix(3);
            std::string_view prefix4 = getPrefix(4);
            std::string_view prefix5 = getPrefix(5);
            std::string_view prefix6 = getPrefix(6);
            std::string_view prefix10 = getPrefix(10);

            // 标记语言/结构化文本
            if (prefix5 == "<!DOC" || prefix5 == "<html" || prefix5 == "<HTML")
                return L"text/html";
            else if (prefix5 == "<?xml" || prefix5 == "<root" || prefix5 == "<ROOT")
                return L"text/xml";
            else if (prefix4 == "<svg" || prefix4 == "<SVG")
                return L"image/svg+xml";
            else if (prefix6 == "<!DOCTYPE" || prefix5 == "<math")
                return L"application/xhtml+xml";

            // 样式表文件
            if (prefix2 == "/*" || prefix4 == "body" || prefix4 == "html" || prefix5 == "style")
                return L"text/css";
            else if (prefix4 == "@import" || prefix5 == "@media")
                return L"text/scss";

            // 脚本/代码文件
            if (prefix2 == "//" || prefix3 == "var " || prefix3 == "let " || prefix5 == "const")
                return L"text/javascript";
            else if (prefix5 == "type " || prefix4 == "interface")
                return L"text/typescript";
            else if (prefix2 == "/*" || prefix2 == "#include" || prefix4 == "class")
                return L"text/x-c++src";
            else if (prefix2 == "/*" || prefix4 == "int " || prefix5 == "float")
                return L"text/x-csrc";
            else if (prefix2 == "#!" || prefix4 == "def " || prefix5 == "class")
                return L"text/x-python";
            else if (prefix4 == "func " || prefix5 == "package")
                return L"text/x-go";
            else if (prefix2 == "//" || prefix4 == "public" || prefix5 == "class")
                return L"text/x-java";
            else if (prefix2 == "#!" || prefix4 == "sub " || prefix5 == "print")
                return L"text/x-perl";
            else if (prefix2 == "#!" || prefix4 == "use " || prefix5 == "my $")
                return L"text/x-ruby";
            else if (prefix6 == "<script")
                return L"application/javascript";
            else if (prefix4 == "<?lua")
                return L"text/x-lua";

            // 配置文件
            if (prefix2 == "# " || prefix2 == "//" || prefix4 == "[main" || prefix4 == "[env")
                return L"text/x-ini";
            else if (prefix1 == "{" || prefix1 == "[" || prefix2 == "{\"" || prefix2 == "[\"")
                return L"application/json";
            else if (prefix3 == "---" || prefix4 == "title")
                return L"text/yaml";
            else if (prefix4 == "<?php" || prefix2 == "<? ")
                return L"application/x-httpd-php";
            else if (prefix2 == "/*" || prefix4 == "user " || prefix5 == "pass ")
                return L"text/x-conf";

            // 标记/文档文件
            if (prefix2 == "# " || prefix2 == "* " || prefix2 == "- " || prefix4 == "## ")
                return L"text/markdown";
            else if (prefix2 == "=" || prefix2 == "-" || prefix4 == "----")
                return L"text/rst";
            else if (prefix4 == ".TH " || prefix2 == ".SH")
                return L"text/troff";

            // 数据文件
            if (prefix2 == "id," || prefix2 == "name" || prefix4 == "col1,")
                return L"text/csv";
            else if (prefix4 == "tsv\t" || prefix2 == "id\t")
                return L"text/tab-separated-values";
            else if (prefix2 == "; " || prefix4 == ";ID," || prefix5 == ";Name")
                return L"text/x-lua";

            // 日志/文本文件
            if (prefix4 == "INFO" || prefix4 == "ERROR" || prefix4 == "WARN " || prefix5 == "DEBUG")
                return L"text/x-log";
            else if (prefix2 == "-- " || prefix2 == "/* " || prefix4 == "NOTE ")
                return L"text/plain";

            // 所有文本类型都不匹配时，返回text/plain（根据编码返回对应charset）
            return isUtf8 ? L"text/plain; charset=UTF-8" : L"text/plain";
        }

        // -------------------------- 2. 再判断二进制类型 --------------------------

        // 图片类型
        if (dataSize >= 2 && data[0] == 0xFF && data[1] == 0xD8)
            return L"image/jpeg";
        const unsigned char PNG_HEADER[] = { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A };
        if (compareHeader(PNG_HEADER, sizeof(PNG_HEADER)))
            return L"image/png";
        const unsigned char GIF_HEADER1[] = { 0x47, 0x49, 0x46, 0x38, 0x39, 0x61 };
        const unsigned char GIF_HEADER2[] = { 0x47, 0x49, 0x46, 0x38, 0x37, 0x61 };
        if (compareHeader(GIF_HEADER1, sizeof(GIF_HEADER1)) || compareHeader(GIF_HEADER2, sizeof(GIF_HEADER2)))
            return L"image/gif";
        if (dataSize >= 2 && data[0] == 0x42 && data[1] == 0x4D)
            return L"image/bmp";
        if (dataSize >= 12 && data[0] == 0x52 && data[1] == 0x49 && data[2] == 0x46 && data[3] == 0x46 &&
            data[8] == 0x57 && data[9] == 0x45 && data[10] == 0x42 && data[11] == 0x50)
            return L"image/webp";
        if (dataSize >= 4 && data[0] == 0x00 && data[1] == 0x00 && data[2] == 0x01 && data[3] == 0x00)
            return L"image/x-icon";
        const unsigned char TIFF_HEADER1[] = { 0x49, 0x49, 0x2A, 0x00 };
        const unsigned char TIFF_HEADER2[] = { 0x4D, 0x4D, 0x00, 0x2A };
        if (compareHeader(TIFF_HEADER1, sizeof(TIFF_HEADER1)) || compareHeader(TIFF_HEADER2, sizeof(TIFF_HEADER2)))
            return L"image/tiff";
        const unsigned char BPG_HEADER[] = { 0x42, 0x50, 0x47, 0xFB };
        if (compareHeader(BPG_HEADER, sizeof(BPG_HEADER)))
            return L"image/bpg";
        const unsigned char JPEG2000_HEADER[] = { 0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20 };
        if (compareHeader(JPEG2000_HEADER, sizeof(JPEG2000_HEADER)))
            return L"image/jp2";
        const unsigned char PCX_HEADER[] = { 0x0A, 0x00, 0x01 };
        if (compareHeader(PCX_HEADER, sizeof(PCX_HEADER)))
            return L"image/pcx";
        const unsigned char TGA_HEADER1[] = { 0x00, 0x00, 0x02 };
        const unsigned char TGA_HEADER2[] = { 0x00, 0x00, 0x10 };
        if (compareHeader(TGA_HEADER1, sizeof(TGA_HEADER1)) || compareHeader(TGA_HEADER2, sizeof(TGA_HEADER2)))
            return L"image/tga";

        // 文档类型
        const unsigned char PDF_HEADER[] = { 0x25, 0x50, 0x44, 0x46 };
        if (compareHeader(PDF_HEADER, sizeof(PDF_HEADER)))
            return L"application/pdf";
        const unsigned char OFFICE_OPEN_XML_HEADER[] = { 0x50, 0x4B, 0x03, 0x04 };
        if (compareHeader(OFFICE_OPEN_XML_HEADER, sizeof(OFFICE_OPEN_XML_HEADER)) && dataSize >= 30)
        {
            std::string_view subHeader(reinterpret_cast<const char*>(data + 30), 12);
            if (subHeader.find("word/") != std::string_view::npos)
                return L"application/vnd.openxmlformats-officedocument.wordprocessingml.document";
            else if (subHeader.find("xl/") != std::string_view::npos)
                return L"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";
            else if (subHeader.find("ppt/") != std::string_view::npos)
                return L"application/vnd.openxmlformats-officedocument.presentationml.presentation";
        }
        if (dataSize >= 8 && data[0] == 0xD0 && data[1] == 0xCF && data[2] == 0x11 && data[3] == 0xE0 &&
            data[4] == 0xA1 && data[5] == 0xB1 && data[6] == 0x1A && data[7] == 0xE1)
        {
            if (dataSize >= 512 && std::string_view(reinterpret_cast<const char*>(data + 512), 4) == "Word")
                return L"application/msword";
            else if (dataSize >= 512 && std::string_view(reinterpret_cast<const char*>(data + 512), 3) == "xls")
                return L"application/vnd.ms-excel";
            else if (dataSize >= 512 && std::string_view(reinterpret_cast<const char*>(data + 512), 3) == "ppt")
                return L"application/vnd.ms-powerpoint";
        }
        const unsigned char EPUB_HEADER[] = { 0x50, 0x4B, 0x03, 0x04, 0x20, 0x00, 0x08, 0x00 };
        if (compareHeader(EPUB_HEADER, sizeof(EPUB_HEADER)))
            return L"application/epub+zip";
        const unsigned char MOBI_HEADER[] = { 0x4D, 0x4F, 0x42, 0x49 };
        if (compareHeader(MOBI_HEADER, sizeof(MOBI_HEADER)))
            return L"application/x-mobipocket-ebook";
        const unsigned char FB2_HEADER[] = { 0x3C, 0x66, 0x69, 0x63, 0x74, 0x69, 0x6F, 0x6E, 0x42, 0x6F, 0x6F, 0x6B };
        if (compareHeader(FB2_HEADER, sizeof(FB2_HEADER)))
            return L"application/fb2";
        const unsigned char RTF_HEADER[] = { 0x7B, 0x5C, 0x72, 0x74, 0x66, 0x31 };
        if (compareHeader(RTF_HEADER, sizeof(RTF_HEADER)))
            return L"application/rtf";
        const unsigned char INDESIGN_HEADER[] = { 0x06, 0x05, 0xED, 0xAB };
        if (compareHeader(INDESIGN_HEADER, sizeof(INDESIGN_HEADER)))
            return L"application/x-indesign";
        const unsigned char WPS_HEADER[] = { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 };
        if (compareHeader(WPS_HEADER, sizeof(WPS_HEADER)) && dataSize >= 512 && std::string_view(reinterpret_cast<const char*>(data + 512), 3) == "WPS")
            return L"application/vnd.ms-wps";

        // 压缩/归档类型
        const unsigned char ZIP_HEADER1[] = { 0x50, 0x4B, 0x03, 0x04 };
        const unsigned char ZIP_HEADER2[] = { 0x50, 0x4B, 0x05, 0x06 };
        const unsigned char ZIP_HEADER3[] = { 0x50, 0x4B, 0x07, 0x08 };
        if (compareHeader(ZIP_HEADER1, sizeof(ZIP_HEADER1)) ||
            compareHeader(ZIP_HEADER2, sizeof(ZIP_HEADER2)) ||
            compareHeader(ZIP_HEADER3, sizeof(ZIP_HEADER3)))
            return L"application/zip";
        const unsigned char RAR_HEADER1[] = { 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00 };
        const unsigned char RAR_HEADER2[] = { 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01 };
        if (compareHeader(RAR_HEADER1, sizeof(RAR_HEADER1)) || compareHeader(RAR_HEADER2, sizeof(RAR_HEADER2)))
            return L"application/x-rar-compressed";
        const unsigned char SEVEN_ZIP_HEADER[] = { 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C };
        if (compareHeader(SEVEN_ZIP_HEADER, sizeof(SEVEN_ZIP_HEADER)))
            return L"application/x-7z-compressed";
        const unsigned char GZIP_HEADER[] = { 0x1F, 0x8B, 0x08 };
        if (compareHeader(GZIP_HEADER, sizeof(GZIP_HEADER)))
            return L"application/gzip";
        const unsigned char BZIP2_HEADER[] = { 0x42, 0x5A, 0x68 };
        if (compareHeader(BZIP2_HEADER, sizeof(BZIP2_HEADER)))
            return L"application/x-bzip2";
        const unsigned char TAR_HEADER[] = { 0x75, 0x73, 0x74, 0x61, 0x72, 0x00, 0x30, 0x30 };
        if (compareHeader(TAR_HEADER, sizeof(TAR_HEADER)))
            return L"application/x-tar";
        const unsigned char ISO_HEADER[] = { 0x43, 0x44, 0x30, 0x30, 0x31 };
        if (dataSize >= 32768 && compareHeaderAtOffset(32768, ISO_HEADER, sizeof(ISO_HEADER)))
            return L"application/x-iso9660-image";
        const unsigned char ZSTD_HEADER[] = { 0x28, 0xB5, 0x2F, 0xFD };
        if (compareHeader(ZSTD_HEADER, sizeof(ZSTD_HEADER)))
            return L"application/zstd";
        const unsigned char LZ4_HEADER1[] = { 0x04, 0x22, 0x4D, 0x18 };
        const unsigned char LZ4_HEADER2[] = { 0x18, 0x4D, 0x22, 0x04 };
        if (compareHeader(LZ4_HEADER1, sizeof(LZ4_HEADER1)) || compareHeader(LZ4_HEADER2, sizeof(LZ4_HEADER2)))
            return L"application/x-lz4";
        const unsigned char XZ_HEADER[] = { 0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00 };
        if (compareHeader(XZ_HEADER, sizeof(XZ_HEADER)))
            return L"application/x-xz";
        const unsigned char CAB_HEADER[] = { 0x4D, 0x53, 0x43, 0x46 };
        if (compareHeader(CAB_HEADER, sizeof(CAB_HEADER)))
            return L"application/vnd.ms-cab-compressed";
        const unsigned char AR_HEADER[] = { 0x21, 0x3C, 0x61, 0x72, 0x63, 0x68, 0x3E };
        if (compareHeader(AR_HEADER, sizeof(AR_HEADER)))
            return L"application/x-archive";
        const unsigned char DMG_HEADER[] = { 0x78, 0x01, 0x73, 0x0D, 0x62, 0x6C, 0x65, 0x6E, 0x64, 0x65, 0x72 };
        if (compareHeader(DMG_HEADER, sizeof(DMG_HEADER)))
            return L"application/x-apple-diskimage";

        // 音频类型
        const unsigned char MP3_HEADER1[] = { 0xFF, 0xFB };
        const unsigned char MP3_HEADER2[] = { 0xFF, 0xF3 };
        const unsigned char MP3_HEADER3[] = { 0xFF, 0xF2 };
        if (compareHeader(MP3_HEADER1, sizeof(MP3_HEADER1)) ||
            compareHeader(MP3_HEADER2, sizeof(MP3_HEADER2)) ||
            compareHeader(MP3_HEADER3, sizeof(MP3_HEADER3)))
            return L"audio/mpeg";
        if (dataSize >= 12 &&
            data[0] == 0x52 && data[1] == 0x49 && data[2] == 0x46 && data[3] == 0x46 &&
            data[8] == 0x57 && data[9] == 0x41 && data[10] == 0x56 && data[11] == 0x45)
            return L"audio/wav";
        const unsigned char FLAC_HEADER[] = { 0x66, 0x4C, 0x61, 0x43 };
        if (compareHeader(FLAC_HEADER, sizeof(FLAC_HEADER)))
            return L"audio/flac";
        const unsigned char AAC_HEADER[] = { 0xFF, 0xF1, 0x00 };
        if (compareHeader(AAC_HEADER, sizeof(AAC_HEADER)))
            return L"audio/aac";
        const unsigned char OGG_HEADER[] = { 0x4F, 0x67, 0x67, 0x53 };
        if (compareHeader(OGG_HEADER, sizeof(OGG_HEADER)))
            return L"audio/ogg";
        if (dataSize >= 12 &&
            data[0] == 0x30 && data[1] == 0x26 && data[2] == 0xB2 && data[3] == 0x75 &&
            data[4] == 0x8E && data[5] == 0x66 && data[6] == 0xCF && data[7] == 0x11)
            return L"audio/x-ms-wma";
        const unsigned char OPUS_HEADER[] = { 0x4F, 0x70, 0x75, 0x73, 0x48, 0x65, 0x61, 0x64 };
        if (compareHeader(OPUS_HEADER, sizeof(OPUS_HEADER)))
            return L"audio/opus";
        const unsigned char WAVPACK_HEADER[] = { 0x77, 0x76, 0x70, 0x6B };
        if (compareHeader(WAVPACK_HEADER, sizeof(WAVPACK_HEADER)))
            return L"audio/x-wavpack";
        const unsigned char AIFF_HEADER[] = { 0x46, 0x4F, 0x52, 0x4D, 0x00, 0x00, 0x00, 0x20, 0x41, 0x49, 0x46, 0x46 };
        if (compareHeader(AIFF_HEADER, sizeof(AIFF_HEADER)))
            return L"audio/aiff";
        const unsigned char MIDI_HEADER[] = { 0x4D, 0x54, 0x68, 0x64 };
        if (compareHeader(MIDI_HEADER, sizeof(MIDI_HEADER)))
            return L"audio/midi";
        const unsigned char APE_HEADER[] = { 0x4D, 0x41, 0x43, 0x20 };
        if (compareHeader(APE_HEADER, sizeof(APE_HEADER)))
            return L"audio/ape";

        // 视频类型
        if (dataSize >= 12 && data[4] == 0x66 && data[5] == 0x74 && data[6] == 0x79 && data[7] == 0x70)
        {
            std::string_view ftyp(reinterpret_cast<const char*>(data + 4), 4);
            if (ftyp == "ftyp")
                return L"video/mp4";
        }
        if (dataSize >= 12 &&
            data[0] == 0x52 && data[1] == 0x49 && data[2] == 0x46 && data[3] == 0x46 &&
            data[8] == 0x41 && data[9] == 0x56 && data[10] == 0x49 && data[11] == 0x20)
            return L"video/avi";
        const unsigned char MKV_HEADER[] = { 0x1A, 0x45, 0xDF, 0xA3 };
        if (compareHeader(MKV_HEADER, sizeof(MKV_HEADER)))
            return L"video/x-matroska";
        const unsigned char FLV_HEADER[] = { 0x46, 0x4C, 0x56, 0x01 };
        if (compareHeader(FLV_HEADER, sizeof(FLV_HEADER)))
            return L"video/x-flv";
        if (dataSize >= 12 &&
            data[0] == 0x30 && data[1] == 0x26 && data[2] == 0xB2 && data[3] == 0x75 &&
            data[4] == 0x8E && data[5] == 0x66 && data[6] == 0xCF && data[7] == 0x11)
            return L"video/x-ms-wmv";
        if (dataSize >= 8 &&
            (data[0] == 0x6D && data[1] == 0x6F && data[2] == 0x6F && data[3] == 0x76 ||
                data[0] == 0x66 && data[1] == 0x74 && data[2] == 0x79 && data[3] == 0x70))
            return L"video/quicktime";
        const unsigned char WEBM_HEADER[] = { 0x1A, 0x45, 0xDF, 0xA3, 0x93, 0x42, 0x86, 0x81 };
        if (compareHeader(WEBM_HEADER, sizeof(WEBM_HEADER)))
            return L"video/webm";
        const unsigned char AVIF_HEADER[] = { 0x00, 0x00, 0x00, 0x20, 0x66, 0x74, 0x79, 0x70, 0x61, 0x76, 0x69, 0x66 };
        if (compareHeader(AVIF_HEADER, sizeof(AVIF_HEADER)))
            return L"image/avif";
        const unsigned char VOB_HEADER[] = { 0x00, 0x00, 0x01, 0xBA };
        if (compareHeader(VOB_HEADER, sizeof(VOB_HEADER)))
            return L"video/vob";
        const unsigned char MPEG_HEADER[] = { 0x00, 0x00, 0x01, 0xB3 };
        if (compareHeader(MPEG_HEADER, sizeof(MPEG_HEADER)))
            return L"video/mpeg";
        const unsigned char TS_HEADER[] = { 0x47, 0x40, 0x00 };
        if (compareHeader(TS_HEADER, sizeof(TS_HEADER)))
            return L"video/mp2t";
        const unsigned char RM_HEADER[] = { 0x2E, 0x72, 0x6D, 0x66 };
        if (compareHeader(RM_HEADER, sizeof(RM_HEADER)))
            return L"video/x-pn-realvideo";
        const unsigned char MOV_HEADER[] = { 0x66, 0x74, 0x79, 0x70, 0x71, 0x74, 0x20, 0x20 };
        if (compareHeader(MOV_HEADER, sizeof(MOV_HEADER)))
            return L"video/quicktime";

        // 字体文件类型
        const unsigned char TTF_HEADER[] = { 0x00, 0x01, 0x00, 0x00, 0x00 };
        if (compareHeader(TTF_HEADER, sizeof(TTF_HEADER)))
            return L"font/ttf";
        const unsigned char OTF_HEADER[] = { 0x4F, 0x54, 0x54, 0x4F };
        if (compareHeader(OTF_HEADER, sizeof(OTF_HEADER)))
            return L"font/otf";
        const unsigned char WOFF_HEADER[] = { 0x77, 0x4F, 0x46, 0x46 };
        if (compareHeader(WOFF_HEADER, sizeof(WOFF_HEADER)))
            return L"font/woff";
        const unsigned char WOFF2_HEADER[] = { 0x77, 0x4F, 0x46, 0x32 };
        if (compareHeader(WOFF2_HEADER, sizeof(WOFF2_HEADER)))
            return L"font/woff2";
        const unsigned char EOT_HEADER[] = { 0x4C, 0x50, 0x46, 0x46 };
        if (compareHeader(EOT_HEADER, sizeof(EOT_HEADER)))
            return L"application/vnd.ms-fontobject";
        const unsigned char SVG_FONT_HEADER[] = { 0x3C, 0x73, 0x76, 0x67, 0x20, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6F, 0x6E };
        if (compareHeader(SVG_FONT_HEADER, sizeof(SVG_FONT_HEADER)))
            return L"font/svg";
        const unsigned char TTC_HEADER[] = { 0x00, 0x01, 0x00, 0x00, 0x00, 0x02 };
        if (compareHeader(TTC_HEADER, sizeof(TTC_HEADER)))
            return L"font/collection";

        // 新增可执行/脚本格式
        const unsigned char ELF_HEADER[] = { 0x7F, 0x45, 0x4C, 0x46 }; // ELF可执行文件（Linux/Unix）
        if (compareHeader(ELF_HEADER, sizeof(ELF_HEADER)))
            return L"application/x-executable";
        const unsigned char MACHO_HEADER1[] = { 0xCA, 0xFE, 0xBA, 0xBE }; // Mach-O可执行文件（Mac/iOS）
        const unsigned char MACHO_HEADER2[] = { 0xBE, 0xBA, 0xFE, 0xCA };
        if (compareHeader(MACHO_HEADER1, sizeof(MACHO_HEADER1)) || compareHeader(MACHO_HEADER2, sizeof(MACHO_HEADER2)))
            return L"application/x-mach-binary";
        const unsigned char COM_HEADER[] = { 0x43, 0x4F, 0x4D }; // COM可执行文件（DOS）
        if (compareHeader(COM_HEADER, sizeof(COM_HEADER)))
            return L"application/x-dosexec";
        if (dataSize >= 2 && std::string(reinterpret_cast<const char*>(data), 2) == "::") // PowerShell脚本
            return L"application/x-powershell";
        if (dataSize >= 4 && std::string(reinterpret_cast<const char*>(data), 4) == "<?lua") // Lua脚本
            return L"text/x-lua";

        // 9. 数据库文件（新增：主流数据库格式）
        const unsigned char SQLITE_HEADER[] = { 0x53, 0x51, 0x4C, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6F, 0x72, 0x6D, 0x61, 0x74, 0x20, 0x33, 0x00 }; // SQLite数据库
        if (compareHeader(SQLITE_HEADER, sizeof(SQLITE_HEADER)))
            return L"application/x-sqlite3";
        const unsigned char ACCESS_HEADER[] = { 0x53, 0x74, 0x61, 0x6E, 0x64, 0x61, 0x72, 0x64, 0x20, 0x41, 0x43, 0x45, 0x20, 0x44, 0x42 }; // Access数据库
        if (compareHeader(ACCESS_HEADER, sizeof(ACCESS_HEADER)))
            return L"application/vnd.ms-access";
        const unsigned char MYSQL_HEADER[] = { 0x3D, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00 }; // MySQL数据库备份
        if (compareHeader(MYSQL_HEADER, sizeof(MYSQL_HEADER)))
            return L"application/x-mysql";
        const unsigned char PGSQL_HEADER[] = { 0x50, 0x47, 0x53, 0x51, 0x4C }; // PostgreSQL备份
        if (compareHeader(PGSQL_HEADER, sizeof(PGSQL_HEADER)))
            return L"application/x-pgsql";

        // 10. 3D模型文件（新增：主流3D格式）
        const unsigned char OBJ_HEADER[] = { 0x6F, 0x62, 0x6A }; // OBJ模型
        if (compareHeader(OBJ_HEADER, sizeof(OBJ_HEADER)))
            return L"model/obj";
        const unsigned char FBX_HEADER[] = { 0x4B, 0x61, 0x79, 0x64, 0x61, 0x20, 0x46, 0x42, 0x58 }; // FBX模型
        if (compareHeader(FBX_HEADER, sizeof(FBX_HEADER)))
            return L"model/fbx";
        const unsigned char STL_HEADER[] = { 0x73, 0x74, 0x6C, 0x61 }; // STL模型
        if (compareHeader(STL_HEADER, sizeof(STL_HEADER)))
            return L"model/stl";
        const unsigned char GLB_HEADER[] = { 0x67, 0x6C, 0x54, 0x46 }; // GLB模型（glTF二进制）
        if (compareHeader(GLB_HEADER, sizeof(GLB_HEADER)))
            return L"model/gltf-binary";

        // 11. 加密/证书文件（新增：安全相关格式）
        const unsigned char PEM_HEADER[] = { 0x2D, 0x2D, 0x2D, 0x2D, 0x2D }; // PEM证书/密钥
        if (compareHeader(PEM_HEADER, sizeof(PEM_HEADER)))
            return L"application/x-pem-file";
        const unsigned char DER_HEADER[] = { 0x30, 0x82 }; // DER证书
        if (compareHeader(DER_HEADER, sizeof(DER_HEADER)))
            return L"application/x-der";
        const unsigned char GPG_HEADER[] = { 0x85, 0x01, 0x02, 0x00 }; // GPG加密文件
        if (compareHeader(GPG_HEADER, sizeof(GPG_HEADER)))
            return L"application/gpg-encrypted";
        const unsigned char PKCS12_HEADER[] = { 0x30, 0x82, 0x00, 0x00 }; // PKCS12证书库
        if (compareHeader(PKCS12_HEADER, sizeof(PKCS12_HEADER)))
            return L"application/x-pkcs12";

        // 未知类型，返回默认二进制MIME
        return L"application/octet-stream";
    }

    const char* const codingMaps[] = {
        "0123456789ABCDEF",                              // 16
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",              // 32
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz", // 58
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", // 62
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", // 64
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", // 64url
        "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstu", //85
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~\"", //91
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~-"  //91url
    };
    enum MapIdx { BASE16 = 0, BASE32 = 1, BASE58 = 2, BASE62 = 3, BASE64 = 4, BASE64URL = 5, BASE85 = 6, BASE91 = 7, BASE91URL = 8 };
    bool BaseXToBinary(BYTEBUFFER_PTR binaryPtr, uint64_t base, bool isUrl) {
        if (!binaryPtr || binaryPtr->empty() || base < 2) return false;
        BYTEBUFFER& input = *binaryPtr;
        BYTEBUFFER result, cleanInput;
        size_t padding = 0;

        if (base == 85) {
            for (unsigned char c : input) if (c != '=') cleanInput.push_back(c);
            size_t inputLen = cleanInput.size();
            if (inputLen == 0) { *binaryPtr = std::move(result); return true; }

            uint32_t acc = 0;
            int nchars = 0;
            const unsigned char* p = cleanInput.data();
            while (inputLen--) {
                unsigned char c = *p++;
                if (c == 'z' && nchars == 0) {
                    result.insert(result.end(), 4, 0x00);
                    continue;
                }

                int val = c - '!';
                if (val < 0 || val >= 85) {
                    val = -1;
                    for (int i = 0; i < 85 && val == -1; i++)
                        if (codingMaps[BASE85][i] == c) val = i;
                    if (val == -1) continue;
                }

                uint64_t temp = (uint64_t)acc * 85 + val;
                if (temp > 0xFFFFFFFF) { acc = 0; nchars = 0; continue; }
                acc = (uint32_t)temp;
                if (++nchars == 5) {
                    result.push_back((acc >> 24) & 0xFF);
                    result.push_back((acc >> 16) & 0xFF);
                    result.push_back((acc >> 8) & 0xFF);
                    result.push_back(acc & 0xFF);
                    acc = 0; nchars = 0;
                }
            }

            if (nchars > 0) {
                for (int i = nchars; i < 5; i++) acc = acc * 85 + 84;
                size_t byteCount = nchars - 1;
                if (byteCount >= 1) result.push_back((acc >> 24) & 0xFF);
                if (byteCount >= 2) result.push_back((acc >> 16) & 0xFF);
                if (byteCount >= 3) result.push_back((acc >> 8) & 0xFF);
                if (byteCount >= 4) result.push_back(acc & 0xFF);
            }
            *binaryPtr = std::move(result);
            return !binaryPtr->empty() || input.empty();
        }

        const char* codingMap = nullptr;
        size_t mapLen = 0;
        switch (base) {
        case 16: codingMap = codingMaps[BASE16]; mapLen = 16; break;
        case 32: codingMap = codingMaps[BASE32]; mapLen = 32; break;
        case 58: codingMap = codingMaps[BASE58]; mapLen = 58; break;
        case 62: codingMap = codingMaps[BASE62]; mapLen = 62; break;
        case 64: codingMap = isUrl ? codingMaps[BASE64URL] : codingMaps[BASE64]; mapLen = 64; break;
        case 91: codingMap = isUrl ? codingMaps[BASE91URL] : codingMaps[BASE91]; mapLen = 91; break;
        default: return false;
        }
        if (mapLen != base) return false;

        for (unsigned char c : input) {
            if (c == '=') padding++;
            else cleanInput.push_back(c);
        }
        bool isUrlMode = isUrl && (base == 64 || base == 32);
        if (isUrlMode) {
            padding = 0;
            size_t mod = (base == 64) ? 4 : 8;
            size_t padNeeded = (mod - (cleanInput.size() % mod)) % mod;
            cleanInput.insert(cleanInput.end(), padNeeded, '=');
        }
        else if ((base == 64 && padding > 2) || (base == 32 && padding > 6) || (base == 16 && padding > 0)) {
            return false;
        }

        std::vector<uint64_t> num(1, 0);
        for (unsigned char c : cleanInput) {
            int val = -1;
            for (size_t i = 0; i < mapLen && val == -1; ++i)
                if (codingMap[i] == c) val = static_cast<int>(i);
            if (val == -1) return false;

            uint64_t carry = val;
            for (auto& digit : num) {
                uint64_t temp = digit * base + carry;
                digit = temp & 0xFFFFFFFFFFFF;
                carry = temp >> 48;
            }
            if (carry > 0) num.push_back(carry);
        }

        while (!num.empty()) {
            uint64_t remainder = 0;
            std::vector<uint64_t> newNum;
            for (auto it = num.rbegin(); it != num.rend(); ++it) {
                uint64_t temp = (remainder << 48) | *it;
                *it = temp / 256;
                remainder = temp % 256;
                if (!newNum.empty() || *it != 0) newNum.insert(newNum.begin(), *it);
            }
            num = std::move(newNum);
            result.push_back(static_cast<unsigned char>(remainder));
        }

        std::reverse(result.begin(), result.end());
        if (result.empty() && !cleanInput.empty()) result.push_back(0);

        if (base == 64 || base == 32) {
            size_t expectedBytes = (cleanInput.size() * (base == 64 ? 6 : 5)) / 8;
            if (result.size() > expectedBytes) result.resize(expectedBytes);
        }

        *binaryPtr = std::move(result);
        return true;
    }
    bool BinaryToBaseX(BYTEBUFFER_PTR binaryPtr, uint64_t base, bool isUrl) {
        if (!binaryPtr || binaryPtr->empty() || base < 2) return false;
        BYTEBUFFER& input = *binaryPtr;
        BYTEBUFFER result;

        if (base == 85) {
            size_t inputLen = input.size();
            if (inputLen == 0) { *binaryPtr = std::move(result); return true; }

            size_t pos = 0;
            while (pos < inputLen) {
                uint32_t acc = 0;
                size_t byteCount = 0;
                for (; byteCount < 4 && pos < inputLen; ++byteCount, ++pos)
                    acc = (acc << 8) | static_cast<uint8_t>(input[pos]);

                if (byteCount == 4 && acc == 0) {
                    result.push_back('z');
                    continue;
                }

                char chars[5] = { 0 };
                int charIdx = 4;
                uint64_t bigTemp = static_cast<uint64_t>(acc);
                for (int i = 0; i < 5; i++) {
                    chars[charIdx--] = codingMaps[BASE85][bigTemp % 85];
                    bigTemp /= 85;
                }

                size_t charCount = byteCount + 1;
                result.insert(result.end(), chars, chars + charCount);
            }
            *binaryPtr = std::move(result);
            return true;
        }

        const char* codingMap = nullptr;
        size_t mapLen = 0;
        switch (base) {
        case 16: codingMap = codingMaps[BASE16]; mapLen = 16; break;
        case 32: codingMap = codingMaps[BASE32]; mapLen = 32; break;
        case 58: codingMap = codingMaps[BASE58]; mapLen = 58; break;
        case 62: codingMap = codingMaps[BASE62]; mapLen = 62; break;
        case 64: codingMap = isUrl ? codingMaps[BASE64URL] : codingMaps[BASE64]; mapLen = 64; break;
        case 91: codingMap = isUrl ? codingMaps[BASE91URL] : codingMaps[BASE91]; mapLen = 91; break;
        default: return false;
        }
        if (mapLen != base) return false;

        std::vector<uint64_t> num;
        for (unsigned char byte : input) {
            uint64_t carry = byte;
            for (auto& digit : num) {
                uint64_t temp = digit * 256 + carry;
                digit = temp & 0xFFFFFFFFFFFF;
                carry = temp >> 48;
            }
            if (carry > 0) num.push_back(carry);
        }
        if (num.empty()) num.push_back(0);

        while (!num.empty()) {
            uint64_t remainder = 0;
            std::vector<uint64_t> newNum;
            for (auto it = num.rbegin(); it != num.rend(); ++it) {
                uint64_t temp = (remainder << 48) | *it;
                *it = temp / base;
                remainder = temp % base;
                if (!newNum.empty() || *it != 0) newNum.insert(newNum.begin(), *it);
            }
            num = std::move(newNum);
            result.push_back(static_cast<unsigned char>(codingMap[remainder]));
        }

        std::reverse(result.begin(), result.end());

        size_t paddingCount = 0;
        switch (base) {
        case 16: paddingCount = result.size() % 2 == 1 ? 1 : 0; if (paddingCount) result.insert(result.begin(), '0'); break;
        case 32: paddingCount = (8 - (result.size() % 8)) % 8; break;
        case 64: paddingCount = (4 - (result.size() % 4)) % 4; break;
        default: paddingCount = 0; break;
        }

        bool isUrlMode = isUrl && (base == 64 || base == 32 || base == 91);
        if (!isUrlMode && (base == 32 || base == 64))
            result.insert(result.end(), paddingCount, '=');

        if (result.empty()) result.push_back(codingMap[0]);
        *binaryPtr = std::move(result);
        return true;
    }

    static inline size_t gcd(size_t a, size_t b) {
        while (b != 0) {
            size_t temp = b;
            b = a % b;
            a = temp;
        }
        return a;
    }

    std::wstring GetFileNameFromPath(std::wstring path) {
        if (path.empty()) return L"";

        // 移除末尾的路径分隔符
        while (!path.empty() && (path.back() == L'/' || path.back() == L'\\')) {
            path.pop_back();
        }
        if (path.empty()) return L"";

        // 找到最后一个路径分隔符的位置
        size_t lastSlash = path.find_last_of(L"/\\");
        if (lastSlash == std::wstring::npos) {
            // 没有路径分隔符，整个就是文件名
            return path;
        }

        // 提取最后一个路径分隔符之后的部分
        std::wstring filename = path.substr(lastSlash + 1);

        // 如果提取到的部分为空，返回空字符串
        if (filename.empty()) return L"";

        return filename;
    }
    std::wstring GetFilePathWithoutName(std::wstring path) {
        if (path.empty()) return L"";

        // 第一步：将所有反斜杠 \ 替换为正斜杠 /，统一路径分隔符
        for (size_t i = 0; i < path.size(); ++i) {
            if (path[i] == L'\\') {
                path[i] = L'/';
            }
        }

        // 第二步：移除末尾的所有路径分隔符（此时只剩正斜杠）
        while (!path.empty() && path.back() == L'/') {
            path.pop_back();
        }
        if (path.empty()) return L"";

        // 第三步：找到最后一个路径分隔符的位置
        size_t lastSlash = path.find_last_of(L'/');
        if (lastSlash == std::wstring::npos) {
            // 没有路径分隔符，说明只有文件名没有路径，返回空字符串
            return L"";
        }

        // 第四步：提取最后一个路径分隔符及之前的部分，并确保末尾带正斜杠
        std::wstring dirPath = path.substr(0, lastSlash + 1);

        return dirPath;
    }

    template<typename T>
    uint64_t GetPtrAddress(const T* ptr) {
        return static_cast<uint64_t>(reinterpret_cast<uintptr_t>(ptr));
    }

    template<typename T>
    T* GetPtrByAddress(uint64_t address) {
        static_assert(sizeof(uintptr_t) <= sizeof(uint64_t), "uintptr_t size exceeds uint64_t");
        return reinterpret_cast<T*>(address);
    }

    class JavaScript;
    class JavaScriptMethod;

#include "../include/cjsapibase.h"

    void DeleteInstance(JavaScript* instance);
    JavaScript* NewInstance();
    bool InitInstance(JavaScript* instance, JSRuntime* InjsRuntime = nullptr, JSContext* InjsContext = nullptr);
    JavaScriptMethod* GetInstanceMethodThis(JavaScript* instance);
    JSContext* GetContextThis(JavaScript* instance);
    JSRuntime* GetRuntimeThis(JavaScript* instance);
    void ChildSystemExitInstance(JavaScript* instance);
    bool IsAliveInstance(JavaScript* instance);

    void* jsRtValidValue = (void*)0x00000001;
    void* jsCtxValidValue = (void*)0x00000002;

    bool SetRuntimeOpaque(JSRuntime* rt, void* ptr = nullptr) {
        if (rt == nullptr) {
            return false;
        }
        JS_SetRuntimeOpaque(rt, ptr);
        return true;
    }
    bool CheckRuntimeOpaque(JSRuntime* rt, void* ptr = nullptr) {
        if (rt == nullptr) {
            return false;
        }
        void* current_opaque = JS_GetRuntimeOpaque(rt);
        return (current_opaque == ptr);
    }
    bool SetContextOpaque(JSContext* ctx, void* ptr = nullptr) {
        if (ctx == nullptr) {
            return false;
        }
        JS_SetContextOpaque(ctx, ptr);
        return true;
    }
    bool CheckContextOpaque(JSContext* ctx, void* ptr = nullptr) {
        if (ctx == nullptr) {
            return false;
        }
        void* current_opaque = JS_GetContextOpaque(ctx);
        return (current_opaque == ptr);
    }
    void SafeFreeRuntime(JSRuntime* rt) {
        if (rt == nullptr) {
            return;
        }
        JS_FreeRuntime(rt);
    }
    template<typename T>
    bool IsInstance(T* ptr) {
        // 1. 空指针/0xdd标记指针直接判无效
        if (ptr == nullptr) return false;

#ifdef _WIN64
        uint64_t ptr_val = reinterpret_cast<uint64_t>(ptr);
        if (ptr_val == 0xdddddddddddddddd) return false;
#else
        uint32_t ptr_val = reinterpret_cast<uint32_t>(ptr);
        if (ptr_val == 0xdddddddd) return false;
#endif

        // 2. 仅支持类类型
        static_assert(std::is_class_v<T>, "IsInstance only supports class types!");

        // 3. 核心校验：
        // - _CrtIsMemoryBlock 是唯一能判定「地址是否已释放」的公开接口
        //   只要返回false，说明地址已释放/不属于有效堆块（无论指针值是不是原地址）
        if (!_CrtIsMemoryBlock(ptr, sizeof(T), nullptr, nullptr, nullptr)) {
            return false;
        }

        // 4. 兜底：堆指针合法性+内存可访问性校验
        return _CrtIsValidHeapPointer(ptr) && _CrtIsValidPointer(ptr, sizeof(T), true);
    }
    void AdvSleep(double timeout) {
        timeBeginPeriod(1);
        LONGLONG delay100Ns = static_cast<LONGLONG>(timeout * 10000.0);
        LARGE_INTEGER dueTime = { .QuadPart = -delay100Ns };
        HANDLE hTimer = CreateWaitableTimerW(NULL, TRUE, NULL);
        if (hTimer == NULL) return;
        if (SetWaitableTimer(hTimer, &dueTime, 0, NULL, NULL, FALSE)) {
            WaitForSingleObject(hTimer, INFINITE);
        }
        CloseHandle(hTimer);
        timeEndPeriod(1);
    }
    std::string GetFullPrototypeName(JSContext* ctx, JSValue jsv) {

        if (!ctx || JS_IsUndefined(jsv) || JS_IsNull(jsv)) {
            return "";
        }

        JSValue proto = JS_GetPrototype(ctx, jsv);
        if (JS_IsException(proto) || JS_IsUndefined(proto)) {
            JS_FreeValue(ctx, proto);
            return "";
        }

        JSValue globalObj = JS_GetGlobalObject(ctx);
        if (JS_IsException(globalObj)) {
            JS_FreeValue(ctx, proto);
            JS_FreeValue(ctx, globalObj);
            return "";
        }

        JSValue objectProto = JS_GetPropertyStr(ctx, globalObj, "Object");
        JS_FreeValue(ctx, globalObj);
        if (JS_IsException(objectProto) || JS_IsUndefined(objectProto)) {
            JS_FreeValue(ctx, proto);
            JS_FreeValue(ctx, objectProto);
            return "";
        }

        JSValue protoObj = JS_GetPropertyStr(ctx, objectProto, "prototype");
        JS_FreeValue(ctx, objectProto);
        if (JS_IsException(protoObj) || JS_IsUndefined(protoObj)) {
            JS_FreeValue(ctx, proto);
            JS_FreeValue(ctx, protoObj);
            return "";
        }

        JSValue objToString = JS_GetPropertyStr(ctx, protoObj, "toString");
        JS_FreeValue(ctx, protoObj);
        if (JS_IsException(objToString) || !JS_IsFunction(ctx, objToString)) {
            JS_FreeValue(ctx, proto);
            JS_FreeValue(ctx, objToString);
            return "";
        }

        JSValue toStringResult = JS_Call(ctx, objToString, proto, 0, nullptr);
        if (JS_IsException(toStringResult) || !JS_IsString(toStringResult)) {
            JS_FreeValue(ctx, proto);
            JS_FreeValue(ctx, objToString);
            JS_FreeValue(ctx, toStringResult);
            return "";
        }

        std::string result = "";
        const char* str = JS_ToCString(ctx, toStringResult);
        if (str) {
            result = std::string(str);
            JS_FreeCString(ctx, str);
        }

        JS_FreeValue(ctx, proto);
        JS_FreeValue(ctx, objToString);
        JS_FreeValue(ctx, toStringResult);

        return result;
    }
    std::string GetPrototypeName(JSContext* ctx, JSValue jsv) {
        std::string fullName = GetFullPrototypeName(ctx, jsv);
        if (fullName.empty()) {
            return "";
        }

        std::string result = "";
        const char* str = fullName.c_str();
        const char* prefix = "[object ";
        const size_t prefix_len = strlen(prefix);

        const char* start = strstr(str, prefix);
        if (start) {
            start += prefix_len;
            const char* end = strchr(start, ']');
            if (end && end > start) {
                result = std::string(start, end - start);
            }
        }

        return result;
    }

    class JSVInst {
    public:
        JSVInst(JSValue* InJsv) {
            if (InJsv == nullptr) {
                jsv = JS_UNDEFINED;
            }
            else {
                jsv = *InJsv;
            }
        }
        JSVInst(JSValue InJsv) {
            jsv = InJsv;
        }
        ~JSVInst() {
            jsv = { 0 };
        }
        JSValue get() {
            return jsv.load();
        }
        void add() {
            if (refCount.load() < ULLONG_MAX) refCount.fetch_add(1, std::memory_order_relaxed);
        }
        void remove() {
            if (refCount.load() > 0) refCount.fetch_sub(1, std::memory_order_acq_rel);
        }
        ULL read() {
            return refCount.load();
        }
        void qjs_add(int ref = 1) {
            if (qjsRefCount.load() < ULLONG_MAX) qjsRefCount.fetch_add(static_cast<size_t>(ref), std::memory_order_relaxed);
        }
        void qjs_remove(int ref = 1) {
            if (qjsRefCount.load() > 0) qjsRefCount.fetch_sub(static_cast<size_t>(ref), std::memory_order_acq_rel);
        }
        ULL qjs_read() {
            return qjsRefCount.load();
        }
    private:
        std::atomic<JSValue> jsv = {};
        std::atomic<ULL> refCount = 0;
        std::atomic<ULL> qjsRefCount = 0;
    };
    class JSV {
    public:
        void* operator new(size_t) = delete;
        void operator delete(void*) = delete;
        void* operator new[](size_t) = delete;
        void operator delete[](void*) = delete;
        JSV() {
            try {
                jsvi = new JSVInst(nullptr);
            }
            catch (...) {
                throw std::runtime_error("[JSV] Failed to new.");
            }

            jsvi->add();
        }
        JSV(const JSV& other) {
            this->jsvi = other.jsvi;
            this->ctx = other.ctx;
            if (this->jsvi != nullptr) {
                this->jsvi->add();
            }
        }
        JSV(JSV&& other) noexcept {
            this->jsvi = other.jsvi;
            this->ctx = other.ctx;
            other.jsvi = nullptr;
            other.ctx = nullptr;
        }
        JSV& operator=(const JSV& other) {
            if (this == &other || *this == other) return *this;

            if (this->jsvi == other.jsvi && this->ctx != other.ctx) {
                return *this;
            }

            this->update(this->jsvi, this->ctx);

            other.jsvi->add();
            this->jsvi = other.jsvi;
            this->ctx = other.ctx;

            return *this;
        }
        JSV& operator=(const JSValue& other) {

            try {
                jsvi = new JSVInst(other);
            }
            catch (...) {
                throw std::runtime_error("[JSV] Failed to new.");
            }

            jsvi->add();

            return *this;
        }
        bool operator==(const JSV& other) const {
            return this->ctx == other.ctx && this->jsvi == other.jsvi;
        }
        JSV(JSContext* InCtx, JSValue* InJsv, JSVInst** InJsvi = nullptr) {
            if (InCtx == nullptr) {
                throw std::runtime_error("[JSV] The 'JSContext* InCtx' cannot be nullptr.");
            }
            if (InJsv == nullptr) {
                throw std::runtime_error("[JSV] The 'JSValue* InJsv' cannot be nullptr.");
            }
            ctx = InCtx;
            if (InJsvi == nullptr) {
                try {
                    jsvi = new JSVInst(InJsv);
                }
                catch (...) {
                    throw std::runtime_error("[JSV] Failed to new.");
                }
            }
            else {
                jsvi = *InJsvi;
            }

            jsvi->add();
        }
        JSV(JSContext* InCtx, JSValue InJsv, JSVInst** InJsvi = nullptr) {
            if (InCtx == nullptr) {
                throw std::runtime_error("[JSV] The 'JSContext* InCtx' cannot be nullptr.");
            }
            ctx = InCtx;
            if (InJsvi == nullptr) {
                try {
                    jsvi = new JSVInst(InJsv);
                }
                catch (...) {
                    throw std::runtime_error("[JSV] Failed to new.");
                }
            }
            else {
                jsvi = *InJsvi;
            }

            jsvi->add();
        }
        JSV(JSValue* InJsv) {
            if (InJsv == nullptr) {
                throw std::runtime_error("[JSV] The 'JSValue* InJsv' cannot be nullptr.");
            }
            try {
                jsvi = new JSVInst(InJsv);
            }
            catch (...) {
                throw std::runtime_error("[JSV] Failed to new.");
            }

            jsvi->add();
        }
        JSV(JSValue InJsv) {
            try {
                jsvi = new JSVInst(InJsv);
            }
            catch (...) {
                throw std::runtime_error("[JSV] Failed to new.");
            }

            jsvi->add();
        }
        ~JSV() {
            update(jsvi, ctx);
        }
        ULL set(int strongRef = 0) {
            if (strongRef != 0) {
                if (strongRef > 0)
                    jsvi->qjs_add(strongRef);
                else
                    jsvi->qjs_remove(-strongRef);
            }
            return jsvi->qjs_read();
        }
        JSV& cset(int strongRef = 0) {
            set(strongRef);
            return *this;
        }
        JSValue get(long long dupRef = 0) const {
            if (jsvi == nullptr) return JS_UNDEFINED;
            if (dupRef > 0) {
                for (long long i = 0; i < dupRef; i++) {
                    //扒开底层代码发现这个函数单纯新增了u.ptr的引用计数，返回和入参为相同JSValue
                    if (ctx != nullptr && !JS_IsUndefined((jsvi->get())) && !JS_IsNull((jsvi->get()))) JS_DupValue(ctx, (jsvi->get()));
                }
            }
            else if (dupRef < 0) {
                for (long long i = 0; i < -dupRef; i++) {
                    //扒开底层代码发现这个函数单纯减少了u.ptr的引用计数，直到减少到0才释放
                    if (ctx != nullptr && !JS_IsUndefined((jsvi->get())) && !JS_IsNull((jsvi->get()))) JS_FreeValue(ctx, (jsvi->get()));
                }
            }
            return (jsvi->get());
        }
        JSV& cget(long long dupRef = 0) {
            if (jsvi == nullptr) return *this;
            if (dupRef > 0) {
                for (long long i = 0; i < dupRef; i++) {
                    //扒开底层代码发现这个函数单纯新增了u.ptr的引用计数，返回和入参为相同JSValue
                    if (ctx != nullptr) JS_DupValue(ctx, (jsvi->get()));
                }
            }
            else if (dupRef < 0) {
                for (long long i = 0; i < -dupRef; i++) {
                    //扒开底层代码发现这个函数单纯减少了u.ptr的引用计数，直到减少到0才释放
                    if (ctx != nullptr) JS_FreeValue(ctx, (jsvi->get()));
                }
            }
            return *this;
        }
        ULL tell() {
            return jsvi->read();
        }
        bool isAutoRelease() const {
            return this->ctx != nullptr && this->jsvi != nullptr && !JS_IsUndefined((this->get())) && !JS_IsNull((this->get()));
        }
        bool isValid() const {
            return this->jsvi != nullptr && !JS_IsUndefined((this->get())) && !JS_IsNull((this->get()));
        }
        JSContext* getCtx() {
            return ctx;
        }
    private:
        JSVInst* jsvi = nullptr;
        JSContext* ctx = nullptr;
        void update(JSVInst* jsvi, JSContext* ctx) const {
            if (jsvi != nullptr) {
                jsvi->remove();
                if (jsvi->read() == 0) {
                    if (ctx != nullptr && !JS_IsUndefined((jsvi->get())) && !JS_IsNull((jsvi->get()))) {
                        for (ULL i = 0; i < jsvi->qjs_read(); i++) {
                            JS_FreeValue(ctx, (jsvi->get()));
                        }
                    }
                    delete jsvi;
                }
                jsvi = nullptr;
            }
        }
    };

    class ThreadInst {
    public:
        ThreadInst(std::thread t) {
            thread = std::move(t);
            handle = (HANDLE)thread.native_handle();
        }
        std::thread* get() {
            return &thread;
        }
        HANDLE getHandle() {
            return handle;
        }
        void setHandle(HANDLE hd) {
            handle = hd;
        }
        void add() {
            if (refCount.load() < ULLONG_MAX) refCount.fetch_add(1, std::memory_order_relaxed);
        }
        void remove() {
            if (refCount.load() > 0) refCount.fetch_sub(1, std::memory_order_acq_rel);
        }
        ULL read() {
            return refCount.load();
        }
    private:
        std::thread thread;
        HANDLE handle;
        std::atomic<ULL> refCount = 0;
    };
    class Thread {
    public:
        void* operator new(size_t) = delete;
        void operator delete(void*) = delete;
        void* operator new[](size_t) = delete;
        void operator delete[](void*) = delete;
        Thread() {
            threadInst = nullptr;
        }
        Thread(std::thread t) {
            try {
                threadInst = new ThreadInst(std::move(t));
            }
            catch (...) {
                throw std::runtime_error("[Thread] Failed to new.");
            }

            threadInst->add();
        }
        Thread(const Thread& other) {
            this->threadInst = other.threadInst;
            if (this->threadInst != nullptr) {
                this->threadInst->add();
            }
        }
        Thread(Thread&& other) noexcept {
            this->threadInst = other.threadInst;
            other.threadInst = nullptr;
        }
        ~Thread() {
            update();
        }
        Thread& operator=(const Thread& other) {

            if (this == &other || *this == other) return *this;
            this->update();
            this->threadInst = other.threadInst;
            if (this->threadInst != nullptr) {
                this->threadInst->add();
            }

            return *this;
        }
        bool operator==(const Thread& other) const {
            return this->threadInst == other.threadInst;
        }
        std::thread* get() const {
            if (threadInst == nullptr) return nullptr;
            return threadInst->get();
        }
        HANDLE getHandle() const {
            if (threadInst == nullptr) return INVALID_HANDLE_VALUE;
            return threadInst->getHandle();
        }
        bool isValid() const {
            return this->threadInst != nullptr;
        }
        HANDLE join() {
            if (joinable()) {
                DWORD threadId = GetThreadId(threadInst->getHandle());
                threadInst->setHandle(OpenThread(
                    THREAD_QUERY_INFORMATION | THREAD_TERMINATE | SYNCHRONIZE,
                    FALSE,
                    threadId
                ));
                (*(threadInst->get())).join();
            }
            return threadInst->getHandle();
        }
        HANDLE detach() {
            if (joinable()) {
                threadInst->setHandle(OpenThread(
                    THREAD_QUERY_INFORMATION | THREAD_TERMINATE | SYNCHRONIZE,
                    FALSE,
                    GetThreadId(threadInst->getHandle())
                ));
                (*(threadInst->get())).detach();
            }
            return threadInst->getHandle();
        }
        bool joinable() {
            return (*(threadInst->get())).joinable();
        }
        bool isQuit() {
            if (getHandle() == NULL || getHandle() == INVALID_HANDLE_VALUE) {
                return true;
            }
            return (WaitForSingleObject(getHandle(), 0) == WAIT_OBJECT_0);
        }
    private:
        ThreadInst* threadInst = nullptr;
        void update() {
            if (threadInst == nullptr) return;
            threadInst->remove();
            if (threadInst->read() == 0) {
                HANDLE hThread = threadInst->getHandle();
                if (hThread != INVALID_HANDLE_VALUE) {
                    DWORD exitCode = 0;
                    if (GetExitCodeThread(hThread, &exitCode)) {
                        if (exitCode == STILL_ACTIVE) {
                            DWORD waitResult = WaitForSingleObject(hThread, 1000);
                            if (waitResult != WAIT_OBJECT_0) {
                                TerminateThread(hThread, 0);
                            }
                            std::thread* t = threadInst->get();
                            if (t->joinable()) {
                                t->join();
                            }
                        }
                    }
                    CloseHandle(hThread);
                }
                delete threadInst;
            }
            threadInst = nullptr;
        }
    };

    typedef struct FORMDATAITEM {
        JSV key = JS_UNDEFINED;
        JSV value = JS_UNDEFINED;
        std::string contentType = "";
        std::string name = "";
        std::string fileName = "";
        BYTEBUFFER binary = {};
    } *FORMDATAITEM_PTR;
    typedef ordered_multimap<std::string, FORMDATAITEM> FORMDATA, * FORMDATA_PTR;

    struct Task {
        JSV task = JSV();
        JSV thisVal = JSV();
        JSV flags = {};
        std::vector<JSV> args = {};
    };

    struct TaskData {
        bool isValid = false;
        Task task = {};
        JSV ret = JSV();
    };

    struct JSINFO {
        bool isValid = false;
        bool isSuccess = false;
        JSV result = JS_UNDEFINED;
        std::wstring message = L"";
        GMMT detail = {};
        GMMT output = {};
        std::wstring errorFront = L"";
        std::vector<std::wstring> errorStack = {};
    };
    JSINFO EvalInstance(JavaScript* instance, const std::wstring& code, const std::wstring& fileName);
    void ApplyExtension(JavaScript* instance) {
        if (!extensionList.empty()) {
            for (auto& [name, path] : extensionList) {

                FileController* fc = NewInstance<FileController>(path, apppath(0));
                if (fc == nullptr) continue;
                if (!fc->exists()) {
                    delete fc;
                    continue;
                }

                BYTEBUFFER binary = {};
                bool status = fc->read(0, fc->size(), &binary);
                delete fc;
                if (!status) continue;
                std::wstring code = GetTextFromBYTEBUFFER(&binary);
                if (IsCodeEmpty(code)) continue;

                JSINFO result = EvalInstance(instance, code, name);
                if (!result.isValid) continue;
                if (result.isSuccess) continue;

                CreateOutput(L"Extension:" + result.errorFront + L":" + result.message + L"\n", GetColorValue(L"Error"));
                OutputStack(result.errorStack);

            }
        }
    }

    std::wstring GetFormData(BYTEBUFFER_PTR bodyPtr, const FORMDATA_PTR formData) {
        if (!bodyPtr || !formData) return L"";
        std::srand(static_cast<unsigned>(std::time(nullptr)));
        static const char alphanum_bound[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        std::string boundary = "----WebKitFormBoundary";
        for (int i = 0; i < 16; ++i) boundary += alphanum_bound[std::rand() % (sizeof(alphanum_bound) - 1)];
        std::wstring wboundary(boundary.begin(), boundary.end());
        auto WriteMultipartField = [](BYTEBUFFER& body, const std::string& b, const std::wstring& fn, const std::wstring& fnm, const std::wstring& mt, const BYTEBUFFER& fd) {
            std::string h = "--" + b + "\r\nContent-Disposition: form-data; name=\"" + wstringToString(fn) + "\"";
            if (!fnm.empty()) h += "; filename=\"" + wstringToString(fnm) + "\"";
            h += "\r\n";
            if (!mt.empty() && mt != L"application/octet-stream") h += "Content-Type: " + wstringToString(mt) + "\r\n";
            h += "\r\n";
            body.insert(body.end(), h.begin(), h.end());
            body.insert(body.end(), fd.begin(), fd.end());
            body.insert(body.end(), '\r');
            body.insert(body.end(), '\n');
            };
        auto GetExtAndRandName = [](const std::wstring& mt) -> std::wstring {
            static const std::unordered_map<std::wstring, std::wstring> MIME_EXT_MAP = {
                {L"image/jpeg",L"jpg"},{L"image/png",L"png"},{L"image/gif",L"gif"},{L"image/bmp",L"bmp"},{L"image/webp",L"webp"},
                {L"application/pdf",L"pdf"},{L"application/msword",L"doc"},{L"application/vnd.openxmlformats-officedocument.wordprocessingml.document",L"docx"},
                {L"application/vnd.ms-excel",L"xls"},{L"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",L"xlsx"},
                {L"application/vnd.ms-powerpoint",L"ppt"},{L"application/vnd.openxmlformats-officedocument.presentationml.presentation",L"pptx"},
                {L"text/plain",L"txt"},{L"text/html",L"html"},{L"text/css",L"css"},{L"text/javascript",L"js"},{L"application/json",L"json"},
                {L"audio/mpeg",L"mp3"},{L"audio/wav",L"wav"},{L"video/mp4",L"mp4"},{L"video/avi",L"avi"},{L"video/mpeg",L"mpeg"},{L"video/quicktime",L"mov"}
            };
            std::wstring ext = L"dat";
            auto it = MIME_EXT_MAP.find(mt);
            if (it != MIME_EXT_MAP.end()) ext = it->second;
            static const wchar_t alphanum_name[] = L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            std::wstring name; name.reserve(16);
            for (int i = 0; i < 16; ++i) name += alphanum_name[std::rand() % (sizeof(alphanum_name) / sizeof(wchar_t) - 1)];
            if (!ext.empty()) name += L"." + ext;
            return name;
            };
        BYTEBUFFER& body = *bodyPtr;
        for (const auto& pair : *formData) {
            const std::wstring& fieldName = stringToWstring(pair.first);
            FORMDATAITEM fd = pair.second;
            std::wstring fileName = stringToWstring(fd.fileName);
            std::wstring mimeType = GetMIMETypeFromBYTEBUFFER(&fd.binary);
            if (fileName.empty() && mimeType != L"application/octet-stream") fileName = GetExtAndRandName(mimeType);
            WriteMultipartField(body, boundary, fieldName, fileName, mimeType, fd.binary);
        }
        std::string endBoundary = "--" + boundary + "--\r\n\r\n";
        body.insert(body.end(), endBoundary.begin(), endBoundary.end());
        return L"multipart/form-data; boundary=" + wboundary;
    }

    class XMLHttpRequest {
    public:
        struct XMLHttpRequestUpload {
            XHRPROGRESSCALLBACK onloadstart = nullptr;
            XHRPROGRESSCALLBACK onprogress = nullptr;
            XHRPROGRESSCALLBACK onload = nullptr;
            XHRPROGRESSCALLBACK onloadend = nullptr;
            XHRPROGRESSCALLBACK onabort = nullptr;
            XHRPROGRESSCALLBACK onerror = nullptr;
            XHRPROGRESSCALLBACK ontimeout = nullptr;
        };

        ~XMLHttpRequest() noexcept { release(); }

        XHRReadyState readyState = XHRReadyState::UNSENT;
        int status = 0;
        std::wstring statusText = L"";
        BYTEBUFFER response = {};
        std::wstring responseType = L"";
        std::wstring responseText = L"";
        double timeout = 0.0;
        uint64_t loaded = 0;
        uint64_t total = 0;
        uint64_t uploadLoaded = 0;
        uint64_t uploadTotal = 0;
        bool isSended = false;

        NONECALLBACK onreadystatechange = nullptr;
        NONECALLBACK onload = nullptr;
        XHRPROGRESSCALLBACK onloadend = nullptr;
        XHRPROGRESSCALLBACK onabort = nullptr;
        XHRPROGRESSCALLBACK onprogress = nullptr;
        XHRPROGRESSCALLBACK onerror = nullptr;
        XHRPROGRESSCALLBACK ontimeout = nullptr;
        NONECALLBACK onrelease = nullptr;
        XHRPROGRESSCALLBACK onloadstart = nullptr;
        XHRPROGRESSCALLBACK onheadersreceived = nullptr;

        XMLHttpRequestUpload upload;

        bool isOpened() { return readyState != XHRReadyState::UNSENT; }
        bool isResponsed() { return readyState == XHRReadyState::HEADERS_RECEIVED || readyState == XHRReadyState::LOADING || readyState == XHRReadyState::DONE; }

        void open(const std::wstring& InMethod, const std::wstring& InUrl, bool InIsAsync = true, const std::wstring& InAuthUser = L"", const std::wstring& InAuthPassword = L"") noexcept {
            if (readyState != XHRReadyState::UNSENT) { abort(true); onClean(false); }
            method = InMethod.empty() ? L"GET" : ToUpLetters(std::wstring(InMethod));
            urlInfo = GetURLINFOFromUrl(InUrl);
            isAsync = InIsAsync;
            authUser = InAuthUser;
            authPassword = InAuthPassword;
            requestHeaders = { { L"User-Agent",L"CGI.JS/" + AY_CJS_CPP_VW }, { L"Accept", L"*/*" }, { L"Accept-Encoding", L"gzip" }, { L"Accept-Language", GetAcceptLanguageHeader() } };
            isSended = false;
            changeReadyState(XHRReadyState::OPENED);
        }

        void preProcess() noexcept {
            if (!authUser.empty() && !authPassword.empty()) {
                std::wstring auth = authUser + L":" + authPassword;
                BYTEBUFFER bin = ToBinary(auth);
                bool encodeOk = BinaryToBaseX(&bin, 64, false);
                if (encodeOk) {
                    setRequestHeader(L"Authorization", L"Basic " + stringToWstring(GetTextFromBinarySafely(&bin)));
                }
            }
        }
        bool send() { return send(nullptr, nullptr); }
        bool send(const BYTEBUFFER& body) noexcept { bodyTemp = body; return send(&bodyTemp, nullptr); }
        bool send(BYTEBUFFER_PTR bodyPtr) { return send(bodyPtr, nullptr); }
        bool send(const FORMDATA& formData) { formDataTemp = formData; return send(nullptr, &formDataTemp); }
        bool send(FORMDATA_PTR formDataPtr) { return send(nullptr, formDataPtr); }
        bool send(BYTEBUFFER_PTR bodyPtrG, FORMDATA_PTR formDataPtr = nullptr) {
            try {
                if (!isOpened() || isSended)
                    return false;

                isSended = true;
                preProcess();

                BYTEBUFFER_PTR bodyPtr = bodyPtrG;

                if (urlInfo.protocol == L"blob:") {
                    if (bodyPtr == nullptr && formDataPtr == nullptr && method == L"GET" && URLDataList.count(urlInfo.href)) {
                        BLOB_PTR bp = &URLDataList[urlInfo.href];
                        responseText = GetTextFromBYTEBUFFER(&(bp->data));
                        responseType = stringToWstring(bp->mimeType);
                        response = bp->data;
                        onFinish();
                        return true;
                    }
                    else {
                        event.errorCode = NULL;
                        event.errorMessage = L"";
                        onError();
                        return false;
                    }
                }

                hSession = WinHttpOpen(
                    requestHeaders.count(L"User-Agent") ? requestHeaders[L"User-Agent"].c_str() : L"",
                    WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                    WINHTTP_NO_PROXY_NAME,
                    WINHTTP_NO_PROXY_BYPASS,
                    0
                );

                if (!hSession) {
                    DWORD dwError = GetLastError();
                    event.errorCode = dwError;
                    event.errorMessage = GetErrorMessageFromErrorCode(dwError);
                    onError();
                    WinHttpCloseHandleSafely(hSession);
                    if (onloadend) onloadend(event);
                    return false;
                }

                if (timeout > 0) {
                    DWORD timeoutMs = (DWORD)timeout;
                    WinHttpSetTimeouts(hSession, timeoutMs, timeoutMs, timeoutMs, timeoutMs);
                }

                hConnect = WinHttpConnect(
                    hSession,
                    urlInfo.hostname.c_str(),
                    urlInfo.port,
                    0
                );

                if (!hConnect) {
                    DWORD dwError = GetLastError();
                    event.errorCode = dwError;
                    event.errorMessage = GetErrorMessageFromErrorCode(dwError);

                    if (dwError == ERROR_WINHTTP_TIMEOUT) {
                        if (ontimeout) ontimeout(event);
                        uploadEvent.errorCode = dwError;
                        uploadEvent.errorMessage = event.errorMessage;
                        if (upload.ontimeout) upload.ontimeout(uploadEvent);
                    }

                    onError();
                    WinHttpCloseHandleSafely(hConnect);
                    WinHttpCloseHandleSafely(hSession);

                    uploadEvent = {};
                    if (upload.onloadend) upload.onloadend(uploadEvent);
                    return false;
                }

                hRequest = WinHttpOpenRequest(
                    hConnect,
                    method.c_str(),
                    urlInfo.path.c_str(),
                    NULL,
                    WINHTTP_NO_REFERER,
                    WINHTTP_DEFAULT_ACCEPT_TYPES,
                    urlInfo.protocol == L"https:" ? WINHTTP_FLAG_SECURE : 0
                );

                if (!hRequest) {
                    DWORD dwError = GetLastError();
                    event.errorCode = dwError;
                    event.errorMessage = GetErrorMessageFromErrorCode(dwError);

                    if (dwError == ERROR_WINHTTP_TIMEOUT) {
                        if (ontimeout) ontimeout(event);
                        uploadEvent.errorCode = dwError;
                        uploadEvent.errorMessage = event.errorMessage;
                        if (upload.ontimeout) upload.ontimeout(uploadEvent);
                    }

                    uploadEvent.errorCode = dwError;
                    uploadEvent.errorMessage = event.errorMessage;
                    if (upload.onerror) upload.onerror(uploadEvent);

                    onError();
                    WinHttpCloseHandleSafely(hRequest);
                    WinHttpCloseHandleSafely(hConnect);
                    WinHttpCloseHandleSafely(hSession);

                    uploadEvent = {};
                    if (upload.onloadend) upload.onloadend(uploadEvent);
                    return false;
                }

                LPVOID requestBody = NULL;
                DWORD requestBodyLength = 0, totalLength = 0;

                if (method != L"GET" && method != L"HEAD") {
                    if (formDataPtr) {
                        std::wstring contentType = GetFormData(&bodyTemp, formDataPtr);
                        bodyPtr = &bodyTemp;
                        if (!requestHeaders.count(L"Content-Type"))
                            requestHeaders[L"Content-Type"] = contentType;
                        requestBody = bodyPtr->data();
                        requestBodyLength = (DWORD)bodyPtr->size();
                        totalLength = requestBodyLength;
                    }
                    else if (bodyPtr) {
                        if (!requestHeaders.count(L"Content-Type"))
                            requestHeaders[L"Content-Type"] = GetMIMETypeFromBYTEBUFFER(bodyPtr);
                        requestBody = bodyPtr->data();
                        requestBodyLength = (DWORD)bodyPtr->size();
                        totalLength = requestBodyLength;
                    }
                }

                std::wstring requestHeadersWtring = GetHeadersFromHeaderList(requestHeaders);

                BOOL bSendRequest = WinHttpSendRequest(
                    hRequest,
                    requestHeadersWtring.c_str(),
                    -1,
                    WINHTTP_NO_REQUEST_DATA,
                    0,
                    totalLength,
                    0
                );

                if (!bSendRequest) {
                    DWORD dwError = GetLastError();
                    event.errorCode = dwError;
                    event.errorMessage = GetErrorMessageFromErrorCode(dwError);

                    uploadEvent.errorCode = dwError;
                    uploadEvent.errorMessage = event.errorMessage;
                    if (upload.onerror) upload.onerror(uploadEvent);

                    onError();
                    WinHttpCloseHandleSafely(hRequest);
                    WinHttpCloseHandleSafely(hConnect);
                    WinHttpCloseHandleSafely(hSession);

                    uploadEvent = {};
                    if (upload.onloadend) upload.onloadend(uploadEvent);
                    return false;
                }

                if (onloadstart)
                    onloadstart(event);

                bool uploadSuccess = false;
                if (totalLength > 0) {
                    uploadEvent = {};
                    uploadEvent.total = totalLength;
                    uploadLoaded = 0;
                    uploadTotal = totalLength;

                    if (upload.onloadstart)
                        upload.onloadstart(uploadEvent);

                    DWORD totalWritten = 0;
                    const DWORD chunkSize = 4096;

                    while (totalWritten < totalLength && !isAborted) {
                        DWORD toWrite = std::min(chunkSize, totalLength - totalWritten);
                        BYTE* buf = (BYTE*)requestBody + totalWritten;
                        DWORD wrote = 0;

                        if (!WinHttpWriteData(hRequest, buf, toWrite, &wrote) || wrote == 0) {
                            DWORD dwError = GetLastError();
                            event.errorCode = dwError;
                            event.errorMessage = GetErrorMessageFromErrorCode(dwError);

                            uploadEvent.errorCode = dwError;
                            uploadEvent.errorMessage = event.errorMessage;
                            if (upload.onerror) upload.onerror(uploadEvent);

                            onError();
                            WinHttpCloseHandleSafely(hRequest);
                            WinHttpCloseHandleSafely(hConnect);
                            WinHttpCloseHandleSafely(hSession);

                            uploadEvent = {};
                            if (upload.onloadend) upload.onloadend(uploadEvent);
                            return false;
                        }

                        totalWritten += wrote;
                        uploadEvent.loaded = totalWritten;
                        uploadLoaded = totalWritten;

                        if (upload.onprogress)
                            upload.onprogress(uploadEvent);
                    }

                    if (!isAborted && totalWritten == totalLength) {
                        uploadSuccess = true;
                        if (upload.onload)
                            upload.onload(uploadEvent);
                    }
                }

                if (upload.onloadend)
                    upload.onloadend(uploadEvent);

                if (isAborted) {
                    uploadEvent = {};
                    if (upload.onabort) upload.onabort(uploadEvent);
                    if (upload.onloadend) upload.onloadend(uploadEvent);

                    WinHttpCloseHandleSafely(hRequest);
                    WinHttpCloseHandleSafely(hConnect);
                    WinHttpCloseHandleSafely(hSession);
                    if (onloadend) onloadend(event);
                    return false;
                }

                BOOL bReceiveResponse = WinHttpReceiveResponse(hRequest, NULL);
                if (!bReceiveResponse) {
                    DWORD dwError = GetLastError();
                    event.errorCode = dwError;
                    event.errorMessage = GetErrorMessageFromErrorCode(dwError);
                    onError();
                    WinHttpCloseHandleSafely(hRequest);
                    WinHttpCloseHandleSafely(hConnect);
                    WinHttpCloseHandleSafely(hSession);
                    if (onloadend) onloadend(event);
                    return false;
                }

                changeReadyState(XHRReadyState::HEADERS_RECEIVED);
                if (onheadersreceived)
                    onheadersreceived(event);

                DWORD dwStatusCode = 0;
                DWORD dwStatusCodeSize = sizeof(dwStatusCode);
                if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                    WINHTTP_HEADER_NAME_BY_INDEX, &dwStatusCode, &dwStatusCodeSize, WINHTTP_NO_HEADER_INDEX)) {
                    status = (int)dwStatusCode;
                    statusText = GetResponseMessageFromResponseCode(status);
                }
                else {
                    DWORD dwError = GetLastError();
                    event.errorCode = dwError;
                    event.errorMessage = GetErrorMessageFromErrorCode(dwError);
                    onError();
                    WinHttpCloseHandleSafely(hRequest);
                    WinHttpCloseHandleSafely(hConnect);
                    WinHttpCloseHandleSafely(hSession);
                    if (onloadend) onloadend(event);
                    return false;
                }

                responseHeaders.clear();
                DWORD index = 0;
                while (!isAborted) {
                    DWORD len = 0;
                    if (!WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF,
                        WINHTTP_HEADER_NAME_BY_INDEX, NULL, &len, &index)) {
                        DWORD err = GetLastError();
                        if (err == ERROR_NO_MORE_ITEMS)
                            break;
                        if (err != ERROR_INSUFFICIENT_BUFFER)
                            break;
                    }
                    if (len == 0)
                        break;

                    std::vector<wchar_t> buf(len / 2 + 1);
                    if (!WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF,
                        WINHTTP_HEADER_NAME_BY_INDEX, buf.data(), &len, &index)) {
                        break;
                    }

                    std::wstring s(buf.data());
                    size_t p;
                    while ((p = s.find(L"\r\n")) != std::wstring::npos) {
                        std::wstring line = s.substr(0, p);
                        s.erase(0, p + 2);

                        size_t col = line.find(L':');
                        if (col == std::wstring::npos)
                            continue;

                        std::wstring k = line.substr(0, col);
                        std::wstring v = line.substr(col + 1);

                        size_t ks = k.find_first_not_of(L" \t");
                        size_t ke = k.find_last_not_of(L" \t");
                        if (ks == std::wstring::npos || ke == std::wstring::npos)
                            continue;
                        k = k.substr(ks, ke - ks + 1);

                        size_t vs = v.find_first_not_of(L" \t");
                        size_t ve = v.find_last_not_of(L" \t");
                        if (vs != std::wstring::npos && ve != std::wstring::npos)
                            v = v.substr(vs, ve - vs + 1);

                        responseHeaders[k] = v;
                    }
                    index++;
                }

                if (method != L"HEAD") {
                    response.clear();
                    const DWORD chunk = 4096;
                    std::vector<BYTE> buf(chunk);
                    loaded = 0;
                    total = 0;
                    XHRPROGRESSEVENT pe{};

                    std::wstring cl = getResponseHeader(L"Content-Length");
                    if (!cl.empty()) {
                        total = _wtoi64(cl.c_str());
                        pe.total = total;
                    }

                    changeReadyState(XHRReadyState::LOADING);

                    DWORD avail = 0;
                    while (!isAborted && WinHttpQueryDataAvailable(hRequest, &avail) && avail > 0) {
                        if (avail > buf.size())
                            buf.resize(avail);
                        DWORD read = 0;
                        if (!WinHttpReadData(hRequest, buf.data(), avail, &read) || read == 0)
                            break;
                        response.insert(response.end(), buf.begin(), buf.begin() + read);
                        loaded += read;
                        pe.loaded = loaded;
                        if (onprogress)
                            onprogress(pe);
                    }
                }

                UnGzip(&response);

                responseText = GetTextFromBYTEBUFFER(&response);
                responseType = getMimeTypeFromContentType(
                    mimeTypeOverride.empty() ?
                    (responseHeaders.count(L"Content-Type") ? responseHeaders[L"Content-Type"] : GetMIMETypeFromBYTEBUFFER(&response))
                    : mimeTypeOverride
                );

                onFinish();
                return true;
            }
            catch (...) {
                WinHttpCloseHandleSafely(hRequest);
                WinHttpCloseHandleSafely(hConnect);
                WinHttpCloseHandleSafely(hSession);

                event.errorCode = -1;
                event.errorMessage = L"Unknown exception occurred";
                if (onerror) onerror(event);

                uploadEvent.errorCode = -1;
                uploadEvent.errorMessage = L"Unknown exception occurred";
                if (upload.onerror) upload.onerror(uploadEvent);

                uploadEvent = {};
                if (upload.onloadend) upload.onloadend(uploadEvent);
                if (onloadend) onloadend(event);
                return false;
            }
        }

        void abort(bool mode = false) noexcept {
            if (isAborted) return;
            isAborted = true;
            WinHttpCloseHandleSafely(hRequest);
            WinHttpCloseHandleSafely(hConnect);
            WinHttpCloseHandleSafely(hSession);

            uploadEvent = {};
            if (upload.onabort) upload.onabort(uploadEvent);
            if (upload.onloadend) upload.onloadend(uploadEvent);

            if (!mode) {
                XHRReadyState oldState = readyState;
                readyState = XHRReadyState::DONE;
                status = 0;
                statusText = L"";

                if (onabort) {
                    event.loaded = loaded;
                    event.total = _wtoi64(getResponseHeader(L"Content-Length").c_str());
                    onabort(event);
                }
                onClean(true);
                if (onreadystatechange && oldState != XHRReadyState::DONE)
                    onreadystatechange();
                if (onloadend)
                    onloadend(event);
            }
        }

        bool setRequestHeader(const std::wstring& headerName, const std::wstring& headerValue) noexcept {
            if (!isOpened()) return false;
            if (requestHeaders.count(headerName)) {
                requestHeaders[headerName] += L", " + headerValue;
            }
            else {
                requestHeaders[headerName] = headerValue;
            }
            return true;
        }
        bool hasRequestHeader(const std::wstring& headerName) noexcept {
            if (!isOpened()) return false;
            return requestHeaders.count(headerName) > 0;
        }
        bool deleteRequestHeader(const std::wstring& headerName) noexcept {
            if (!isOpened()) return false;
            return requestHeaders.count(headerName) && requestHeaders.erase(headerName);
        }
        GMT* getRequestHeadersPtr() noexcept {
            if (!isOpened()) return nullptr;
            return &requestHeaders;
        }
        GMT getRequestHeaders() noexcept {
            if (!isOpened()) return {};
            return requestHeaders;
        }

        std::wstring getResponseHeader(const std::wstring& headerName) noexcept {
            if (!isResponsed()) return L"";
            return responseHeaders.count(headerName) ? responseHeaders[headerName] : L"";
        }
        GMT* getResponseHeadersPtr() noexcept {
            if (!isResponsed()) return nullptr;
            return &responseHeaders;
        }
        GMT getResponseHeaders() noexcept {
            if (!isResponsed()) return {};
            return responseHeaders;
        }

        void overrideMimeType(std::wstring mimeType) { mimeTypeOverride = mimeType; }
        void release() noexcept {
            abort(true);
            onClean(false);
            onreadystatechange = onload = nullptr;
            onloadend = onabort = onprogress = onerror = ontimeout = nullptr;
            onrelease = nullptr;
            onloadstart = onheadersreceived = nullptr;
            upload = {};
            if (onrelease) onrelease();
        }

    private:
        std::wstring method = L"GET";
        URLINFO urlInfo = {};
        bool isAsync = true;
        std::wstring authUser = L"";
        std::wstring authPassword = L"";
        GMT requestHeaders = {};
        GMT responseHeaders = {};
        BYTEBUFFER bodyTemp = {};
        FORMDATA formDataTemp = {};
        XHRPROGRESSEVENT event = {};
        XHRPROGRESSEVENT uploadEvent = {};

        HINTERNET hSession = NULL;
        HINTERNET hConnect = NULL;
        HINTERNET hRequest = NULL;
        bool isAborted = false;
        bool isTimeout = false;
        std::wstring mimeTypeOverride = L"";

        void onClean(bool preserveState = false) {
            if (!preserveState) {
                readyState = XHRReadyState::UNSENT;
                status = 0;
                statusText = L"";
            }
            response.clear();
            responseText.clear();
            responseType.clear();
            timeout = 0.0;
            loaded = total = uploadLoaded = uploadTotal = 0;
            method = L"GET";
            urlInfo = {};
            isAsync = true;
            authUser.clear();
            authPassword.clear();
            requestHeaders.clear();
            responseHeaders.clear();
            bodyTemp.clear();
            formDataTemp.clear();
            event = {};
            uploadEvent = {};
            isTimeout = false;
            mimeTypeOverride.clear();
            if (!preserveState) isAborted = false;
            hSession = hConnect = hRequest = NULL;
        }

        void changeReadyState(XHRReadyState newState) {
            if (readyState == newState || isAborted) return;
            readyState = newState;
            if (onreadystatechange) onreadystatechange();
        }

        void onError() {
            if (status == 0) {
                readyState = XHRReadyState::DONE;
                statusText = L"";
            }
            if (onerror) onerror(event);
        }

        void onFinish() {
            changeReadyState(XHRReadyState::DONE);
            if (onload) onload();
            WinHttpCloseHandleSafely(hRequest);
            WinHttpCloseHandleSafely(hConnect);
            WinHttpCloseHandleSafely(hSession);
            if (onloadend) onloadend(event);
        }

        bool WinHttpCloseHandleSafely(IN HINTERNET& hInternet) {
            if (hInternet == NULL) return false;
            BOOL status = WinHttpCloseHandle(hInternet);
            hInternet = NULL;
            return static_cast<bool>(status);
        }
    };

    struct ThreadData {
        Thread thread;
        void* shared;
    };

    enum PromiseState : int {
        PENDING = 0,
        FULFILLED = 1,
        REJECTED = 2,
    };
    struct Promise {
        Promise& operator=(const Promise& other) {
            if (this == &other || *this == other) return *this;
            this->promise = other.promise;
            this->resolve = other.resolve;
            this->reject = other.reject;
            this->Resolve = other.Resolve;
            this->Reject = other.Reject;
            return *this;
        }
        bool operator==(const Promise& other) const {
            return this->promise == other.promise &&
                this->resolve == other.resolve &&
                this->reject == other.reject;
        }
        JSV promise = JSV(JS_UNDEFINED);
        JSV resolve = JSV(JS_UNDEFINED);
        JSV reject = JSV(JS_UNDEFINED);
        std::function<void(JSContext* ctx, JSV arg)> Resolve = nullptr;
        std::function<void(JSContext* ctx, JSV arg)> Reject = nullptr;
    };
    struct PromiseCallback {
        JSV onFulfilled;
        JSV onRejected;
        JSV onFinally;
        Promise returnPromise;
        bool isFinally;
    };
    struct PromiseData {
        bool isValid = false;
        bool isChanged = false;
        bool isProcessedSelf = false;
        int state = PromiseState::PENDING;
        ULL callbackId = 0;
        JSV promise = {};
        JSV resolve = {};
        JSV reject = {};
        vector_lock<JSV> result = {};
        vector_lock<JSV> error = {};
        vector_lock<PromiseCallback> callbacks;
    };

    struct CJSHeapData {
        void* data = nullptr;
        CJSSize size = 0;
        CJSTAG tag = 0;
    };

    struct JSMData {

        bool isQuit = false;
        bool isAutoLoadModules = false;

        bool isMessageLoopRunning = false;

        JSRuntime* rt = nullptr;
        JSContext* ctx = nullptr;

        JSContext* parentCtx = nullptr;

        JavaScript* js = nullptr;
        JavaScriptMethod* jsm = nullptr;

        vector_lock<JSV> releaseList = {};
        unordered_map_lock<ULL, FileController*> fileControllerList = {};
        unordered_map_lock<ULL, JavaScript*> executeJsList = {};
        unordered_map_lock<ULL, FORMDATA> formDataList = {};
        unordered_map_lock<ULL, XMLHttpRequest*> networkHttpList = {};

        bool isUpdating = false;
        unordered_map_lock<ULL, ThreadData> timeoutList = {};
        vector_lock<Thread> threadList = {};

        unordered_map_lock<ULL, PromiseData> promiseList = {};

        bool isRunningTask = false;
        unordered_map_lock<ULL, Task> taskList = {};
        unordered_map_lock<ULL, TaskData> runnedTaskList = {};

        vector_lock<HMODULE> hModuleList = {};
        unordered_map_lock<ULL, JSV> hModuleCJSValueList = {};

        unordered_map_lock<ULL, CJSArgumentPackage> argumentPackageList = {};
        unordered_map_lock<ULL, CJSHeapData> cjsByteDataList = {};

    };
    static unordered_map_lock<JSContext*, JSMData> jsinfo = {};
    bool GetData(JSContext* ctx, JSMData* jsmd) {
        if (ctx == nullptr || jsmd == nullptr) return false;
        auto it = jsinfo.find(ctx);
        if (it != jsinfo.end()) {
            *jsmd = it->second;
            return true;
        }
        return false;
    }
    bool RemoveData(JSContext* ctx) {
        if (ctx == nullptr) return false;
        auto it = jsinfo.find(ctx);
        if (it != jsinfo.end()) {
            jsinfo.erase(it);
            return true;
        }
        return false;
    }
    bool SetData(JSContext* ctx, JSMData* jsmd) {
        if (ctx == nullptr || jsmd == nullptr) return false;
        jsinfo[ctx] = *jsmd;
        return true;
    }
    bool GetData(JSContext* ctx, JSMData** jsmd) {
        if (ctx == nullptr || jsmd == nullptr) return false;
        auto it = jsinfo.find(ctx);
        if (it != jsinfo.end()) {
            *jsmd = &(it->second);
            return true;
        }
        return false;
    }
    bool RemoveSameJSValue(JSContext* ctx, std::vector<JSValue>& jsvLst) {
        if (jsvLst.empty()) {
            return true;
        }

        try {
            std::unordered_set<uintptr_t> seen_addrs;
            std::vector<JSValue> unique_jsvs;

            for (const auto& val : jsvLst) {
                if (!JS_VALUE_HAS_REF_COUNT(val)) {
                    continue;
                }

                uintptr_t addr = (uintptr_t)JS_VALUE_GET_PTR(val);
                if (addr == 0) {
                    continue;
                }

                if (seen_addrs.find(addr) == seen_addrs.end()) {
                    seen_addrs.insert(addr);
                    unique_jsvs.push_back(val);
                }
            }
            jsvLst.swap(unique_jsvs);
            return true;
        }
        catch (...) {
            return false;
        }
    }
    std::string FormatPath(std::string path) {
        std::replace(path.begin(), path.end(), '\\', '/');
        return path;
    }
    std::wstring FormatPath(std::wstring path) {
        std::replace(path.begin(), path.end(), L'\\', L'/');
        return path;
    }
    BOOL ExecuteCmdCommand(const std::wstring& command, std::wstring& output, DWORD* exitCode = nullptr)
    {
        output.clear();

        HANDLE hReadPipeOut = NULL, hWritePipeOut = NULL;
        HANDLE hReadPipeErr = NULL, hWritePipeErr = NULL;
        SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };

        if (!CreatePipe(&hReadPipeOut, &hWritePipeOut, &sa, 0) ||
            !CreatePipe(&hReadPipeErr, &hWritePipeErr, &sa, 0))
        {
            if (exitCode) *exitCode = GetLastError();
            CloseHandle(hReadPipeOut);
            CloseHandle(hWritePipeOut);
            CloseHandle(hReadPipeErr);
            CloseHandle(hWritePipeErr);
            return FALSE;
        }

        STARTUPINFOW si = { sizeof(STARTUPINFOW) };
        si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        si.hStdOutput = hWritePipeOut;
        si.hStdError = hWritePipeErr;
        si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

        std::wstring cmdLine = L"cmd.exe /U /c " + command;

        PROCESS_INFORMATION pi = { 0 };
        BOOL bCreate = CreateProcessW(
            NULL, (LPWSTR)cmdLine.c_str(), NULL, NULL, TRUE,
            CREATE_UNICODE_ENVIRONMENT,
            NULL, NULL, &si, &pi
        );

        if (!bCreate)
        {
            if (exitCode) *exitCode = GetLastError();
            CloseHandle(hReadPipeOut);
            CloseHandle(hWritePipeOut);
            CloseHandle(hReadPipeErr);
            CloseHandle(hWritePipeErr);
            return FALSE;
        }

        CloseHandle(hWritePipeOut);
        CloseHandle(hWritePipeErr);

        const DWORD BYTE_BUFFER_SIZE = 4096;
        std::vector<BYTE> byteBuffer(BYTE_BUFFER_SIZE);
        DWORD dwRead = 0;
        std::vector<BYTE> totalBytes;

        while (ReadFile(hReadPipeOut, byteBuffer.data(), BYTE_BUFFER_SIZE, &dwRead, NULL) && dwRead > 0)
        {
            totalBytes.insert(totalBytes.end(), byteBuffer.begin(), byteBuffer.begin() + dwRead);
        }

        while (ReadFile(hReadPipeErr, byteBuffer.data(), BYTE_BUFFER_SIZE, &dwRead, NULL) && dwRead > 0)
        {
            totalBytes.insert(totalBytes.end(), byteBuffer.begin(), byteBuffer.begin() + dwRead);
        }

        if (!totalBytes.empty() && totalBytes.size() % 2 == 0)
        {
            output.assign(reinterpret_cast<WCHAR*>(totalBytes.data()), totalBytes.size() / 2);
        }

        size_t pos = 0;
        while ((pos = output.find(L"\r\n", pos)) != std::wstring::npos)
        {
            output.replace(pos, 2, L"\n");
            pos += 1;
        }
        WaitForSingleObject(pi.hProcess, INFINITE);
        DWORD cmdExitCode = 0;
        GetExitCodeProcess(pi.hProcess, &cmdExitCode);
        if (exitCode) *exitCode = cmdExitCode;

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        CloseHandle(hReadPipeOut);
        CloseHandle(hReadPipeErr);

        return (cmdExitCode == 0);
    }
    static JSV CallFunction(JSContext* ctx, JSV func, JSV thisVal, std::vector<JSV> args, bool isAsync = false, bool isWait = true);
    static JSV CallFunction(JSContext* ctx, JSV func, JSV thisVal, int argc, JSValueConst* argv, bool isAsync = false, bool isWait = true);

    template<typename T>
    struct is_simple_type : std::integral_constant<bool, std::is_fundamental_v<T> || std::is_pointer_v<T> || std::is_enum_v<T>> {};
    template<typename RetType, typename... Args>
    bool CallLibraryFunction(HMODULE hm, const std::string& funcName, RetType& ret, Args&&... args) {
        using FuncType = RetType(*)(std::remove_cv_t<std::remove_reference_t<Args>>...);
        FuncType func = reinterpret_cast<FuncType>(GetProcAddress(hm, funcName.c_str()));
        if (!func) {
            ret = RetType{};
            return false;
        }

        try {
            if constexpr ((is_simple_type<std::remove_reference_t<Args>>::value && ...)) {
                ret = func(args...);
            }
            else {
                ret = func(std::forward<Args>(args)...);
            }
            return true;
        }
        catch (...) {
            ret = RetType{};
            return false;
        }
    }

    static std::unordered_map<std::string, std::unordered_map<std::string, std::string>> allowedGenerateAlgorithm = {
        // -------------------------- AES 对称加密算法（密钥生成） --------------------------
        {"AES-GCM", {
            {"name", ""},
            {"length", ""}
        }},
        {"AES-CBC", {
            {"name", ""},
            {"length", ""}
        }},
        {"AES-CTR", {
            {"name", ""},
            {"length", ""}
        }},
        {"AES-KW", {
            {"name", ""},
            {"length", ""}
        }},
        // 新增：ChaCha20-Poly1305（密钥生成）
        {"ChaCha20-Poly1305", {
            {"name", ""}  // 仅需name参数，密钥长度固定256位
        }},

        // -------------------------- RSA 非对称算法（密钥生成） --------------------------
        {"RSA-OAEP", {
            {"name", ""},                  // 必需：算法名称
            {"modulusLength", ""},         // 必需：模数长度（2048/4096）
            {"publicExponent", ""},        // 必需：公钥指数（通常为65537）
            {"hash", ""}                   // 必需：哈希算法
        }},
        {"RSA-PSS", {
            {"name", ""},
            {"modulusLength", ""},
            {"publicExponent", ""},
            {"hash", ""}
        }},
        {"RSASSA-PKCS1-v1_5", {
            {"name", ""},
            {"modulusLength", ""},
            {"publicExponent", ""},
            {"hash", ""}
        }},

        // -------------------------- 椭圆曲线算法（密钥生成） --------------------------
        {"ECDSA", {
            {"name", ""},                  // 必需：算法名称
            {"namedCurve", ""},            // 必需：曲线名称（P-256/P-384/P-521）
            {"hash", "a"}                   // 必需：哈希算法（ECDSA生成密钥需指定）
        }},
        {"ECDH", {
            {"name", ""},
            {"namedCurve", ""}
        }},
        {"Ed25519", {
            {"name", ""}
        }},
        {"X25519", {
            {"name", ""}
        }},

        // -------------------------- HMAC 算法（密钥生成） --------------------------
        {"HMAC", {
            {"name", ""},                  // 必需：算法名称
            {"hash", ""},                  // 必需：哈希算法
            {"length", "a"}                // 可选：length（HMAC密钥长度），值为'a'
        }}
    };
    static std::unordered_map<std::string, std::unordered_map<std::string, std::unordered_map<std::string, std::string>>> allowedImportAlgorithm = {
        // -------------------------- raw 格式（二进制原始数据） --------------------------
        {"raw", {
            // AES 对称密钥（raw格式）
            {"AES-GCM", {
                {"name", ""},          // 必需：算法名称
                {"length", ""}         // 必需：密钥长度（验证与密钥数据长度匹配）
            }},
            {"AES-CBC", {
                {"name", ""},
                {"length", ""}
            }},
            {"AES-CTR", {
                {"name", ""},
                {"length", ""}
            }},
            {"AES-KW", {
                {"name", ""},
                {"length", ""}
            }},
        // ChaCha20-Poly1305（raw格式）
        {"ChaCha20-Poly1305", {
            {"name", ""}  // 仅需name，密钥长度固定256位无需验证
        }},
        // HMAC 密钥（raw格式）
        {"HMAC", {
            {"name", ""},          // 必需：算法名称
            {"hash", ""},          // 必需：哈希算法
            {"length", "a"}        // 可选：HMAC密钥长度，值为'a'
        }},
        // HKDF（raw格式）- 核心配置
        {"HKDF", {
            {"name", ""},          // 必需：算法名称（固定为HKDF）
            {"hash", ""},          // 必需：哈希算法（如SHA-256、SHA-512）
            {"salt", "a"},         // 可选：盐值，值为'a'（替换原o）
            {"info", "a"}          // 可选：上下文信息，值为'a'（替换原o）
        }},
        // 新增：PBKDF2（raw格式）
        {"PBKDF2", {
            {"name", ""},          // 必需：算法名称
            {"hash", ""},          // 必需：哈希算法
            {"salt", ""},          // 必需：盐值（PBKDF2必需）
            {"iterations", ""},    // 必需：迭代次数
            {"length", "a"},       // 可选：派生密钥长度，值为'a'
            {"info", "a"}          // 可选：上下文信息，值为'a'
        }}
    }},

        // -------------------------- pkcs8 格式（私钥，ASN.1编码） --------------------------
        {"pkcs8", {
            // RSA 私钥（PKCS#8格式）
            {"RSA-OAEP", {
                {"name", ""},                  // 必需：算法名称
                {"hash", ""}                   // 必需：哈希算法
            }},
            {"RSA-PSS", {
                {"name", ""},
                {"hash", ""}                   // 必需：哈希算法
            }},
            {"RSASSA-PKCS1-v1_5", {
                {"name", ""},
                {"hash", ""}                   // 必需：哈希算法
            }},
        // 椭圆曲线私钥（PKCS#8格式）
        {"ECDSA", {
            {"name", ""},                  // 必需：算法名称
            {"namedCurve", ""},            // 必需：曲线名称
            {"hash", ""}                   // 必需（ECDSA导入需指定hash）
        }},
        {"ECDH", {
            {"name", ""},
            {"namedCurve", ""}             // 必需：曲线名称
        }},
        // 现代椭圆曲线私钥（PKCS#8格式）
        {"Ed25519", {
            {"name", ""}                   // 仅需name，曲线固定
        }},
        {"X25519", {
            {"name", ""}                   // 仅需name，曲线固定
        }},
        // AES 私钥（极少场景）
        {"AES-GCM", {
            {"name", ""},
            {"length", ""}                 // 必需：密钥长度
        }},
        // ChaCha20-Poly1305私钥（PKCS#8格式）
        {"ChaCha20-Poly1305", {
            {"name", ""}  // 仅需name，密钥长度固定
        }},
        // HKDF（PKCS#8格式）- 通常用于基于私钥的密钥派生
        {"HKDF", {
            {"name", ""},                  // 必需：算法名称
            {"hash", ""},                  // 必需：哈希算法
            {"salt", "a"},                 // 可选：盐值，值为'a'
            {"info", "a"}                  // 可选：上下文信息，值为'a'
        }},
        // 新增：PBKDF2（PKCS#8格式）- 基于私钥的密码派生
        {"PBKDF2", {
            {"name", ""},                  // 必需：算法名称
            {"hash", ""},                  // 必需：哈希算法
            {"salt", ""},                  // 必需：盐值
            {"iterations", ""},            // 必需：迭代次数
            {"length", "a"},               // 可选：派生密钥长度，值为'a'
            {"info", "a"}                  // 可选：上下文信息，值为'a'
        }}
    }},

        // -------------------------- spki 格式（公钥，ASN.1编码） --------------------------
        {"spki", {
            // RSA 公钥（SPKI格式）
            {"RSA-OAEP", {
                {"name", ""},
                {"hash", ""}                   // 必需：哈希算法
            }},
            {"RSA-PSS", {
                {"name", ""},
                {"hash", ""}
            }},
            {"RSASSA-PKCS1-v1_5", {
                {"name", ""},
                {"hash", ""}
            }},
        // 椭圆曲线公钥（SPKI格式）
        {"ECDSA", {
            {"name", ""},
            {"namedCurve", ""},            // 必需：曲线名称
            {"hash", ""}                   // 必需（ECDSA导入需指定hash）
        }},
        {"ECDH", {
            {"name", ""},
            {"namedCurve", ""}
        }},
        // 现代椭圆曲线公钥（SPKI格式）
        {"Ed25519", {
            {"name", ""}
        }},
        {"X25519", {
            {"name", ""}
        }},
        // HKDF（SPKI格式）- 基于公钥的密钥派生
        {"HKDF", {
            {"name", ""},                  // 必需：算法名称
            {"hash", ""},                  // 必需：哈希算法
            {"salt", "a"},                 // 可选：盐值，值为'a'
            {"info", "a"}                  // 可选：上下文信息，值为'a'
        }},
        // 新增：PBKDF2（SPKI格式）- 基于公钥的密码派生
        {"PBKDF2", {
            {"name", ""},                  // 必需：算法名称
            {"hash", ""},                  // 必需：哈希算法
            {"salt", ""},                  // 必需：盐值
            {"iterations", ""},            // 必需：迭代次数
            {"length", "a"},               // 可选：派生密钥长度，值为'a'
            {"info", "a"}                  // 可选：上下文信息，值为'a'
        }},
        // ChaCha20-Poly1305无公钥，无需添加
    }},

        // -------------------------- jwk 格式（JSON Web Key） --------------------------
        {"jwk", {
            // AES 密钥（JWK格式）
            {"AES-GCM", {
                {"name", ""},      // 必需：算法名称
                {"length", ""}     // 必需：密钥长度（匹配JWK的k值长度）
            }},
            {"AES-CBC", {
                {"name", ""},
                {"length", ""}
            }},
            {"AES-CTR", {
                {"name", ""},
                {"length", ""}
            }},
            {"AES-KW", {
                {"name", ""},
                {"length", ""}
            }},
        // ChaCha20-Poly1305（JWK格式）
        {"ChaCha20-Poly1305", {
            {"name", ""}  // 仅需name，密钥长度固定256位
        }},
        // HMAC 密钥（JWK格式）
        {"HMAC", {
            {"name", ""},
            {"hash", ""}           // 必需：哈希算法
        }},
        // HKDF（JWK格式）- JWK中HKDF的标准配置
        {"HKDF", {
            {"name", ""},          // 必需：算法名称
            {"hash", ""},          // 必需：哈希算法（匹配JWK的hash值）
            {"salt", "a"},         // 可选：盐值（对应JWK的salt参数），值为'a'
            {"info", "a"},         // 可选：上下文信息（对应JWK的info参数），值为'a'
            {"ext", "a"}           // 可选：是否提取阶段（JWK扩展字段），值为'a'
        }},
        // 新增：PBKDF2（JWK格式）
        {"PBKDF2", {
            {"name", ""},          // 必需：算法名称
            {"hash", ""},          // 必需：哈希算法
            {"salt", ""},          // 必需：盐值
            {"iterations", ""},    // 必需：迭代次数
            {"length", "a"},       // 可选：派生密钥长度，值为'a'
            {"info", "a"},         // 可选：上下文信息，值为'a'
            {"prf", "a"}           // 可选：伪随机函数，值为'a'
        }},
        // RSA 密钥（JWK格式）
        {"RSA-OAEP", {
            {"name", ""},
            {"hash", ""},          // 必需：哈希算法
            {"label", "a"}         // 可选：标签，值为'a'
        }},
        {"RSA-PSS", {
            {"name", ""},
            {"hash", ""}
        }},
        {"RSASSA-PKCS1-v1_5", {
            {"name", ""},
            {"hash", ""}
        }},
        // 椭圆曲线密钥（JWK格式）
        {"ECDSA", {
            {"name", ""},
            {"namedCurve", ""},    // 必需：曲线名称（匹配JWK的crv值）
            {"hash", ""}           // 必需（ECDSA导入需指定hash）
        }},
        {"ECDH", {
            {"name", ""},
            {"namedCurve", ""}
        }},
        // 现代椭圆曲线密钥（JWK格式）
        {"Ed25519", {
            {"name", ""}
        }},
        {"X25519", {
            {"name", ""}
        }}
    }}
    };
    static std::unordered_map<std::string, std::unordered_map<std::string, std::string>> allowedExportAlgorithm = {
        // -------------------------- raw 格式（二进制原始数据） --------------------------
        {"raw", {
            // AES 对称密钥（raw格式支持）
            {"AES-GCM", ""},
            {"AES-CBC", ""},
            {"AES-CTR", ""},
            {"AES-KW", ""},
            // ChaCha20-Poly1305（raw格式支持）
            {"ChaCha20-Poly1305", ""},
            // HMAC 密钥（raw格式支持）
            {"HMAC", ""},
            // 新增：HKDF（raw格式支持）
            {"HKDF", ""},
            // 新增：PBKDF2（raw格式支持）
            {"PBKDF2", ""}
        }},

        // -------------------------- pkcs8 格式（私钥，ASN.1编码） --------------------------
        {"pkcs8", {
            // RSA 私钥（pkcs8格式支持）
            {"RSA-OAEP", ""},
            {"RSA-PSS", ""},
            {"RSASSA-PKCS1-v1_5", ""},
            // 椭圆曲线私钥（pkcs8格式支持）
            {"ECDSA", ""},
            {"ECDH", ""},
            {"Ed25519", ""},
            {"X25519", ""},
            // 新增：HKDF（pkcs8格式支持）
            {"HKDF", ""},
            // 新增：PBKDF2（pkcs8格式支持）
            {"PBKDF2", ""}
        }},

        // -------------------------- spki 格式（公钥，ASN.1编码） --------------------------
        {"spki", {
            // RSA 公钥（spki格式支持）
            {"RSA-OAEP", ""},
            {"RSA-PSS", ""},
            {"RSASSA-PKCS1-v1_5", ""},
            // 椭圆曲线公钥（spki格式支持）
            {"ECDSA", ""},
            {"ECDH", ""},
            {"Ed25519", ""},
            {"X25519", ""},
            // 新增：HKDF（spki格式支持）
            {"HKDF", ""},
            // 新增：PBKDF2（spki格式支持）
            {"PBKDF2", ""}
        }},

        // -------------------------- jwk 格式（JSON Web Key） --------------------------
        {"jwk", {
            // AES 对称密钥（jwk格式支持）
            {"AES-GCM", ""},
            {"AES-CBC", ""},
            {"AES-CTR", ""},
            {"AES-KW", ""},
            // ChaCha20-Poly1305（jwk格式支持）
            {"ChaCha20-Poly1305", ""},
            // HMAC 密钥（jwk格式支持）
            {"HMAC", ""},
            // 新增：HKDF（jwk格式支持）
            {"HKDF", ""},
            // 新增：PBKDF2（jwk格式支持）
            {"PBKDF2", ""},
            // RSA 密钥（jwk格式支持）
            {"RSA-OAEP", ""},
            {"RSA-PSS", ""},
            {"RSASSA-PKCS1-v1_5", ""},
            // 椭圆曲线密钥（jwk格式支持）
            {"ECDSA", ""},
            {"ECDH", ""},
            {"Ed25519", ""},
            {"X25519", ""}
        }}
    };
    static std::unordered_map<std::string, std::unordered_map<std::string, std::string>> allowedKeyUsagesList = {
        // -------------------------- 对称加密算法 --------------------------
        // 对称密钥无公私之分，均为空
        {"AES-GCM", {
            {"encrypt", ""},
            {"decrypt", ""}
        }},
        {"AES-CBC", {
            {"encrypt", ""},
            {"decrypt", ""}
        }},
        {"AES-CTR", {
            {"encrypt", ""},
            {"decrypt", ""}
        }},
        {"AES-KW", {
            {"wrapKey", ""},
            {"unwrapKey", ""}
        }},
        {"ChaCha20-Poly1305", {
            {"encrypt", ""},
            {"decrypt", ""},
            {"wrapKey", ""},
            {"unwrapKey", ""}
        }},

        // -------------------------- 非对称加密算法 --------------------------
        {"RSA-OAEP", {
            {"encrypt", "a"},    // 公钥专属：加密
            {"decrypt", "b"},    // 私钥专属：解密
            {"wrapKey", "a"},    // 公钥专属：包装密钥
            {"unwrapKey", "b"}   // 私钥专属：解包密钥
        }},
        {"RSA-PSS", {
            {"sign", "b"},       // 私钥专属：签名
            {"verify", "a"}      // 公钥专属：验签
        }},
        {"RSASSA-PKCS1-v1_5", {
            {"sign", "b"},       // 私钥专属：签名
            {"verify", "a"}      // 公钥专属：验签
        }},
        {"ECDSA", {
            {"sign", "b"},       // 私钥专属：签名
            {"verify", "a"}      // 公钥专属：验签
        }},
        {"ECDH", {
            {"deriveKey", "b"},  // Web Crypto：私钥专属（派生密钥）
            {"deriveBits", "b"}  // Web Crypto：私钥专属（派生比特流）
        }},
        {"Ed25519", {
            {"sign", "b"},       // 私钥专属：签名
            {"verify", "a"}      // 公钥专属：验签
        }},
        {"X25519", {
            {"deriveKey", "b"},  // Web Crypto：私钥专属（派生密钥）
            {"deriveBits", "b"}  // Web Crypto：私钥专属（派生比特流）
        }},

        // -------------------------- 哈希/签名/密钥派生算法 --------------------------
        // HMAC是对称签名，无公私之分，均为空
        {"HMAC", {
            {"sign", ""},
            {"verify", ""}
        }},
        {"HKDF", {
            {"deriveKey", ""},   // 密钥派生（无公私之分）
            {"deriveBits", ""}   // 比特流派生（无公私之分）
        }},
        // 新增：PBKDF2 密钥用途
        {"PBKDF2", {
            {"deriveKey", ""},   // 密钥派生（无公私之分）
            {"deriveBits", ""}   // 比特流派生（无公私之分）
        }}
    };
    static std::unordered_map<std::string, std::string> allowedShaName = {
        {"SHA-1", ""},
        {"SHA-224", ""},
        {"SHA-256", ""},
        {"SHA-384", ""},
        {"SHA-512", ""},
        {"SHA-3-224", ""},
        {"SHA-3-256", ""},
        {"SHA-3-384", ""},
        {"SHA-3-512", ""},
        {"SHA-512/224", ""},
        {"SHA-512/256", ""},
    };
    static std::unordered_map<std::string, std::string> allowedCurveName = {
        {"P-192", ""},
        {"P-256", ""},
        {"P-384", ""},
        {"P-521", ""},
        {"secp192k1", ""},
        {"secp224r1", ""},
        {"secp224k1", ""},
        {"secp256k1", ""},
    };
    static std::unordered_map<std::string, std::unordered_map<std::string, std::string>> allowedEncryptAlgorithm = {
        // -------------------------- 对称加密 --------------------------
        {"AES-GCM", {
            {"name", ""},                  // 必需：算法名称（如 AES-GCM）
            {"iv", ""},                    // 必需：初始化向量（12字节推荐，Web Crypto 要求）
            {"additionalData", "a"},       // 可选：附加认证数据
            {"tagLength", "a"}             // 可选：认证标签长度（8-128，默认128）
        }},
        {"AES-CBC", {
            {"name", ""},                  // 必需：算法名称（如 AES-CBC）
            {"iv", ""}                     // 必需：初始化向量（16字节，Web Crypto 要求）
        }},
        {"AES-CTR", {
            {"name", ""},                  // 必需：算法名称（如 AES-CTR）
            {"iv", ""},                    // 必需：计数器（16字节，Web Crypto 中统一叫 iv）
            {"counterLength", ""}          // 必需：计数器长度（单位：比特，1-128，通常128，Web Crypto 标准参数）
        }},
        {"AES-KW", {
            {"name", ""}                   // 必需：算法名称（如 AES-KW）
        }},
        {"ChaCha20-Poly1305", {
            {"name", ""},                  // 必需：算法名称（如 ChaCha20-Poly1305）
            {"iv", ""},                    // 必需：初始化向量（12字节，Web Crypto 要求）
            {"additionalData", "a"}        // 可选：附加认证数据
        }},

        // -------------------------- 非对称加密/签名 --------------------------
        {"RSA-OAEP", {
            {"name", ""},                  // 必需：算法名称（如 RSA-OAEP）
            {"label", "a"}                 // 可选：标签数据（Web Crypto 中为可选）
        }},
        {"RSA-PSS", {
            {"name", ""},                  // 必需：算法名称（如 RSA-PSS）
            {"saltLength", ""}             // 必需：盐长度（推荐与哈希长度一致，Web Crypto 要求）
        }},
        {"RSASSA-PKCS1-v1_5", {
            {"name", ""}                   // 必需：算法名称（如 RSASSA-PKCS1-v1_5）
        }},

        // -------------------------- 椭圆曲线签名 --------------------------
        {"ECDSA", {
            {"name", ""},                  // 必需：算法名称（如 ECDSA）
            {"hash", ""}                   // 必需：哈希算法（如 SHA-256，Web Crypto 要求）
        }},
        {"Ed25519", {
            {"name", ""}                   // 必需：算法名称（如 Ed25519，无额外参数）
        }},

        // -------------------------- 密钥派生 --------------------------
        {"HKDF", {
            {"name", ""},                  // 必需：算法名称（如 HKDF）
            {"hash", ""},                  // 必需：哈希算法（如 SHA-256，Web Crypto 要求）
            {"salt", "a"},                 // 可选：盐值
            {"info", ""}                   // 必需：上下文信息（Web Crypto 要求）
        }},
        {"PBKDF2", {
            {"name", ""},                  // 必需：算法名称（如 PBKDF2）
            {"hash", ""},                  // 必需：哈希算法（如 SHA-256，Web Crypto 要求）
            {"salt", ""},                  // 必需：盐值（Web Crypto 要求）
            {"iterations", ""},            // 必需：迭代次数（Web Crypto 要求）
            {"length", "a"}                // 可选：派生密钥长度（默认与哈希输出长度一致）
        }},

        // -------------------------- HMAC（签名/验证） --------------------------
        {"HMAC", {
            {"name", ""},                  // 必需：算法名称（如 HMAC）
            {"hash", ""}                   // 必需：哈希算法（如 SHA-256，Web Crypto 要求）
        }}
    };
    static std::unordered_map<std::string, std::unordered_map<std::string, std::string>> allowedDecryptAlgorithm = {
        // -------------------------- 对称解密 --------------------------
        {"AES-GCM", {
            {"name", ""},                  // 必需：算法名称（与加密一致）
            {"iv", ""},                    // 必需：加密时使用的 iv
            {"additionalData", "a"},       // 可选：加密时使用的附加认证数据
            {"tagLength", "a"}             // 可选：加密时使用的标签长度
        }},
        {"AES-CBC", {
            {"name", ""},                  // 必需：算法名称（与加密一致）
            {"iv", ""}                     // 必需：加密时使用的 iv
        }},
        {"AES-CTR", {
            {"name", ""},                  // 必需：算法名称（与加密一致）
            {"iv", ""},                    // 必需：加密时使用的 iv（原 counter）
            {"counterLength", ""}          // 必需：加密时使用的计数器长度（原 length）
        }},
        {"AES-KW", {
            {"name", ""}                   // 必需：算法名称（与加密一致）
        }},
        {"ChaCha20-Poly1305", {
            {"name", ""},                  // 必需：算法名称（与加密一致）
            {"iv", ""},                    // 必需：加密时使用的 iv
            {"additionalData", "a"}        // 可选：加密时使用的附加认证数据
        }},

        // -------------------------- 非对称解密/验签 --------------------------
        {"RSA-OAEP", {
            {"name", ""},                  // 必需：算法名称（与加密一致）
            {"label", "a"}                 // 可选：加密时使用的标签数据
        }},
        {"RSA-PSS", {
            {"name", ""},                  // 必需：算法名称（与签名一致）
            {"saltLength", ""}             // 必需：签名时使用的盐长度
        }},
        {"RSASSA-PKCS1-v1_5", {
            {"name", ""}                   // 必需：算法名称（与签名一致）
        }},

        // -------------------------- 椭圆曲线验签 --------------------------
        {"ECDSA", {
            {"name", ""},                  // 必需：算法名称（与签名一致）
            {"hash", ""}                   // 必需：签名时使用的哈希算法
        }},
        {"Ed25519", {
            {"name", ""}                   // 必需：算法名称（与签名一致）
        }},

        // -------------------------- HMAC（验签） --------------------------
        {"HMAC", {
            {"name", ""},                  // 必需：算法名称（与签名一致）
            {"hash", ""}                   // 必需：签名时使用的哈希算法
        }}
    };
    static std::unordered_map<std::string, std::unordered_map<std::string, std::string>> allowedSignAlgorithm = {
        // -------------------------- 非对称签名 --------------------------
        {"RSA-PSS", {
            {"name", ""},                  // 必需：算法名称（如 RSA-PSS）
            {"saltLength", ""}             // 必需：盐长度（推荐与哈希长度一致，Web Crypto 要求）
        }},
        {"RSASSA-PKCS1-v1_5", {
            {"name", ""}                   // 必需：算法名称（如 RSASSA-PKCS1-v1_5）
        }},

        // -------------------------- 椭圆曲线签名 --------------------------
        {"ECDSA", {
            {"name", ""},                  // 必需：算法名称（如 ECDSA）
            {"hash", ""}                   // 必需：哈希算法（如 SHA-256，Web Crypto 要求）
        }},
        {"Ed25519", {
            {"name", ""}                   // 必需：算法名称（如 Ed25519，无额外参数）
        }},

        // -------------------------- HMAC（基于哈希的签名） --------------------------
        {"HMAC", {
            {"name", ""},                  // 必需：算法名称（如 HMAC）
            {"hash", ""}                   // 必需：哈希算法（如 SHA-256，Web Crypto 要求）
        }}
    };
    static std::unordered_map<std::string, std::unordered_map<std::string, std::string>> allowedVerifyAlgorithm = {
        // -------------------------- 非对称验签 --------------------------
        {"RSA-PSS", {
            {"name", ""},                  // 必需：算法名称（与签名一致）
            {"saltLength", ""}             // 必需：签名时使用的盐长度
        }},
        {"RSASSA-PKCS1-v1_5", {
            {"name", ""}                   // 必需：算法名称（与签名一致）
        }},

        // -------------------------- 椭圆曲线验签 --------------------------
        {"ECDSA", {
            {"name", ""},                  // 必需：算法名称（与签名一致）
            {"hash", ""}                   // 必需：签名时使用的哈希算法
        }},
        {"Ed25519", {
            {"name", ""}                   // 必需：算法名称（与签名一致）
        }},

        // -------------------------- HMAC（验签） --------------------------
        {"HMAC", {
            {"name", ""},                  // 必需：算法名称（与签名一致）
            {"hash", ""}                   // 必需：签名时使用的哈希算法
        }}
    };
    static std::unordered_map<std::string, std::unordered_map<std::string, std::string>> allowedWrapAlgorithm = {
        // -------------------------- 对称密钥包装（Web Crypto 原生支持） --------------------------
        {"AES-KW", {
            {"name", ""}                   // 必需：算法名称（固定为 "AES-KW"）
        }},

        // -------------------------- 非对称密钥包装（Web Crypto 原生支持） --------------------------
        {"RSA-OAEP", {
            {"name", ""},                  // 必需：算法名称（固定为 "RSA-OAEP"）
            {"hash", ""},                  // 必需：哈希算法（如 "SHA-256"）
            {"label", "a"}                 // 可选：额外标签数据，占位符设为 "a"
        }},
        {"RSA-PKCS1-v1_5", {
            {"name", ""}                   // 必需：算法名称（固定为 "RSA-PKCS1-v1_5"）
        }}
    };
    static std::unordered_map<std::string, std::unordered_map<std::string, std::string>> allowedUnwrapAlgorithm = {
        // -------------------------- 对称密钥解包（Web Crypto 原生支持） --------------------------
        {"AES-KW", {
            {"name", ""}                   // 必需：算法名称（与包装时一致）
        }},

        // -------------------------- 非对称密钥解包（Web Crypto 原生支持） --------------------------
        {"RSA-OAEP", {
            {"name", ""},                  // 必需：算法名称（与包装时一致）
            {"hash", ""},                  // 必需：包装时使用的哈希算法
            {"label", "a"}                 // 可选：包装时使用的标签数据，占位符设为 "a"
        }},
        {"RSA-PKCS1-v1_5", {
            {"name", ""}                   // 必需：算法名称（与包装时一致）
        }}
    };
    static std::unordered_map<std::string, std::unordered_map<std::string, std::string>> allowedDeriveKeyAlgorithm = {
        // -------------------------- 基于密码的密钥派生（PBKDF2） --------------------------
        {"PBKDF2", {
            {"name", ""},                  // 必需：算法名称（固定为 "PBKDF2"）
            {"salt", ""},                  // 必需：随机盐值（二进制数据）
            {"iterations", ""},            // 必需：迭代次数（如 100000）
            {"hash", ""},                  // 必需：哈希算法（如 "SHA-256"）
            {"length", "a"}                // 可选：派生位长度（默认与目标密钥长度一致）
        }},

        // -------------------------- 椭圆曲线密钥协商（ECDH） --------------------------
        {"ECDH", {
            {"name", ""},                  // 必需：算法名称（固定为 "ECDH"）
            {"public", ""},                // 必需：对方的 ECDH 公钥（CryptoKey 对象）
            {"publicKey", ""},                // 必需：对方的 ECDH 公钥（CryptoKey 对象）
            {"namedCurve", ""}             // 必需：曲线名称（如 "P-256"/"P-384"/"P-521"）
        }},

        // -------------------------- 密钥扩展（HKDF） --------------------------
        {"HKDF", {
            {"name", ""},                  // 必需：算法名称（固定为 "HKDF"）
            {"hash", ""},                  // 必需：哈希算法（如 "SHA-256"）
            {"salt", "a"},                 // 可选：盐值（二进制数据）
            {"info", ""}                   // 必需：上下文信息（区分不同用途的派生密钥）
        }}
    };
    static std::unordered_map<std::string, std::unordered_map<std::string, std::string>> allowedDeriveBitsAlgorithm = {
        // -------------------------- 基于密码的密钥派生（PBKDF2） --------------------------
        {"PBKDF2", {
            {"name", ""},                  // 必需：算法名称（固定为 "PBKDF2"）
            {"salt", ""},                  // 必需：随机盐值（二进制数据）
            {"iterations", ""},            // 必需：迭代次数（如 100000）
            {"hash", ""},                  // 必需：哈希算法（如 "SHA-256"）
            {"length", ""}                 // 必需：派生位长度（8的倍数，如 256）
        }},

        // -------------------------- 椭圆曲线密钥协商（ECDH） --------------------------
        {"ECDH", {
            {"name", ""},                  // 必需：算法名称（固定为 "ECDH"）
            {"public", ""},                // 必需：对方的 ECDH 公钥（CryptoKey 对象）
            {"publicKey", ""},                // 必需：对方的 ECDH 公钥（CryptoKey 对象）
            {"namedCurve", ""}             // 必需：曲线名称（如 "P-256"/"P-384"/"P-521"）
        }},

        // -------------------------- 密钥扩展（HKDF） --------------------------
        {"HKDF", {
            {"name", ""},                  // 必需：算法名称（固定为 "HKDF"）
            {"hash", ""},                  // 必需：哈希算法（如 "SHA-256"）
            {"salt", "a"},                 // 可选：盐值（二进制数据）
            {"info", ""},                  // 必需：上下文信息（区分不同用途的派生密钥）
            {"length", ""}                 // 必需：派生位长度（8的倍数，如 256）
        }}
    };
    struct RSAJWKDATA {
        bool isValid = false;
        bool isPrivate = false;
        BYTEBUFFER e = {};
        BYTEBUFFER n = {};
        BYTEBUFFER d = {};
        BYTEBUFFER p = {};
        BYTEBUFFER q = {};
        BYTEBUFFER dp = {};
        BYTEBUFFER dq = {};
        BYTEBUFFER qi = {};
    };
    struct ECJWKDATA {
        bool isValid = false;
        bool isPrivate = false;
        BYTEBUFFER x = {};
        BYTEBUFFER y = {};
        BYTEBUFFER d = {};
    };
    struct EXJWKDATA {
        bool isValid = false;
        bool isPrivate = false;
        BYTEBUFFER x = {};
        BYTEBUFFER d = {};
    };
    struct PKDATA {
        bool isValid = false;

        std::string name = "";

        bool isPrivate = false;

        //RSA专有+-
        uint64_t modulusLength = 0;
        uint64_t publicExponent = 0;
        //-+

    };
    PKDATA GetPKData(BYTEBUFFER_PTR keyBinaryPtr) {
        PKDATA pkData;
        if (keyBinaryPtr == nullptr || keyBinaryPtr->empty()) {
            return pkData;
        }

        auto initByteQueue = [&](CryptoPP::ByteQueue& queue) {
            queue.Clear();
            queue.Put(keyBinaryPtr->data(), keyBinaryPtr->size());
            queue.MessageEnd();
            };

        CryptoPP::ByteQueue byteQueue;
        initByteQueue(byteQueue);

        try {
            CryptoPP::ByteQueue tempQueue;
            initByteQueue(tempQueue);
            CryptoPP::InvertibleRSAFunction rsaPrivKey;
            rsaPrivKey.Load(tempQueue);

            pkData.isPrivate = true;
            pkData.name = "RSA";
            pkData.modulusLength = static_cast<uint64_t>(rsaPrivKey.GetModulus().BitCount());

            CryptoPP::Integer e = rsaPrivKey.GetPublicExponent();
            unsigned char eBuf[8] = { 0 };
            size_t eLen = std::min<size_t>(e.MinEncodedSize(), 8);
            e.Encode(eBuf, eLen);
            pkData.publicExponent = 0;
            for (size_t i = 0; i < eLen; ++i) {
                pkData.publicExponent |= (static_cast<uint64_t>(eBuf[i]) << (8 * (eLen - 1 - i)));
            }

            pkData.isValid = true;
            return pkData;
        }
        catch (...) {
            try {
                CryptoPP::ByteQueue tempQueue;
                initByteQueue(tempQueue);
                CryptoPP::RSAFunction rsaPubKey;
                rsaPubKey.Load(tempQueue);

                pkData.isPrivate = false;
                pkData.name = "RSA";
                pkData.modulusLength = static_cast<uint64_t>(rsaPubKey.GetModulus().BitCount());

                CryptoPP::Integer e = rsaPubKey.GetPublicExponent();
                unsigned char eBuf[8] = { 0 };
                size_t eLen = std::min<size_t>(e.MinEncodedSize(), 8);
                e.Encode(eBuf, eLen);
                pkData.publicExponent = 0;
                for (size_t i = 0; i < eLen; ++i) {
                    pkData.publicExponent |= (static_cast<uint64_t>(eBuf[i]) << (8 * (eLen - 1 - i)));
                }

                pkData.isValid = true;
                return pkData;
            }
            catch (...) {}
        }

        initByteQueue(byteQueue);
        try {
            CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey eccPrivKey;
            eccPrivKey.Load(byteQueue);

            pkData.isPrivate = true;
            pkData.name = "ECDSA";
            pkData.isValid = true;
            return pkData;
        }
        catch (...) {
            initByteQueue(byteQueue);
            try {
                CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey eccPubKey;
                eccPubKey.Load(byteQueue);

                pkData.isPrivate = false;
                pkData.name = "ECDSA";
                pkData.isValid = true;
                return pkData;
            }
            catch (...) {
                initByteQueue(byteQueue);
                try {
                    CryptoPP::DL_PrivateKey_EC<CryptoPP::ECP> ecdhPrivKey;
                    ecdhPrivKey.Load(byteQueue);

                    pkData.isPrivate = true;
                    pkData.name = "ECDH";
                    pkData.isValid = true;
                    return pkData;
                }
                catch (...) {
                    initByteQueue(byteQueue);
                    try {
                        CryptoPP::DL_PublicKey_EC<CryptoPP::ECP> ecdhPubKey;
                        ecdhPubKey.Load(byteQueue);

                        pkData.isPrivate = false;
                        pkData.name = "ECDH";
                        pkData.isValid = true;
                        return pkData;
                    }
                    catch (...) {}
                }
            }
        }

        initByteQueue(byteQueue);
        try {
            size_t dataLen = keyBinaryPtr->size();
            if (dataLen == 32 || dataLen == 64) {
                std::vector<unsigned char> keyCopy(keyBinaryPtr->begin(), keyBinaryPtr->end());

                if (dataLen == 64) {
                    const unsigned char* pubKey = keyCopy.data() + 32;
                    CryptoPP::ed25519Verifier verifier(pubKey);
                    pkData.isPrivate = true;
                    pkData.name = "Ed25519";
                    pkData.isValid = true;
                    return pkData;
                }
                else if (dataLen == 32) {
                    CryptoPP::ed25519Verifier verifier(keyCopy.data());
                    pkData.isPrivate = false;
                    pkData.name = "Ed25519";
                    pkData.isValid = true;
                    return pkData;
                }
            }
        }
        catch (...) {}

        initByteQueue(byteQueue);
        try {
            size_t dataLen = keyBinaryPtr->size();
            if (dataLen == 32) {
                std::vector<unsigned char> keyCopy(keyBinaryPtr->begin(), keyBinaryPtr->end());
                CryptoPP::x25519 x25519Key;
                unsigned char pk[32] = { 0 };
                CryptoPP::AutoSeededRandomPool rngTmp;
                x25519Key.GeneratePublicKey(rngTmp, keyCopy.data(), pk);
                bool isAllZero = true;
                for (int i = 0; i < 32; ++i) {
                    if (pk[i] != 0) {
                        isAllZero = false;
                        break;
                    }
                }
                if (!isAllZero) {
                    pkData.isPrivate = true;
                    pkData.name = "X25519";
                    pkData.isValid = true;
                    return pkData;
                }
            }
        }
        catch (...) {
            initByteQueue(byteQueue);
            try {
                size_t dataLen = keyBinaryPtr->size();
                if (dataLen == 32) {
                    std::vector<unsigned char> keyCopy(keyBinaryPtr->begin(), keyBinaryPtr->end());
                    CryptoPP::x25519 x25519Key;
                    unsigned char sk[32] = { 0 };
                    unsigned char shared[32] = { 0 };
                    CryptoPP::AutoSeededRandomPool rngTmp;
                    rngTmp.GenerateBlock(sk, 32);
                    x25519Key.Agree(shared, sk, keyCopy.data());
                    bool isAllZero = true;
                    for (int i = 0; i < 32; ++i) {
                        if (shared[i] != 0) {
                            isAllZero = false;
                            break;
                        }
                    }
                    if (!isAllZero) {
                        pkData.isPrivate = false;
                        pkData.name = "X25519";
                        pkData.isValid = true;
                        return pkData;
                    }
                }
            }
            catch (...) {}
        }

        return pkData;
    }
    bool IsAESMatched(BYTEBUFFER_PTR binary, uint64_t length) {
        if (binary == nullptr || binary->empty()) {
            return false;
        }

        size_t keyByteLen = static_cast<size_t>(length / 8);
        if (length % 8 != 0 || (keyByteLen != 16 && keyByteLen != 24 && keyByteLen != 32)) {
            return false; // AES仅支持16/24/32字节（128/192/256比特）
        }

        if (binary->size() != keyByteLen) {
            return false;
        }

        try {
            const unsigned char* keyPtr = binary->data();
            CryptoPP::AES::Encryption aesEnc;
            aesEnc.SetKey(keyPtr, keyByteLen);
            return true;
        }
        catch (...) {
            return false;
        }
    }
    bool IsHMACMatched(BYTEBUFFER_PTR binary, std::string hash) {
        if (binary == nullptr || binary->empty() || hash.empty()) {
            return false;
        }

        const unsigned char* keyPtr = binary->data();
        size_t keyByteLen = binary->size();

        try {
            if (hash == "SHA-1") {
                CryptoPP::HMAC<CryptoPP::SHA1> hmac(keyPtr, keyByteLen);
            }
            else if (hash == "SHA-256") {
                CryptoPP::HMAC<CryptoPP::SHA256> hmac(keyPtr, keyByteLen);
            }
            else if (hash == "SHA-384") {
                CryptoPP::HMAC<CryptoPP::SHA384> hmac(keyPtr, keyByteLen);
            }
            else if (hash == "SHA-512") {
                CryptoPP::HMAC<CryptoPP::SHA512> hmac(keyPtr, keyByteLen);
            }
            else if (hash == "SHA-3-256") {
                CryptoPP::HMAC<CryptoPP::SHA3_256> hmac(keyPtr, keyByteLen);
            }
            else if (hash == "SHA-3-384") {
                CryptoPP::HMAC<CryptoPP::SHA3_384> hmac(keyPtr, keyByteLen);
            }
            else if (hash == "SHA-3-512") {
                CryptoPP::HMAC<CryptoPP::SHA3_512> hmac(keyPtr, keyByteLen);
            }
            else {
                return false;
            }
            return true;
        }
        catch (...) {
            return false;
        }
    }
    std::string GetTextFromBinarySafely(BYTEBUFFER_PTR bp) {
        if (bp == nullptr || bp->empty()) {
            return "";
        }

        const auto& buffer = *bp;
        std::string utf8_str;
        size_t i = 0;
        const size_t len = buffer.size();

        while (i < len) {
            uint8_t first_byte = buffer[i];
            size_t utf8_bytes = 0;
            bool is_valid = true;

            if ((first_byte & 0x80) == 0) {
                utf8_bytes = 1;
            }
            else if ((first_byte & 0xE0) == 0xC0) {
                utf8_bytes = 2;
                if (i + 1 >= len || (buffer[i + 1] & 0xC0) != 0x80) {
                    is_valid = false;
                }
            }
            else if ((first_byte & 0xF0) == 0xE0) {
                utf8_bytes = 3;
                if (i + 2 >= len || (buffer[i + 1] & 0xC0) != 0x80 || (buffer[i + 2] & 0xC0) != 0x80) {
                    is_valid = false;
                }
            }
            else if ((first_byte & 0xF8) == 0xF0) {
                utf8_bytes = 4;
                if (i + 3 >= len || (buffer[i + 1] & 0xC0) != 0x80 ||
                    (buffer[i + 2] & 0xC0) != 0x80 || (buffer[i + 3] & 0xC0) != 0x80) {
                    is_valid = false;
                }
            }
            else {
                is_valid = false;
            }

            if (is_valid) {
                for (size_t j = 0; j < utf8_bytes; ++j) {
                    utf8_str += static_cast<char>(buffer[i + j]);
                }
                i += utf8_bytes;
            }
            else {
                utf8_str += '?';
                i += 1;
            }
        }
        std::wstring wide_str = stringToWstring(utf8_str);
        return wstringToString(wide_str);
    }
    bool IsMimeTypeValid(std::string mimeType) {
        if (mimeType.empty() || mimeType.length() > 255) return false;
        size_t slashPos = mimeType.find('/');
        if (slashPos == std::string::npos || slashPos == 0 || slashPos == mimeType.length() - 1) return false;

        std::string type = mimeType.substr(0, slashPos);
        if (!isalpha(static_cast<unsigned char>(type[0]))) return false;
        for (char c : type) {
            if (!isalnum(static_cast<unsigned char>(c)) && c != '-' && c != '+') return false;
        }

        std::string subtype = mimeType.substr(slashPos + 1);
        if (!isalnum(static_cast<unsigned char>(subtype[0]))) return false;
        for (char c : subtype) {
            if (!isalnum(static_cast<unsigned char>(c)) && c != '-' && c != '+' && c != '.') return false;
        }

        return true;
    }
    bool IsDeviceOnline() {
        DWORD dwUnused = 0;
        return InternetGetConnectedState(&dwUnused, 0) != FALSE;
    }
    std::vector<std::string> SplitString(std::string str, std::string p = "") {
        std::vector<std::string> result = {};

        if (str.empty()) {
            return result;
        }

        if (p.empty()) {
            for (char c : str) {
                result.emplace_back(1, c);
            }
            return result;
        }

        if (p.length() > str.length()) {
            result.push_back(str);
            return result;
        }

        size_t pos = 0;
        size_t prev_pos = 0;
        const size_t delim_len = p.length();

        while ((pos = str.find(p, prev_pos)) != std::string::npos) {
            if (pos > prev_pos) {
                result.push_back(str.substr(prev_pos, pos - prev_pos));
            }
            prev_pos = pos + delim_len;
        }

        if (prev_pos <= str.length()) {
            result.push_back(str.substr(prev_pos));
        }

        return result;
    }
    bool InitLibrary(JSMData* jsmdPtr, std::wstring path);
    bool UnInitLibrary(JSMData* jsmdPtr, HMODULE hm);
    class RunInThread {
    public:
        static uint64_t run(std::function<void()> func) {
            std::lock_guard<std::mutex> lock(threadMapMutex);
            uint64_t id = nextId++;
            auto threadData = std::make_shared<ThreadData>();
            threadData->running = true;
            threadData->thread = std::thread([threadData]() {
                while (threadData->running) {
                    std::function<void()> task;
                    {
                        std::unique_lock<std::mutex> lock(threadData->queueMutex);
                        threadData->cv.wait(lock, [threadData]() {
                            return !threadData->taskQueue.empty() || !threadData->running;
                            });
                        if (!threadData->running && threadData->taskQueue.empty()) break;
                        task = std::move(threadData->taskQueue.front());
                        threadData->taskQueue.pop();
                    }
                    if (task) {
                        task();
                        std::lock_guard<std::mutex> lock(threadData->awaitMutex);
                        threadData->taskDone = true;
                        threadData->awaitCv.notify_all();
                    }
                }
                });
            threadData->taskQueue.push(std::move(func));
            threadData->cv.notify_one();
            threadMap[id] = threadData;
            return id;
        }

        template<typename Func, typename... Args>
        static uint64_t run(Func&& func, Args&&... args) {
            std::function<void()> wrapped = std::bind(std::forward<Func>(func), std::forward<Args>(args)...);
            return run(wrapped);
        }

        static void run(uint64_t id, std::function<void()> func) {
            std::lock_guard<std::mutex> lock(threadMapMutex);
            auto it = threadMap.find(id);
            if (it != threadMap.end()) {
                std::lock_guard<std::mutex> queueLock(it->second->queueMutex);
                it->second->taskDone = false;
                it->second->taskQueue.push(std::move(func));
                it->second->cv.notify_one();
            }
        }

        template<typename Func, typename... Args>
        static void run(uint64_t id, Func&& func, Args&&... args) {
            std::function<void()> wrapped = std::bind(std::forward<Func>(func), std::forward<Args>(args)...);
            run(id, wrapped);
        }

        static bool stop(uint64_t id) {
            std::lock_guard<std::mutex> lock(threadMapMutex);
            auto it = threadMap.find(id);
            if (it == threadMap.end()) return false;
            auto threadData = it->second;
            threadData->running = false;
            threadData->cv.notify_one();
            if (threadData->thread.joinable()) {
                threadData->thread.join();
            }
            threadMap.erase(it);
            return true;
        }

        static void await(uint64_t id) {
            std::lock_guard<std::mutex> lock(threadMapMutex);
            auto it = threadMap.find(id);
            if (it == threadMap.end()) return;
            auto threadData = it->second;
            std::unique_lock<std::mutex> awaitLock(threadData->awaitMutex);
            threadData->awaitCv.wait(awaitLock, [threadData]() {
                return threadData->taskDone || !threadData->running;
                });
        }

        static bool has(uint64_t id) {
            std::lock_guard<std::mutex> lock(threadMapMutex);
            return threadMap.find(id) != threadMap.end();
        }

    private:
        struct ThreadData {
            std::thread thread;
            std::mutex queueMutex;
            std::condition_variable cv;
            std::queue<std::function<void()>> taskQueue;
            std::atomic<bool> running{ false };
            std::mutex awaitMutex;
            std::condition_variable awaitCv;
            bool taskDone{ true };
        };

        static std::unordered_map<uint64_t, std::shared_ptr<ThreadData>> threadMap;
        static std::mutex threadMapMutex;
        static std::atomic<uint64_t> nextId;
    };
    std::unordered_map<uint64_t, std::shared_ptr<RunInThread::ThreadData>> RunInThread::threadMap;
    std::mutex RunInThread::threadMapMutex;
    std::atomic<uint64_t> RunInThread::nextId{ 1 };

    template <typename T>
    size_t CopyVectorData(std::vector<T>& vec, T** ptrPtr) {
        if (ptrPtr == nullptr || vec.empty()) {
            if (ptrPtr != nullptr) {
                *ptrPtr = nullptr;
            }
            return 0;
        }
        T* newData = nullptr;
        try {
            newData = new T[vec.size()];
        }
        catch (...) {
            *ptrPtr = nullptr;
            return 0;
        }
        for (size_t i = 0; i < vec.size(); ++i) {
            newData[i] = vec[i];
        }
        *ptrPtr = newData;
        return vec.size();
    }
    size_t CopyWstringData(std::wstring data, const wchar_t** outPtr) {
        if (outPtr == nullptr) {
            return 0;
        }

        size_t len = data.length();
        size_t bufferSize = len + 1;
        wchar_t* buffer = new wchar_t[bufferSize];

        if (len > 0) {
            wcscpy_s(buffer, bufferSize, data.c_str());
        }
        else {
            buffer[0] = L'\0';
        }

        *outPtr = buffer;
        return len * sizeof(wchar_t);
    }
    void FreeHeapData(CJSHeapData data) {
        if (data.tag == 1) {
            delete[]((CJSByte*)data.data);
        }
        else if (data.tag == 2) {
            delete[]((CJSString*)data.data);
        }
    }

    class JavaScriptMethod {
    public:
        JavaScriptMethod(JavaScript* InInstance, JSRuntime* InjsRuntime, JSContext* InjsContext) {

            JSMData jsmdTemp = {};
            jsmdTemp.rt = InjsRuntime;
            jsmdTemp.ctx = InjsContext;
            jsmdTemp.js = InInstance;
            jsmdTemp.jsm = this;
            SetData(jsmdTemp.ctx, &jsmdTemp);

            JSMData* jsmdPtr = nullptr;
            if (!GetData(jsmdTemp.ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                return;
            }
            JSMData& jsmd = *jsmdPtr;
            JSContext* ctx = jsmd.ctx;

            JSV null = JSV(JS_NULL);
            JSV global = NewGlobalObject(ctx);
            SetSymbolName(ctx, global, "Global");

            SetAttribute(ctx, global, "window", global);
            SetAttribute(ctx, global, "global", global);
            AppendMethod(ctx, global, "eval", global_eval);
            AppendMethod(ctx, global, "using", global_using);
            //AppendMethod(ctx, global, "await", global_await);
            AppendMethod(ctx, global, "wait", global_wait);
            AppendMethod(ctx, global, "btoa", global_btoa);
            AppendMethod(ctx, global, "atob", global_atob);
            AppendMethod(ctx, global, "FormData", NewConstructor(ctx, "FormData", global_FormData));
            AppendMethod(ctx, global, "setTimeout", global_setTimeout);
            AppendMethod(ctx, global, "clearTimeout", global_clearTimeout);
            AppendMethod(ctx, global, "Blob", NewConstructor(ctx, "Blob", global_Blob));

            //JSV Promise = NewConstructor(ctx, "Promise", global_Promise);
            //AppendMethod(ctx, global, "Promise", Promise);
            //AppendMethod(ctx, Promise, "resolve", global_Promise_resolve);
            //AppendMethod(ctx, Promise, "reject", global_Promise_reject);
            //AppendMethod(ctx, Promise, "all", global_Promise_all);
            //AppendMethod(ctx, Promise, "allSettled", global_Promise_allSettled);
            //AppendMethod(ctx, Promise, "race", global_Promise_race);
            //AppendMethod(ctx, Promise, "any", global_Promise_any);

            JSV system = NewObject(ctx, global, "system");
            SetSymbolName(ctx, system, "System");
            SetAttribute(ctx, system, "platform", platform);
            SetAttribute(ctx, system, "version", wstringToString(AY_CJS_CPP_VW));
            AppendMethod(ctx, system, "saveConfig", system_saveConfig);
            AppendMethod(ctx, system, "exit", system_exit);

            JSV console = NewObject(ctx, global, "console");
            SetSymbolName(ctx, console, "Console");
            AppendMethod(ctx, console, "log", console_log);

            //运行时修改
            JSV document = NewObject(ctx, global, "document");
            SetSymbolName(ctx, document, "Document");
            SetAttribute(ctx, document, "cookie", "");

            JSV network = NewObject(ctx, global, "network");
            SetSymbolName(ctx, network, "Network");

            JSV request = NewObject(ctx, network, "request");
            SetSymbolName(ctx, request, "RequestNetwork");
            SetAttribute(ctx, request, "workDirectory", "");
            SetAttribute(ctx, request, "url", "");
            SetAttribute(ctx, request, "method", "");
            SetAttribute(ctx, request, "header", NewObject(ctx));
            SetAttribute(ctx, request, "body", "");

            JSV response = NewObject(ctx, network, "response");
            SetSymbolName(ctx, response, "ResponstNetwork");
            SetAttribute(ctx, response, "header", NewObject(ctx));
            SetAttribute(ctx, response, "body", "");

            AppendMethod(ctx, global, "include", [](JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues)->JSValue {

                if (argumentCount == 0) {
                    JS_ThrowTypeError(ctx, "[include] Only 1 or more arguments are supported: (...moduleName)");
                    return JS_EXCEPTION;
                }

                JSMData* jsmdPtr = nullptr;
                if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                    return NewUint64(ctx, 0).get(1);
                }
                JSMData& jsmd = *jsmdPtr;

                if ((jsmdPtr->isAutoLoadModules == false && (configObject[L"general"]["isModuleMode"].isBool() && configObject[L"general"]["isModuleMode"].get<bool>() == false))) {
                    return NewUint64(ctx, 0).get(1);
                }

                JSV global = NewGlobalObject(ctx);
                SetSymbolName(ctx, global, "Global");

                JSV system = GetProperty(ctx, global, "system");
                JSV console = GetProperty(ctx, global, "console");

                ordered_map<std::string, std::string> chosedModules = {};
                for (int i = 0; i < argumentCount; i++) {
                    JSV jsv = JSV(ctx, argumentValues[i]);
                    if (!JS_IsString(jsv.get(0))) continue;
                    std::string name = "";
                    if (!ReadJSValueAsString(ctx, jsv, name)) continue;
                    chosedModules[name] = "";
                }
                std::vector<std::string> chosedModulesList = {};
                for (auto& [name, unused] : chosedModules) {
                    chosedModulesList.push_back(name);
                }

                uint64_t successCount = 0;
                bool isAll = chosedModules.count("all");

                if (isAll || chosedModules.count("cjs:console")) {
                    AppendMethod(ctx, console, "resume", console_resume);
                    AppendMethod(ctx, console, "pause", console_pause);
                    AppendMethod(ctx, console, "hide", console_hide);
                    AppendMethod(ctx, console, "show", console_show);
                    AppendMethod(ctx, console, "kill", console_kill);
                    AppendMethod(ctx, console, "restore", console_restore);
                    successCount++;
                }

                if (isAll || chosedModules.count("cjs:filesystem")) {
                    JSV filesystem = NewObject(ctx, global, "filesystem");
                    SetSymbolName(ctx, filesystem, "Filesystem");
                    AppendMethod(ctx, filesystem, "open", filesystem_open);
                    AppendMethod(ctx, filesystem, "exists", filesystem_exists);
                    AppendMethod(ctx, filesystem, "remove", filesystem_remove);
                    AppendMethod(ctx, filesystem, "count", filesystem_count);
                    successCount++;
                }

                if (isAll || chosedModules.count("cjs:script")) {
                    JSV script = NewObject(ctx, global, "script");
                    SetSymbolName(ctx, script, "Script");
                    AppendMethod(ctx, script, "include", script_include);
                    AppendMethod(ctx, script, "execute", script_execute);
                    successCount++;
                }

                if (isAll || chosedModules.count("cjs:system")) {
                    JSV system_config = NewObject(ctx, configObject);
                    SetSymbolName(ctx, system_config, "ConfigSystem");
                    SetAttribute(ctx, system, "config", system_config);
                    SetAttribute(ctx, system, "isOnLine", NewBool(ctx, IsDeviceOnline()));
                    SetAttribute(ctx, system, "runMode", NewString(ctx, mode));
                    AppendMethod(ctx, system, "cmd", system_cmd);
                    AppendMethod(ctx, system, "cwd", system_cwd);
                    AppendMethod(ctx, system, "ecwd", system_ecwd);
                    AppendMethod(ctx, system, "execute", system_execute);
                    AppendMethod(ctx, system, "updateConfig", system_updateConfig);
                    successCount++;
                }

                if (isAll || chosedModules.count("cjs:crypto")) {
                    JSV crypto = NewObject(ctx, global, "crypto");
                    SetSymbolName(ctx, crypto, "Crypto");
                    AppendMethod(ctx, crypto, "getRandomValues", crypto_getRandomValues);
                    JSV subtle = NewObject(ctx, crypto, "subtle");
                    SetSymbolName(ctx, subtle, "SubtleCrypto");
                    AppendMethod(ctx, subtle, "generateKey", crypto_subtle_generateKey);
                    AppendMethod(ctx, subtle, "importKey", crypto_subtle_importKey);
                    AppendMethod(ctx, subtle, "exportKey", crypto_subtle_exportKey);
                    AppendMethod(ctx, subtle, "digest", crypto_subtle_digest);
                    AppendMethod(ctx, subtle, "encrypt", crypto_subtle_encrypt);
                    AppendMethod(ctx, subtle, "decrypt", crypto_subtle_decrypt);
                    AppendMethod(ctx, subtle, "sign", crypto_subtle_sign);
                    AppendMethod(ctx, subtle, "verify", crypto_subtle_verify);
                    AppendMethod(ctx, subtle, "deriveBits", crypto_subtle_deriveBits);
                    AppendMethod(ctx, subtle, "deriveKey", crypto_subtle_deriveKey);
                    successCount++;
                }

                if (isAll || chosedModules.count("cjs:bytebuffer")) {
                    JSV bytebuffer = NewObject(ctx, global, "bytebuffer");
                    SetSymbolName(ctx, bytebuffer, "ByteBuffer");
                    AppendMethod(ctx, bytebuffer, "toString", bytebuffer_toString);
                    AppendMethod(ctx, bytebuffer, "toBinary", bytebuffer_toBinary);
                    AppendMethod(ctx, bytebuffer, "encodeBase16", bytebuffer_encodeBase16);
                    AppendMethod(ctx, bytebuffer, "encodeBase32", bytebuffer_encodeBase32);
                    AppendMethod(ctx, bytebuffer, "encodeBase58", bytebuffer_encodeBase58);
                    AppendMethod(ctx, bytebuffer, "encodeBase62", bytebuffer_encodeBase62);
                    AppendMethod(ctx, bytebuffer, "encodeBase64", bytebuffer_encodeBase64);
                    AppendMethod(ctx, bytebuffer, "encodeBase85", bytebuffer_encodeBase85);
                    AppendMethod(ctx, bytebuffer, "encodeBase91", bytebuffer_encodeBase91);
                    AppendMethod(ctx, bytebuffer, "decodeBase16", bytebuffer_decodeBase16);
                    AppendMethod(ctx, bytebuffer, "decodeBase32", bytebuffer_decodeBase32);
                    AppendMethod(ctx, bytebuffer, "decodeBase58", bytebuffer_decodeBase58);
                    AppendMethod(ctx, bytebuffer, "decodeBase62", bytebuffer_decodeBase62);
                    AppendMethod(ctx, bytebuffer, "decodeBase64", bytebuffer_decodeBase64);
                    AppendMethod(ctx, bytebuffer, "decodeBase85", bytebuffer_decodeBase85);
                    AppendMethod(ctx, bytebuffer, "decodeBase91", bytebuffer_decodeBase91);
                    AppendMethod(ctx, bytebuffer, "readAsString", bytebuffer_readAsString);
                    AppendMethod(ctx, bytebuffer, "readAsFormData", bytebuffer_readAsFormData);
                    AppendMethod(ctx, bytebuffer, "readAsJson", bytebuffer_readAsJson);
                    successCount++;
                }

                if (isAll || chosedModules.count("cjs:URL")) {
                    JSV URL = NewConstructor(ctx, "URL", global_URL);
                    AppendMethod(ctx, global, "URL", URL);
                    AppendMethod(ctx, URL, "createObjectURL", global_URL_createObjectURL);
                    AppendMethod(ctx, URL, "revokeObjectURL", global_URL_revokeObjectURL);
                    successCount++;
                }

                if (isAll || chosedModules.count("cjs:network_http")) {
                    JSV http = NewObject(ctx, GetProperty(ctx, global, "network"), "http");
                    SetSymbolName(ctx, http, "HttpNetwork");
                    AppendMethod(ctx, http, "open", network_http_open);
                    successCount++;
                }

                if (isAll || chosedModules.count("extension")) {
                    ApplyExtension(jsmd.js);
                    successCount++;
                }

                if (isAll || chosedModules.count("library")) {

                    FileController* fc = NewInstance<FileController>(L"./Library/", apppath(0));
                    if (fc->exists()) {
                        GMMT libraryList = fc->list();
                        for (auto& [name, path] : libraryList) {
                            if (!path.ends_with(L".dll")) continue;
                            if (InitLibrary(jsmdPtr, path)) successCount++;
                        }
                    }
                    delete fc;

                }

                if (!isAll) {
                    for (std::string name : chosedModulesList) {

                        if (name.starts_with("library:")) {
                            std::vector<std::string> ets = SplitString(name, ":");
                            if (ets.size() < 2) {
                            }
                            else {

                                std::wstring path = FormatPath(apppath(0) + L"./Library/" + stringToWstring(ets[1]));
                                if (InitLibrary(jsmdPtr, path)) successCount++;;

                            }
                        }

                        if (name.starts_with("extension:")) {
                            std::vector<std::string> ets = SplitString(name, ":");
                            if (ets.size() < 2) {
                            }
                            else {

                                std::wstring ppath = FormatPath(stringToWstring(ets[1]));
                                std::wstring path = FormatPath(L"./Extension/" + stringToWstring(ets[1]));
                                FileController fc = FileController(path, apppath(0));
                                if (!fc.exists()) {
                                }
                                else if (fc.isFile()) {
                                    BYTEBUFFER binary = {};
                                    bool status = fc.read(0, fc.size(), &binary);
                                    if (!status) {
                                    }
                                    else {
                                        std::wstring code = GetTextFromBYTEBUFFER(&binary);
                                        if (IsCodeEmpty(code)) {
                                        }
                                        else {
                                            JSINFO result = EvalInstance(jsmd.js, code, ppath);
                                            if (!result.isValid || !result.isSuccess) {
                                                CreateOutput(L"Extension:" + result.errorFront + L":" + result.message + L"\n", GetColorValue(L"Error"));
                                                OutputStack(result.errorStack);
                                            }
                                        }
                                    }
                                }
                                else {
                                    GMMT tempExtensionList = extensionList;
                                    extensionList = fc.list();
                                    ApplyExtension(jsmd.js);
                                    extensionList = tempExtensionList;
                                }

                                successCount++;

                            }
                        }

                    }
                }

                return NewUint64(ctx, successCount).get(1);
                });

            if (!isModuleMode) {
                jsmd.isAutoLoadModules = true;
                CallFunction(ctx, GetProperty(ctx, global, "include"), global, { {NewString(ctx, "all")} });
                jsmd.isAutoLoadModules = false;
            }

            const static std::wstring code = LR"(
system.help = (page)=>{
    const totalPage = 1;
    if (page == undefined) page = 1;
    if (page == 1) {
        console.log(`
CGI.JS自定义API使用帮助文档(第 ${page} 页 / 共 ${totalPage} 页)(属性说明顺序: 说明(子属性)，函数说明顺序：功能；参数；返回值；行为):
注意: 本API文档中省略并简写了对行为"传入参数类型或数量的不匹配则抛出类型错误(如果函数不额外抛出错误，则简写为'不抛出错误')\"的描述，因为此行为针对任意有参数函数都会触发。
window:
    include(...moduleName: string):void: 加载模块；(...moduleName: string)模块名称，即全局对象中或其他对象中的属性名称加特定前缀，内置模块写法为'cjs:[模块名称]'，关键字直接写'all'，'extension'；无返回值；不抛出错误。
    await(promise: Promise):void: 保持阻塞等待直到Promise的状态被更改；(promise: Promise)要等待的Promise对象；在Promise被解决时会返回其结果；行为与浏览器中的await关键字一致，若Promise被拒绝则会抛出错误并将Promise拒绝的结果作为错误原因，注意：如果Promise不被解决或拒绝，则此函数会永远保持阻塞状态。
    eval(code):any: 执行代码字符串；(code)要执行的代码；返回最后一次执行成功代码的返回值；与浏览器一致，传入非字符串类型原样返回，代码存在错误抛出。
    using(namespace: object[, where: object]):boolean: 将指定对象的所有属性复写到指定位置；(namespace: object)要被复写的对象，(where: object)要复写的目标对象，默认为全局对象；返回操作状态。
    wait(milliseconds: number):void: 阻塞等待指定的时间(毫秒)，由于受到系统时钟精度的影响，实际等待实际可能存在10毫秒以内的波动；(milliseconds: number)指定的时间，仅可为正整数或0；无返回值；数据不正确抛出类型错误。
    this_close():void: 此方法仅在子上下文的全局对象即通过script.execute(...)函数创建并返回的全局对象中可用，关闭当前上下文并该上下文的清空全局对象；无参数；无返回值；重复关闭抛出类型错误。
system: 
    help([page: number]):void: 显示当前界面；([page])可选页码，默认为1；无返回值；传入错误页码无输出，不抛出错误。
    exit():void: 结束当前上下文，在交互式模式下主上下文被结束后会退出程序；无参数；无返回值；在底层出错时抛出内部错误。
    updateConfig(config: object):void: 更新底层配置；(config: object)配置对象；无返回值；不抛出错误。
    saveConfig():boolean: 保存底层配置到文件；无参数；返回操作状态；不抛出错误。
    cwd():string: 返回当前执行脚本的工作目录；无参数；成功返回目录(以'/'为分隔符，末尾带'/')，失败返回可执行文件所在目录；不抛出错误。
    ecwd():string: 返回当前可执行文件所在目录；无参数；返回目录(以'/'为分隔符，末尾带'/')；不抛出错误。
    execute(cmd: string):object: 在新的命令提示符中执行一段命令；(cmd: string)要执行的cmd命令；返回操作对象，包含(isSuccess: boolean)操作状态，(exitCode: uint64)退出码，(output: string)所有输出结果。
    config:object: 配置对象。
script:
    include(...path: string[]):void: 引入一个或多个本地js文件，支持绝对路径与相对路径，正斜杠分隔符与反斜杠分隔符，相对路径基于脚本执行目录(在交互式模式下为可执行文件所在目录)(下同)；(...path: string[])剩余路径，允许一次传入多个本地路径；无返回值；在文件任意文件不存在或任意文件读取失败时抛出内部错误，在任意引入文件存在错误时中断后续引入并抛出默认错误。
    execute([path: string]):object: 引入一个本地js文件，支持类型同上include(...)函数；([path: string])可选路径；返回新上下文的全局对象；在未传参时会直接返回新上下文的全局对象，在上下文创建失败或在传参且目标文件不存在或读取失败时抛出内部错误，在引入的文件存在错误时中断引入并抛出默认错误，返回值为未初始化。
console:
    log([...data]):void: 在控制台输出任意类型的数据；([...data])可选的剩余数据，允许一次输出多个数据，输出时将使用','分隔；无返回值；和浏览器一致，不抛出错误。
    pause():void: 仅在控制台交互式模式下生效，暂停控制台输入流，注意：操作有1ms延迟，仅同步生效；无参数；无返回值；重复暂停不抛出错误。
    resume():void: 仅在控制台交互式模式下生效，恢复控制台输入流，注意：操作有1ms延迟，仅同步生效；无参数；无返回值；重复继续不抛出错误。
    hide():void: 隐藏控制台，注意：部分操作系统上会被处理为最小化；无参数；无返回值；不抛出错误。
    show():void: 恢复已隐藏控制台；无参数；无返回值；不抛出错误。
    kill():void: 关闭已有的控制台，这不会导致程序退出，注意：仅在文件执行模式下可用；无参数；无返回值；不抛出错误。
    restore([title: string]):void: 恢复已关闭的控制台，这不会导致程序有多个控制台，注意：仅在文件执行模式下可用；([title: string])可选控制台窗口标题；无返回值；不抛出错误。
filesystem:
    open(path: string[, mode: string]):object: 打开一个文件；(path: string)路径，在读模式下文件必须存在，([mode: string])模式；返回文件操作对象；行为与Python3+一致。
    exists(path: string):boolean: 检查一个文件是否存在；(path: string)路径；返回存在状况；不抛出错误。
    count(path: string):uint64: 返回一个目录下所有文件、文件夹的数量(不包括本身)；(path: string)路径；返回数量；在路径不为目录或不存在时抛出类型错误。
    remove(path: string):uint64: 删除一个文件或文件夹；(path: string)路径；返回删除数量(如果删除文件夹，则还包括文件夹本身以及所有子文件或文件夹)；文件或文件夹不存在返回类型错误。
crypto: 标准Web Crypto API。
bytebuffer:
    readAsJson(data: Uint8Array):Promise<object>: 异步将二进制字节数据解析为JSON对象；(data: Uint8Array)要解析的二进制字节数据；返回Promise对象，解决时返回解析后的JSON对象，拒绝时返回语法错误；解析JSON失败时抛出语法错误，参数类型不匹配抛出类型错误。
    readAsFormData(data: Uint8Array):Promise<FormData>: 异步将二进制字节数据转换为FormData对象；(data: Uint8Array)要转换的二进制字节数据；返回Promise对象，解决时返回FormData对象，拒绝时返回对应错误；创建FormData失败时抛出内部错误，参数类型不匹配抛出类型错误。
    readAsString(data: Uint8Array):Promise<string>: 异步将二进制字节数据转换为字符串；(data: Uint8Array)要转换的二进制字节数据；返回Promise对象，解决时返回转换后的字符串；参数类型不匹配抛出类型错误，不额外抛出错误。
    decodeBase91(data: string[, isUrlEncoding: boolean]):Promise<Uint8Array>: 异步将Base91编码字符串解码为二进制字节数据；(data: string)Base91编码字符串，([isUrlEncoding: boolean])是否为URL安全编码，默认为false；返回Promise对象，解决时返回Uint8Array类型二进制数据，拒绝时返回内部错误；解码失败抛出内部错误，第二个参数非布尔值抛出类型错误。
    decodeBase85(data: string):Promise<Uint8Array>: 异步将Base85编码字符串解码为二进制字节数据；(data: string)Base85编码字符串；返回Promise对象，解决时返回Uint8Array类型二进制数据，拒绝时返回内部错误；解码失败抛出内部错误，参数类型不匹配抛出类型错误。
    decodeBase64(data: string[, isUrlEncoding: boolean]):Promise<Uint8Array>: 异步将Base64编码字符串解码为二进制字节数据；(data: string)Base64编码字符串，([isUrlEncoding: boolean])是否为URL安全编码，默认为false；返回Promise对象，解决时返回Uint8Array类型二进制数据，拒绝时返回内部错误；解码失败抛出内部错误，第二个参数非布尔值抛出类型错误。
    decodeBase62(data: string):Promise<Uint8Array>: 异步将Base62编码字符串解码为二进制字节数据；(data: string)Base62编码字符串；返回Promise对象，解决时返回Uint8Array类型二进制数据，拒绝时返回内部错误；解码失败抛出内部错误，参数类型不匹配抛出类型错误。
    decodeBase58(data: string):Promise<Uint8Array>: 异步将Base58编码字符串解码为二进制字节数据；(data: string)Base58编码字符串；返回Promise对象，解决时返回Uint8Array类型二进制数据，拒绝时返回内部错误；解码失败抛出内部错误，参数类型不匹配抛出类型错误。
    decodeBase32(data: string):Promise<Uint8Array>: 异步将Base32编码字符串解码为二进制字节数据；(data: string)Base32编码字符串；返回Promise对象，解决时返回Uint8Array类型二进制数据，拒绝时返回内部错误；解码失败抛出内部错误，参数类型不匹配抛出类型错误。
    decodeBase16(data: string):Promise<Uint8Array>: 异步将Base16编码字符串解码为二进制字节数据；(data: string)Base16编码字符串；返回Promise对象，解决时返回Uint8Array类型二进制数据，拒绝时返回内部错误；解码失败抛出内部错误，参数类型不匹配抛出类型错误。
    encodeBase91(data: Uint8Array[, isUrlEncoding: boolean]):Promise<string>: 异步将二进制字节数据编码为Base91字符串；(data: Uint8Array)要编码的二进制字节数据，([isUrlEncoding: boolean])是否使用URL安全编码，默认为false；返回Promise对象，解决时返回Base91编码字符串，拒绝时返回内部错误；编码失败抛出内部错误，第二个参数非布尔值抛出类型错误。
    encodeBase85(data: Uint8Array):Promise<string>: 异步将二进制字节数据编码为Base85字符串；(data: Uint8Array)要编码的二进制字节数据；返回Promise对象，解决时返回Base85编码字符串，拒绝时返回内部错误；编码失败抛出内部错误，参数类型不匹配抛出类型错误。
    encodeBase64(data: Uint8Array[, isUrlEncoding: boolean]):Promise<string>: 异步将二进制字节数据编码为Base64字符串；(data: Uint8Array)要编码的二进制字节数据，([isUrlEncoding: boolean])是否使用URL安全编码，默认为false；返回Promise对象，解决时返回Base64编码字符串，拒绝时返回内部错误；编码失败抛出内部错误，第二个参数非布尔值抛出类型错误。
    encodeBase62(data: Uint8Array):Promise<string>: 异步将二进制字节数据编码为Base62字符串；(data: Uint8Array)要编码的二进制字节数据；返回Promise对象，解决时返回Base62编码字符串，拒绝时返回内部错误；编码失败抛出内部错误，参数类型不匹配抛出类型错误。
    encodeBase58(data: Uint8Array):Promise<string>: 异步将二进制字节数据编码为Base58字符串；(data: Uint8Array)要编码的二进制字节数据；返回Promise对象，解决时返回Base58编码字符串，拒绝时返回内部错误；编码失败抛出内部错误，参数类型不匹配抛出类型错误。
    encodeBase32(data: Uint8Array):Promise<string>: 异步将二进制字节数据编码为Base32字符串；(data: Uint8Array)要编码的二进制字节数据；返回Promise对象，解决时返回Base32编码字符串，拒绝时返回内部错误；编码失败抛出内部错误，参数类型不匹配抛出类型错误。
    encodeBase16(data: Uint8Array):Promise<string>: 异步将二进制字节数据编码为Base16字符串；(data: Uint8Array)要编码的二进制字节数据；返回Promise对象，解决时返回Base16编码字符串，拒绝时返回内部错误；编码失败抛出内部错误，参数类型不匹配抛出类型错误。
    toBinary(data: any):Promise<Uint8Array>: 异步将任意支持类型的数据转换为Uint8Array二进制字节数据；(data: any)要转换的数据；返回Promise对象，解决时返回Uint8Array类型二进制数据；参数类型不支持时抛出类型错误，不额外抛出错误。
    toString(data: Uint8Array):Promise<string>: 异步将二进制字节数据转换为字符串；(data: Uint8Array)要转换的二进制字节数据；返回Promise对象，解决时返回转换后的字符串；参数类型不匹配抛出类型错误，不额外抛出错误。
 `);
    }
};
			)";

            EvalInstance(jsmd.js, code, L"buildIn");

        }
        ~JavaScriptMethod() {

            OutputDebugStringW(L"JSM被析构\n");

            JSContext* ctx = nullptr;
            JSMData* jsmd = nullptr;

            for (auto& [cctx, cjsmd] : jsinfo) {
                if (cjsmd.jsm == this) {
                    ctx = cctx;
                    jsmd = &cjsmd;
                    break;
                }
            }

            if (ctx != nullptr && jsmd != nullptr) {

                jsmd->isQuit = true;

                while (true) {
                    if (!jsmd->isRunningTask) break;
                    AdvSleep(1.0);
                    continue;
                }

                jsmd->threadList.clear();

                for (HMODULE hm : jsmd->hModuleList) {
                    if (hm != NULL) {
                        UnInitLibrary(jsmd, hm);
                        FreeLibrary(hm);
                    }
                }
                jsmd->hModuleList.clear();

                for (auto& [id, data] : jsmd->argumentPackageList) {
                    delete[] data.argumentValues;
                }
                jsmd->argumentPackageList.clear();

                for (auto& [id, data] : jsmd->cjsByteDataList) {
                    FreeHeapData(data);
                }
                jsmd->cjsByteDataList.clear();

                for (auto& [id, fc] : jsmd->fileControllerList) {
                    if (fc != nullptr) {
                        delete fc;
                        fc = nullptr;
                    }
                }
                jsmd->fileControllerList.clear();

                for (auto& [id, xhr] : jsmd->networkHttpList) {
                    if (xhr != nullptr) {
                        delete xhr;
                        xhr = nullptr;
                    }
                }
                jsmd->networkHttpList.clear();

                for (auto& [id, js] : jsmd->executeJsList) {
                    if (js != nullptr) {
                        DeleteInstance(js);
                        js = nullptr;
                    }
                }
                jsmd->executeJsList.clear();


                jsmd->hModuleCJSValueList.clear();
                jsmd->promiseList.clear();
                jsmd->taskList.clear();
                jsmd->runnedTaskList.clear();
                jsmd->timeoutList.clear();
                jsmd->formDataList.clear();
                jsmd->releaseList.clear();

            }

            RemoveData(ctx);
            jsmd = nullptr;
            ctx = nullptr;
        }

        static JSValue network_http_open(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {

            if (argumentCount < 2 || argumentCount > 5) {
                JS_ThrowTypeError(ctx, "[network.http.open] Only 5 arguments are supported: (method, url, async?, username?, password?)");
                return JS_EXCEPTION;
            }

            JSV js_method = JSV(ctx, &argumentValues[0]).cget(1).cset(1);
            JSV js_url = JSV(ctx, &argumentValues[1]).cget(1).cset(1);
            JSV js_async = (argumentCount >= 3) ? JSV(ctx, &argumentValues[2]).cget(1).cset(1) : NewBool(ctx, true);
            JSV js_username = (argumentCount >= 4) ? JSV(ctx, &argumentValues[3]).cget(1).cset(1) : NewString(ctx, "");
            JSV js_password = (argumentCount >= 5) ? JSV(ctx, &argumentValues[4]).cget(1).cset(1) : NewString(ctx, "");

            std::string method = "";
            if (!ReadJSValueAsString(ctx, js_method, method)) {
                JS_ThrowTypeError(ctx, "[network.http.open] The first argument must be a string");
                return JS_EXCEPTION;
            }
            std::string url = "";
            if (!ReadJSValueAsString(ctx, js_url, url)) {
                JS_ThrowTypeError(ctx, "[network.http.open] The second argument must be a string");
                return JS_EXCEPTION;
            }
            bool isAsync = true;
            if (!ReadJSValueAsBool(ctx, js_async, isAsync)) {
                JS_ThrowTypeError(ctx, "[network.http.open] The third argument must be a boolean");
                return JS_EXCEPTION;
            }
            std::string username = "";
            if (!ReadJSValueAsString(ctx, js_username, username)) {
                JS_ThrowTypeError(ctx, "[network.http.open] The fourth argument must be a string");
                return JS_EXCEPTION;
            }
            std::string password = "";
            if (!ReadJSValueAsString(ctx, js_password, password)) {
                JS_ThrowTypeError(ctx, "[network.http.open] The fifth argument must be a string");
                return JS_EXCEPTION;
            }

            JSMData* jsmdPtr = nullptr;
            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                return JS_EXCEPTION;
            }

            ULL id = GetNewNetworkHttpId(ctx);

            XMLHttpRequest* xhr = NewInstance<XMLHttpRequest>();
            if (xhr == nullptr) {
                JS_ThrowInternalError(ctx, "[network.http.open] Failed to open");
                return JS_EXCEPTION;
            }
            jsmdPtr->networkHttpList[id] = xhr;

            JSV returnValue = NewObject(ctx);
            SetSymbolName(ctx, returnValue, "XMLHttpRequest");

            SetAttribute(ctx, returnValue, "id", NewUint64(ctx, id), 0);
            SetAttribute(ctx, returnValue, "isAsync", NewBool(ctx, isAsync), 0);

            SetAttribute(ctx, returnValue, "DONE", NewNumber(ctx, 4), 0);
            SetAttribute(ctx, returnValue, "LOADING", NewNumber(ctx, 3), 0);
            SetAttribute(ctx, returnValue, "HEADERS_RECEIVED", NewNumber(ctx, 2), 0);
            SetAttribute(ctx, returnValue, "OPENED", NewNumber(ctx, 1), 0);
            SetAttribute(ctx, returnValue, "UNSENT", NewNumber(ctx, 0), 0);

            xhr->open(stringToWstring(method), stringToWstring(url), false, stringToWstring(username), stringToWstring(password));

            SetAttribute(ctx, returnValue, "readyState", NewNumber(ctx, xhr->readyState));
            SetAttribute(ctx, returnValue, "response", NewString(ctx, ""));
            SetAttribute(ctx, returnValue, "responseType", NewString(ctx, ""));

            SetAttribute(ctx, returnValue, "status", NewNumber(ctx, 0));
            SetAttribute(ctx, returnValue, "statusText", NewString(ctx, ""));

            SetAttribute(ctx, returnValue, "onreadystatechange", JS_NULL);
            SetAttribute(ctx, returnValue, "onloadstart", JS_NULL);
            SetAttribute(ctx, returnValue, "onload", JS_NULL);
            SetAttribute(ctx, returnValue, "onloadend", JS_NULL);
            SetAttribute(ctx, returnValue, "onprogress", JS_NULL);
            SetAttribute(ctx, returnValue, "onerror", JS_NULL);
            SetAttribute(ctx, returnValue, "onabort", JS_NULL);
            SetAttribute(ctx, returnValue, "ontimeout", JS_NULL);
            SetAttribute(ctx, returnValue, "onheadersreceived", JS_NULL);

            JSV upload = NewObject(ctx);
            SetSymbolName(ctx, upload, "XMLHttpRequestUpload");
            SetAttribute(ctx, returnValue, "upload", upload);
            SetAttribute(ctx, upload, "onloadstart", JS_NULL);
            SetAttribute(ctx, upload, "onload", JS_NULL);
            SetAttribute(ctx, upload, "onloadend", JS_NULL);
            SetAttribute(ctx, upload, "onprogress", JS_NULL);
            SetAttribute(ctx, upload, "onerror", JS_NULL);
            SetAttribute(ctx, upload, "onabort", JS_NULL);
            SetAttribute(ctx, upload, "ontimeout", JS_NULL);

            xhr->onreadystatechange = [=]() {
                SetAttribute(ctx, returnValue, "readyState", NewNumber(ctx, static_cast<double>(xhr->readyState)));
                if (xhr->readyState == 3) {
                    SetAttribute(ctx, returnValue, "status", NewNumber(ctx, static_cast<double>(xhr->status)));
                    SetAttribute(ctx, returnValue, "statusText", NewString(ctx, wstringToString(xhr->statusText)));
                }

                JSV callback = GetProperty(ctx, returnValue, "onreadystatechange");
                if (callback.isValid() && JS_IsFunction(ctx, callback.get(0))) CallFunction(ctx, callback, returnValue, {}, true);
                };

            auto onload = [=](JSV callback) {
                JSV callbackValue = NewObject(ctx);
                SetSymbolName(ctx, callbackValue, "ProgressEvent");

                SetAttribute(ctx, callbackValue, "type", NewString(ctx, "load"));
                SetAttribute(ctx, callbackValue, "loaded", NewNumber(ctx, static_cast<double>(xhr->loaded)));
                SetAttribute(ctx, callbackValue, "total", NewNumber(ctx, static_cast<double>(xhr->total)));
                SetAttribute(ctx, callbackValue, "lengthComputable", NewBool(ctx, (xhr->total != 0) ? true : false));
                SetAttribute(ctx, callbackValue, "target", returnValue);

                if (callback.isValid() && JS_IsFunction(ctx, callback.get(0))) CallFunction(ctx, callback, returnValue, { {callbackValue} }, true);
                };
            xhr->onload = [=](...) {
                onload(GetProperty(ctx, returnValue, "onload"));
                };

            auto onuploadload = [=](const XHRPROGRESSEVENT& e) {
                JSV callbackValue = NewObject(ctx);
                SetSymbolName(ctx, callbackValue, "ProgressEvent");
                SetAttribute(ctx, callbackValue, "type", NewString(ctx, "load"));
                SetAttribute(ctx, callbackValue, "loaded", NewNumber(ctx, static_cast<double>(e.loaded)));
                SetAttribute(ctx, callbackValue, "total", NewNumber(ctx, static_cast<double>(e.total)));
                SetAttribute(ctx, callbackValue, "lengthComputable", NewBool(ctx, e.total != 0));
                SetAttribute(ctx, callbackValue, "target", returnValue);
                JSV callback = GetProperty(ctx, returnValue, { {"upload"}, {"onload"} });
                if (callback.isValid() && JS_IsFunction(ctx, callback.get(0)))
                    CallFunction(ctx, callback, returnValue, { {callbackValue} }, true);
                };
            xhr->upload.onload = onuploadload;

            auto onloadstart = [=](JSV callback) {
                JSV callbackValue = NewObject(ctx);
                SetSymbolName(ctx, callbackValue, "ProgressEvent");

                SetAttribute(ctx, callbackValue, "type", NewString(ctx, "loadstart"));
                SetAttribute(ctx, callbackValue, "loaded", NewNumber(ctx, 0.0));
                SetAttribute(ctx, callbackValue, "total", NewNumber(ctx, 0.0));
                SetAttribute(ctx, callbackValue, "lengthComputable", NewBool(ctx, false));
                SetAttribute(ctx, callbackValue, "target", returnValue);

                if (callback.isValid() && JS_IsFunction(ctx, callback.get(0))) CallFunction(ctx, callback, returnValue, { {callbackValue} }, true);
                };
            xhr->onloadstart = [=](...) {
                onloadstart(GetProperty(ctx, returnValue, "onloadstart"));
                };

            auto onuploadstart = [=](const XHRPROGRESSEVENT& e) {
                JSV callbackValue = NewObject(ctx);
                SetSymbolName(ctx, callbackValue, "ProgressEvent");
                SetAttribute(ctx, callbackValue, "type", NewString(ctx, "loadstart"));
                SetAttribute(ctx, callbackValue, "loaded", NewNumber(ctx, static_cast<double>(e.loaded)));
                SetAttribute(ctx, callbackValue, "total", NewNumber(ctx, static_cast<double>(e.total)));
                SetAttribute(ctx, callbackValue, "lengthComputable", NewBool(ctx, false));
                SetAttribute(ctx, callbackValue, "target", returnValue);
                JSV callback = GetProperty(ctx, returnValue, { {"upload"}, {"onloadstart"} });
                if (callback.isValid() && JS_IsFunction(ctx, callback.get(0)))
                    CallFunction(ctx, callback, returnValue, { {callbackValue} }, true);
                };
            xhr->upload.onloadstart = onuploadstart;

            auto onprogress = [=](JSV callback) {
                std::string responseType = "";
                ReadJSValueAsString(ctx, GetProperty(ctx, returnValue, "responseType"), responseType);
                responseType = wstringToString(ToDownLetters(stringToWstring(responseType)));
                if (responseType == "" || responseType == "text") {
                    SetAttribute(ctx, returnValue, "response", NewString(ctx, GetTextFromBinarySafely(&xhr->response)));
                }
                else if (responseType == "json") {
                    std::wstring text = GetTextFromBYTEBUFFER(&xhr->response);
                    OBJECT jsonObject = {};
                    try {
                        jsonObject = JSON.parse(text);
                    }
                    catch (...) {}
                    SetAttribute(ctx, returnValue, "response", NewObject(ctx, jsonObject));
                }
                else if (responseType == "arrayBuffer") {
                    SetAttribute(ctx, returnValue, "response", NewArrayBuffer(ctx, xhr->response));
                }
                else {
                    SetAttribute(ctx, returnValue, "response", NewUint8Array(ctx, xhr->response));
                }

                JSV callbackValue = NewObject(ctx);
                SetSymbolName(ctx, callbackValue, "ProgressEvent");

                SetAttribute(ctx, callbackValue, "type", NewString(ctx, "progress"));
                SetAttribute(ctx, callbackValue, "loaded", NewNumber(ctx, static_cast<double>(xhr->loaded)));
                SetAttribute(ctx, callbackValue, "total", NewNumber(ctx, static_cast<double>(xhr->total)));
                SetAttribute(ctx, callbackValue, "lengthComputable", NewBool(ctx, (xhr->total != 0) ? true : false));
                SetAttribute(ctx, callbackValue, "target", returnValue);

                if (callback.isValid() && JS_IsFunction(ctx, callback.get(0))) CallFunction(ctx, callback, returnValue, { {callbackValue} }, true);
                };
            xhr->onprogress = [=](...) {
                onprogress(GetProperty(ctx, returnValue, "onprogress"));
                };

            auto onuploadprogress = [=](const XHRPROGRESSEVENT& e) {
                JSV callbackValue = NewObject(ctx);
                SetSymbolName(ctx, callbackValue, "ProgressEvent");
                SetAttribute(ctx, callbackValue, "type", NewString(ctx, "progress"));
                SetAttribute(ctx, callbackValue, "loaded", NewNumber(ctx, static_cast<double>(e.loaded)));
                SetAttribute(ctx, callbackValue, "total", NewNumber(ctx, static_cast<double>(e.total)));
                SetAttribute(ctx, callbackValue, "lengthComputable", NewBool(ctx, e.total != 0));
                SetAttribute(ctx, callbackValue, "target", returnValue);
                JSV callback = GetProperty(ctx, returnValue, { {"upload"}, {"onprogress"} });
                if (callback.isValid() && JS_IsFunction(ctx, callback.get(0)))
                    CallFunction(ctx, callback, returnValue, { {callbackValue} }, true);
                };
            xhr->upload.onprogress = onuploadprogress;

            auto onerror = [=](JSV callback) {
                JSV callbackValue = NewObject(ctx);
                SetSymbolName(ctx, callbackValue, "ProgressEvent");

                SetAttribute(ctx, callbackValue, "type", NewString(ctx, "error"));
                SetAttribute(ctx, callbackValue, "loaded", NewNumber(ctx, static_cast<double>(xhr->loaded)));
                SetAttribute(ctx, callbackValue, "total", NewNumber(ctx, 0.0));
                SetAttribute(ctx, callbackValue, "lengthComputable", NewBool(ctx, false));
                SetAttribute(ctx, callbackValue, "target", returnValue);

                if (callback.isValid() && JS_IsFunction(ctx, callback.get(0))) CallFunction(ctx, callback, returnValue, { {callbackValue} }, true);
                };
            xhr->onerror = [=](...) {
                onerror(GetProperty(ctx, returnValue, "onerror"));
                };

            auto onuploaderror = [=](const XHRPROGRESSEVENT& e) {
                JSV callbackValue = NewObject(ctx);
                SetSymbolName(ctx, callbackValue, "ProgressEvent");
                SetAttribute(ctx, callbackValue, "type", NewString(ctx, "error"));
                SetAttribute(ctx, callbackValue, "loaded", NewNumber(ctx, static_cast<double>(e.loaded)));
                SetAttribute(ctx, callbackValue, "total", NewNumber(ctx, static_cast<double>(e.total)));
                SetAttribute(ctx, callbackValue, "lengthComputable", NewBool(ctx, false));
                SetAttribute(ctx, callbackValue, "target", returnValue);
                JSV callback = GetProperty(ctx, returnValue, { {"upload"}, {"onerror"} });
                if (callback.isValid() && JS_IsFunction(ctx, callback.get(0)))
                    CallFunction(ctx, callback, returnValue, { {callbackValue} }, true);
                };
            xhr->upload.onerror = onuploaderror;

            auto ontimeout = [=](JSV callback) {
                JSV callbackValue = NewObject(ctx);
                SetSymbolName(ctx, callbackValue, "ProgressEvent");

                SetAttribute(ctx, callbackValue, "type", NewString(ctx, "timeout"));
                SetAttribute(ctx, callbackValue, "loaded", NewNumber(ctx, static_cast<double>(xhr->loaded)));
                SetAttribute(ctx, callbackValue, "total", NewNumber(ctx, 0.0));
                SetAttribute(ctx, callbackValue, "lengthComputable", NewBool(ctx, false));
                SetAttribute(ctx, callbackValue, "target", returnValue);

                if (callback.isValid() && JS_IsFunction(ctx, callback.get(0))) CallFunction(ctx, callback, returnValue, { {callbackValue} }, true);
                };
            xhr->ontimeout = [=](...) {
                ontimeout(GetProperty(ctx, returnValue, "ontimeout"));
                };

            auto onuploadtimeout = [=](const XHRPROGRESSEVENT& e) {
                JSV callbackValue = NewObject(ctx);
                SetSymbolName(ctx, callbackValue, "ProgressEvent");
                SetAttribute(ctx, callbackValue, "type", NewString(ctx, "timeout"));
                SetAttribute(ctx, callbackValue, "loaded", NewNumber(ctx, static_cast<double>(e.loaded)));
                SetAttribute(ctx, callbackValue, "total", NewNumber(ctx, static_cast<double>(e.total)));
                SetAttribute(ctx, callbackValue, "lengthComputable", NewBool(ctx, false));
                SetAttribute(ctx, callbackValue, "target", returnValue);
                JSV callback = GetProperty(ctx, returnValue, { {"upload"}, {"ontimeout"} });
                if (callback.isValid() && JS_IsFunction(ctx, callback.get(0)))
                    CallFunction(ctx, callback, returnValue, { {callbackValue} }, true);
                };
            xhr->upload.ontimeout = onuploadtimeout;

            auto onabort = [=](JSV callback) {
                JSV callbackValue = NewObject(ctx);
                SetSymbolName(ctx, callbackValue, "ProgressEvent");

                SetAttribute(ctx, callbackValue, "type", NewString(ctx, "abort"));
                SetAttribute(ctx, callbackValue, "loaded", NewNumber(ctx, static_cast<double>(xhr->loaded)));
                SetAttribute(ctx, callbackValue, "total", NewNumber(ctx, 0.0));
                SetAttribute(ctx, callbackValue, "lengthComputable", NewBool(ctx, false));
                SetAttribute(ctx, callbackValue, "target", returnValue);

                if (callback.isValid() && JS_IsFunction(ctx, callback.get(0))) CallFunction(ctx, callback, returnValue, { {callbackValue} }, true);
                };
            xhr->onabort = [=](...) {
                onabort(GetProperty(ctx, returnValue, "onabort"));
                };

            auto onuploadabort = [=](const XHRPROGRESSEVENT& e) {
                JSV callbackValue = NewObject(ctx);
                SetSymbolName(ctx, callbackValue, "ProgressEvent");
                SetAttribute(ctx, callbackValue, "type", NewString(ctx, "abort"));
                SetAttribute(ctx, callbackValue, "loaded", NewNumber(ctx, static_cast<double>(e.loaded)));
                SetAttribute(ctx, callbackValue, "total", NewNumber(ctx, static_cast<double>(e.total)));
                SetAttribute(ctx, callbackValue, "lengthComputable", NewBool(ctx, false));
                SetAttribute(ctx, callbackValue, "target", returnValue);
                JSV callback = GetProperty(ctx, returnValue, { {"upload"}, {"onabort"} });
                if (callback.isValid() && JS_IsFunction(ctx, callback.get(0)))
                    CallFunction(ctx, callback, returnValue, { {callbackValue} }, true);
                };
            xhr->upload.onabort = onuploadabort;

            auto onloadend = [=](XHRPROGRESSEVENT event, JSV callback) {
                std::string responseType = "";
                ReadJSValueAsString(ctx, GetProperty(ctx, returnValue, "responseType"), responseType);
                responseType = wstringToString(ToDownLetters(stringToWstring(responseType)));
                if (responseType == "" || responseType == "text") {
                    SetAttribute(ctx, returnValue, "response", NewString(ctx, GetTextFromBinarySafely(&xhr->response)));
                }
                else if (responseType == "json") {
                    std::wstring text = GetTextFromBYTEBUFFER(&xhr->response);
                    OBJECT jsonObject = {};
                    try {
                        jsonObject = JSON.parse(text);
                    }
                    catch (...) {}
                    SetAttribute(ctx, returnValue, "response", NewObject(ctx, jsonObject));
                }
                else if (responseType == "arrayBuffer") {
                    SetAttribute(ctx, returnValue, "response", NewArrayBuffer(ctx, xhr->response));
                }
                else {
                    SetAttribute(ctx, returnValue, "response", NewUint8Array(ctx, xhr->response));
                }

                JSV callbackValue = NewObject(ctx);
                SetSymbolName(ctx, callbackValue, "ProgressEvent");

                SetAttribute(ctx, callbackValue, "type", NewString(ctx, "loadend"));
                SetAttribute(ctx, callbackValue, "loaded", NewNumber(ctx, static_cast<double>(event.loaded)));
                SetAttribute(ctx, callbackValue, "total", NewNumber(ctx, static_cast<double>(event.total)));
                SetAttribute(ctx, callbackValue, "lengthComputable", NewBool(ctx, event.lengthComputable));
                SetAttribute(ctx, callbackValue, "target", returnValue);

                if (callback.isValid() && JS_IsFunction(ctx, callback.get(0))) CallFunction(ctx, callback, returnValue, { {callbackValue} }, true);
                };
            xhr->onloadend = [=](XHRPROGRESSEVENT event) {
                onloadend(event, GetProperty(ctx, returnValue, "onloadend"));
                };

            auto onuploadend = [=](XHRPROGRESSEVENT event) {
                onloadend(event, GetProperty(ctx, returnValue, { {"upload"}, {"onloadend"} }));
                };
            xhr->upload.onloadend = onuploadend;

            xhr->onheadersreceived = [=](...) {
                JSV callbackValue = NewObject(ctx);
                SetSymbolName(ctx, callbackValue, "ProgressEvent");

                SetAttribute(ctx, callbackValue, "type", NewString(ctx, "headersreceived"));
                SetAttribute(ctx, callbackValue, "loaded", NewNumber(ctx, 0.0));
                SetAttribute(ctx, callbackValue, "total", NewNumber(ctx, 0.0));
                SetAttribute(ctx, callbackValue, "lengthComputable", NewBool(ctx, false));
                SetAttribute(ctx, callbackValue, "target", returnValue);

                JSV callback = GetProperty(ctx, returnValue, "onheadersreceived");
                if (callback.isValid() && JS_IsFunction(ctx, callback.get(0))) CallFunction(ctx, callback, returnValue, { {callbackValue} }, true);
                };

            AppendMethod(ctx, returnValue, "open", [](JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues)->JSValue {
                if (argumentCount < 2 || argumentCount > 5) {
                    JS_ThrowTypeError(ctx, "[network.http.open->open] Only 5 arguments are supported: (method, url, async?, username?, password?)");
                    return JS_EXCEPTION;
                }

                JSV js_method = JSV(ctx, &argumentValues[0]).cget(1).cset(1);
                JSV js_url = JSV(ctx, &argumentValues[1]).cget(1).cset(1);
                JSV js_async = (argumentCount >= 3) ? JSV(ctx, &argumentValues[2]).cget(1).cset(1) : NewBool(ctx, true);
                JSV js_username = (argumentCount >= 4) ? JSV(ctx, &argumentValues[3]).cget(1).cset(1) : NewString(ctx, "");
                JSV js_password = (argumentCount >= 5) ? JSV(ctx, &argumentValues[4]).cget(1).cset(1) : NewString(ctx, "");

                std::string method = "";
                if (!ReadJSValueAsString(ctx, js_method, method)) {
                    JS_ThrowTypeError(ctx, "[network.http.open] The first argument must be a string");
                    return JS_EXCEPTION;
                }
                std::string url = "";
                if (!ReadJSValueAsString(ctx, js_url, url)) {
                    JS_ThrowTypeError(ctx, "[network.http.open] The second argument must be a string");
                    return JS_EXCEPTION;
                }
                bool isAsync = true;
                if (!ReadJSValueAsBool(ctx, js_async, isAsync)) {
                    JS_ThrowTypeError(ctx, "[network.http.open] The third argument must be a boolean");
                    return JS_EXCEPTION;
                }
                std::string username = "";
                if (!ReadJSValueAsString(ctx, js_username, username)) {
                    JS_ThrowTypeError(ctx, "[network.http.open] The fourth argument must be a string");
                    return JS_EXCEPTION;
                }
                std::string password = "";
                if (!ReadJSValueAsString(ctx, js_password, password)) {
                    JS_ThrowTypeError(ctx, "[network.http.open] The fifth argument must be a string");
                    return JS_EXCEPTION;
                }

                JSMData* jsmdPtr = nullptr;
                if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                    JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                    return JS_EXCEPTION;
                }

                JSV js_id = GetProperty(ctx, thisVal, "id");
                ULL id = 0;
                if (!ReadJSValueAsUint64(ctx, js_id, id) || !jsmdPtr->networkHttpList.count(id)) {
                    JS_ThrowInternalError(ctx, "[network.http.open] This instance is invalid");
                    return JS_EXCEPTION;
                }
                XMLHttpRequest* xhr = jsmdPtr->networkHttpList[id];

                xhr->open(stringToWstring(method), stringToWstring(url), false, stringToWstring(username), stringToWstring(password));

                SetAttribute(ctx, thisVal, "readyState", NewUint64(ctx, 0));
                SetAttribute(ctx, thisVal, "response", NewString(ctx, ""));
                SetAttribute(ctx, thisVal, "responseType", NewString(ctx, ""));

                SetAttribute(ctx, thisVal, "status", NewUint64(ctx, 0));
                SetAttribute(ctx, thisVal, "statusText", NewString(ctx, ""));

                return JS_UNDEFINED;
                });
            AppendMethod(ctx, returnValue, "send", [](JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) -> JSValue {

                JSMData* jsmdPtr = nullptr;
                if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                    JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                    return JS_EXCEPTION;
                }

                JSV js_id = GetProperty(ctx, thisVal, "id");
                ULL id = 0;
                if (!ReadJSValueAsUint64(ctx, js_id, id) || !jsmdPtr->networkHttpList.count(id)) {
                    JS_ThrowInternalError(ctx, "[network.http.open] This instance is invalid");
                    return JS_EXCEPTION;
                }
                XMLHttpRequest* xhr = jsmdPtr->networkHttpList[id];

                if (xhr->readyState != XHRReadyState::OPENED || xhr->isSended) {
                    JS_ThrowInternalError(ctx, "[network.http.open->send] The object's state must be OPENED");
                    return JS_EXCEPTION;
                }

                uint64_t timeout = 0;
                ReadJSValueAsUint64(ctx, GetProperty(ctx, thisVal, "timeout"), timeout);
                xhr->timeout = static_cast<double>(timeout);

                bool isAsync = true;
                ReadJSValueAsBool(ctx, GetProperty(ctx, thisVal, "isAsync"), isAsync);
                BYTEBUFFER tempBinary = {};
                if (argumentCount == 0) {
                    if (!isAsync) xhr->send();
                    else {

                        std::thread t([=]() {
                            xhr->send();
                            });
                        Thread td = std::move(t);
                        td.detach();
                        jsmdPtr->threadList.push_back(td);
                        update(ctx);
                    }
                }
                else if (argumentCount == 1) {
                    JSV js_body = JSV(ctx, &argumentValues[0]).cget(1).cset(1);
                    if (JS_IsNull(js_body.get(0)) || JS_IsUndefined(js_body.get(0))) {
                        if (!isAsync) xhr->send();
                        else {

                            std::thread t([=]() {
                                xhr->send();
                                });
                            Thread td = std::move(t);
                            td.detach();
                            jsmdPtr->threadList.push_back(td);
                            update(ctx);
                        }
                    }
                    else if (JS_IsString(js_body.get(0))) {
                        BYTEBUFFER body = ToValue(ctx, js_body);
                        if (!isAsync) xhr->send(body);
                        else {

                            std::thread t([=, body = std::move(body)]() {
                                xhr->send(body);
                                });
                            Thread td = std::move(t);
                            td.detach();
                            jsmdPtr->threadList.push_back(td);
                            update(ctx);
                        }
                    }
                    else if (GetSymbolName(ctx, js_body) == "FormData") {
                        JSV js_id = GetProperty(ctx, js_body, { {"internal"}, {"id"} });
                        ULL id = 0;
                        if (!js_id.isValid() || !ReadJSValueAsUint64(ctx, js_id, id) || !jsmdPtr->formDataList.count(id)) {
                            JS_ThrowInternalError(ctx, "[network.http.open->send] The FormData instance is invalid");
                            return JS_EXCEPTION;
                        }
                        FORMDATA fl = jsmdPtr->formDataList[id];
                        if (!isAsync) xhr->send(fl);
                        else {

                            std::thread t([=, fl = std::move(fl)]() {
                                xhr->send(fl);
                                });
                            Thread td = std::move(t);
                            td.detach();
                            jsmdPtr->threadList.push_back(td);
                            update(ctx);
                        }
                    }
                    else if (GetSymbolName(ctx, js_body) == "Blob") {

                        JSV js_data = GetProperty(ctx, js_body, { {"internal"}, {"data"} });
                        if (!js_data.isValid() || !ReadJSValueAsArrayBuffer(ctx, js_data, tempBinary)) {
                            JS_ThrowInternalError(ctx, "[network.http.open->send] The Blob instance is invalid");
                            return JS_EXCEPTION;
                        }

                        if (!isAsync) xhr->send(tempBinary);
                        else {
                            std::thread t([=, tempBinary = std::move(tempBinary)]() {
                                xhr->send(tempBinary);
                                });
                            Thread td = std::move(t);
                            td.detach();
                            jsmdPtr->threadList.push_back(td);
                            update(ctx);
                        }
                    }
                    else if (ReadJSValueAsArrayBufferView(ctx, js_body, tempBinary)) {
                        if (!isAsync) xhr->send(tempBinary);
                        else {

                            std::thread t([=, tempBinary = std::move(tempBinary)]() {
                                xhr->send(tempBinary);
                                });
                            Thread td = std::move(t);
                            td.detach();
                            jsmdPtr->threadList.push_back(td);
                            update(ctx);
                        }
                    }
                    else {
                        JS_ThrowTypeError(ctx, ("[network.http.open->send] Unsupported body type '" + GetPrototypeName(ctx, js_body.get(0)) + "'").c_str());
                    }
                }
                else {
                    JS_ThrowTypeError(ctx, "[network.http.open->send] Only 1 argument is supported: (body)");
                    return JS_EXCEPTION;
                }

                return JS_UNDEFINED;
                });
            AppendMethod(ctx, returnValue, "overrideMimeType", [](JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) -> JSValue {
                if (argumentCount != 1) {
                    JS_ThrowTypeError(ctx, "[network.http.open->overrideMimeType] Only 1 argument is supported: (mimeString)");
                    return JS_EXCEPTION;
                }

                JSV js_mimeString = JSV(ctx, &argumentValues[0]).cget(1).cset(1);

                JSMData* jsmdPtr = nullptr;
                if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                    JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                    return JS_EXCEPTION;
                }

                JSV js_id = GetProperty(ctx, thisVal, "id");
                ULL id = 0;
                if (!ReadJSValueAsUint64(ctx, js_id, id) || !jsmdPtr->networkHttpList.count(id)) {
                    JS_ThrowInternalError(ctx, "[network.http.open] This instance is invalid");
                    return JS_EXCEPTION;
                }
                XMLHttpRequest* xhr = jsmdPtr->networkHttpList[id];

                std::string mimeString = "";
                if (!ReadJSValueAsString(ctx, js_mimeString, mimeString)) {
                    JS_ThrowTypeError(ctx, "[network.http.open->overrideMimeType] The first argument must be a string");
                    return JS_EXCEPTION;
                }
                xhr->overrideMimeType(stringToWstring(mimeString));
                return JS_UNDEFINED;
                });
            AppendMethod(ctx, returnValue, "setRequestHeader", [](JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) -> JSValue {
                if (argumentCount != 2) {
                    JS_ThrowTypeError(ctx, "[network.http.open->setRequestHeader] Only 2 arguments are supported: (name, value)");
                    return JS_EXCEPTION;
                }

                JSV js_name = JSV(ctx, &argumentValues[0]).cget(1).cset(1);
                JSV js_value = JSV(ctx, &argumentValues[1]).cget(1).cset(1);
                std::string name = ToString(ctx, js_name);
                std::string value = ToString(ctx, js_value);

                JSMData* jsmdPtr = nullptr;
                if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                    JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                    return JS_EXCEPTION;
                }

                JSV js_id = GetProperty(ctx, thisVal, "id");
                ULL id = 0;
                if (!ReadJSValueAsUint64(ctx, js_id, id) || !jsmdPtr->networkHttpList.count(id)) {
                    JS_ThrowInternalError(ctx, "[network.http.open] This instance is invalid");
                    return JS_EXCEPTION;
                }
                XMLHttpRequest* xhr = jsmdPtr->networkHttpList[id];

                xhr->setRequestHeader(stringToWstring(name), stringToWstring(value));
                return JS_UNDEFINED;
                });
            AppendMethod(ctx, returnValue, "getResponseHeader", [](JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) -> JSValue {
                if (argumentCount != 1) {
                    JS_ThrowTypeError(ctx, "[network.http.open->getResponseHeader] Only 1 argument is supported: (name)");
                    return JS_EXCEPTION;
                }

                JSV js_name = JSV(ctx, &argumentValues[0]).cget(1).cset(1);
                std::string name = ToString(ctx, js_name);

                JSMData* jsmdPtr = nullptr;
                if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                    JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                    return JS_EXCEPTION;
                }

                JSV js_id = GetProperty(ctx, thisVal, "id");
                ULL id = 0;
                if (!ReadJSValueAsUint64(ctx, js_id, id) || !jsmdPtr->networkHttpList.count(id)) {
                    JS_ThrowInternalError(ctx, "[network.http.open] This instance is invalid");
                    return JS_EXCEPTION;
                }
                XMLHttpRequest* xhr = jsmdPtr->networkHttpList[id];

                return NewString(ctx, wstringToString(xhr->getResponseHeader(stringToWstring(name)))).get(1);
                });
            AppendMethod(ctx, returnValue, "getAllResponseHeaders", [](JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) -> JSValue {
                JSMData* jsmdPtr = nullptr;
                if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                    JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                    return JS_EXCEPTION;
                }

                JSV js_id = GetProperty(ctx, thisVal, "id");
                ULL id = 0;
                if (!ReadJSValueAsUint64(ctx, js_id, id) || !jsmdPtr->networkHttpList.count(id)) {
                    JS_ThrowInternalError(ctx, "[network.http.open] This instance is invalid");
                    return JS_EXCEPTION;
                }
                XMLHttpRequest* xhr = jsmdPtr->networkHttpList[id];

                GMT responseHeader = xhr->getResponseHeaders();
                if (responseHeader.empty()) return JS_NULL;
                std::string headerString = "";
                for (const auto& [key, value] : responseHeader) {
                    std::wstring tkey = key;
                    std::wstring tvalue = value;
                    headerString += wstringToString(ToDownLetters(key)) + ": " + wstringToString(ToDownLetters(value)) + "\r\n";
                }
                return NewString(ctx, headerString).get(1);
                });
            AppendMethod(ctx, returnValue, "abort", [](JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues)->JSValue {
                if (argumentCount != 0) {
                    JS_ThrowTypeError(ctx, "[network.http.open->abort] No arguments are supported");
                    return JS_EXCEPTION;
                }

                JSMData* jsmdPtr = nullptr;
                if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                    JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                    return JS_EXCEPTION;
                }

                JSV js_id = GetProperty(ctx, thisVal, "id");
                ULL id = 0;
                if (!ReadJSValueAsUint64(ctx, js_id, id) || !jsmdPtr->networkHttpList.count(id) || jsmdPtr->networkHttpList[id] == nullptr) {
                    JS_ThrowInternalError(ctx, "[network.http.open->abort] This instance has been closed already");
                    return JS_EXCEPTION;
                }

                jsmdPtr->networkHttpList[id]->abort();

                return JS_UNDEFINED;
                });
            AppendMethod(ctx, returnValue, "close", [](JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues)->JSValue {
                if (argumentCount != 0) {
                    JS_ThrowTypeError(ctx, "[network.http.open->close] No arguments are supported");
                    return JS_EXCEPTION;
                }

                JSMData* jsmdPtr = nullptr;
                if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                    JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                    return JS_EXCEPTION;
                }

                JSV js_id = GetProperty(ctx, thisVal, "id");
                ULL id = 0;
                if (!ReadJSValueAsUint64(ctx, js_id, id) || !jsmdPtr->networkHttpList.count(id) || jsmdPtr->networkHttpList[id] == nullptr) {
                    JS_ThrowInternalError(ctx, "[network.http.open->close] This instance has been closed already");
                    return JS_EXCEPTION;
                }

                jsmdPtr->networkHttpList[id]->release();
                delete jsmdPtr->networkHttpList[id];
                jsmdPtr->networkHttpList.erase(id);

                return JS_UNDEFINED;
                });

            return returnValue.get(1);
        }

        static JSValue bytebuffer_readAsJson(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            Promise promise = NewPromise(ctx);
            if (argumentCount != 1) {
                promise.Reject(ctx, NewTypeError(ctx, "[bytebuffer.bytebuffer_readAsJson] Only 1 argument is supported: (data)"));
                return promise.promise.get(1);
            }

            JSV js_data = JSV(ctx, &argumentValues[0]).cget(1).cset(1);

            JSMData* jsmdPtr = nullptr;
            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                return JS_EXCEPTION;
            }

            std::thread t([=]() {
                BYTEBUFFER data = ToValue(ctx, js_data);
                std::wstring text = GetTextFromBYTEBUFFER(&data);
                OBJECT jsonObject;
                try {
                    jsonObject = JSON.parse(text);
                }
                catch (const std::invalid_argument& e) {
                    promise.Reject(ctx, NewSyntaxError(ctx, std::string("[bytebuffer.readAsJson] Failed to parse JSON: ") + e.what()));
                    return;
                }
                promise.Resolve(ctx, NewObject(ctx, jsonObject));
                return;
                });
            Thread td = std::move(t);
            td.detach();
            jsmdPtr->threadList.push_back(td);
            update(ctx);

            return promise.promise.get(1);
        }
        static JSValue bytebuffer_readAsFormData(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            Promise promise = NewPromise(ctx);
            if (argumentCount != 1) {
                promise.Reject(ctx, NewTypeError(ctx, "[bytebuffer.readAsFormData] Only 1 argument is supported: (data)"));
                return promise.promise.get(1);
            }

            JSV js_data = JSV(ctx, &argumentValues[0]).cget(1).cset(1);

            JSMData* jsmdPtr = nullptr;
            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                return JS_EXCEPTION;
            }

            std::thread t([=]() {
                JSV result = CallConstructor(ctx, GetProperty(ctx, NewGlobalObject(ctx), "FormData"), { js_data });
                if (JS_IsException(result.get(0))) promise.Reject(ctx, result);
                else promise.Resolve(ctx, result);
                return;
                });
            Thread td = std::move(t);
            td.detach();
            jsmdPtr->threadList.push_back(td);
            update(ctx);

            return promise.promise.get(1);
        }
        static JSValue bytebuffer_readAsString(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            Promise promise = NewPromise(ctx);
            if (argumentCount != 1) {
                promise.Reject(ctx, NewTypeError(ctx, "[bytebuffer.readAsString] Only 1 argument is supported: (data)"));
                return promise.promise.get(1);
            }

            JSV js_data = JSV(ctx, &argumentValues[0]).cget(1).cset(1);

            JSMData* jsmdPtr = nullptr;
            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                return JS_EXCEPTION;
            }

            std::thread t([=]() {
                BYTEBUFFER data = ToValue(ctx, js_data);
                promise.Resolve(ctx, NewString(ctx, GetTextFromBinary(&data)));
                return;
                });
            Thread td = std::move(t);
            td.detach();
            jsmdPtr->threadList.push_back(td);
            update(ctx);

            return promise.promise.get(1);
        }

        static JSValue bytebuffer_decodeBase91(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            Promise promise = NewPromise(ctx);
            if (argumentCount > 2) {
                promise.Reject(ctx, NewTypeError(ctx, "[bytebuffer.decodeBase91] Only 1 or 2 arguments are supported: (data, isUrlEncoding?)"));
                return promise.promise.get(1);
            }

            JSV js_data = JSV(ctx, &argumentValues[0]).cget(1).cset(1);
            JSV js_isUrlEncoding = (argumentCount == 2) ? JSV(ctx, &argumentValues[1]).cget(1).cset(1) : NewBool(ctx, false);
            bool isUrlEncoding = false;
            if (!JS_IsBool(js_isUrlEncoding.get(0)) || !ReadJSValueAsBool(ctx, js_isUrlEncoding, isUrlEncoding)) {
                promise.Reject(ctx, NewTypeError(ctx, "[bytebuffer.decodeBase91] The second argument must be a boolean"));
                return promise.promise.get(1);
            }

            JSMData* jsmdPtr = nullptr;
            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                return JS_EXCEPTION;
            }

            std::thread t([=]() {
                BYTEBUFFER data = ToValue(ctx, js_data);
                if (!BaseXToBinary(&data, 91, isUrlEncoding)) {
                    promise.Reject(ctx, NewInternalError(ctx, "[bytebuffer.decodeBase91] Failed to decoding data"));
                    return;
                }
                promise.Resolve(ctx, NewUint8Array(ctx, data));
                return;
                });
            Thread td = std::move(t);
            td.detach();
            jsmdPtr->threadList.push_back(td);
            update(ctx);

            return promise.promise.get(1);
        }
        static JSValue bytebuffer_decodeBase85(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            Promise promise = NewPromise(ctx);
            if (argumentCount != 1) {
                promise.Reject(ctx, NewTypeError(ctx, "[bytebuffer.decodeBase85] Only 1 argument is supported: (data)"));
                return promise.promise.get(1);
            }

            JSV js_data = JSV(ctx, &argumentValues[0]).cget(1).cset(1);

            JSMData* jsmdPtr = nullptr;
            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                return JS_EXCEPTION;
            }

            std::thread t([=]() {
                BYTEBUFFER data = ToValue(ctx, js_data);
                if (!BaseXToBinary(&data, 85, false)) {
                    promise.Reject(ctx, NewInternalError(ctx, "[bytebuffer.decodeBase85] Failed to decoding data"));
                    return;
                }
                promise.Resolve(ctx, NewUint8Array(ctx, data));
                return;
                });
            Thread td = std::move(t);
            td.detach();
            jsmdPtr->threadList.push_back(td);
            update(ctx);

            return promise.promise.get(1);
        }
        static JSValue bytebuffer_decodeBase64(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            Promise promise = NewPromise(ctx);
            if (argumentCount > 2) {
                promise.Reject(ctx, NewTypeError(ctx, "[bytebuffer.decodeBase64] Only 1 or 2 arguments are supported: (data, isUrlEncoding?)"));
                return promise.promise.get(1);
            }

            JSV js_data = JSV(ctx, &argumentValues[0]).cget(1).cset(1);
            JSV js_isUrlEncoding = (argumentCount == 2) ? JSV(ctx, &argumentValues[1]).cget(1).cset(1) : NewBool(ctx, false);
            bool isUrlEncoding = false;
            if (!JS_IsBool(js_isUrlEncoding.get(0)) || !ReadJSValueAsBool(ctx, js_isUrlEncoding, isUrlEncoding)) {
                promise.Reject(ctx, NewTypeError(ctx, "[bytebuffer.decodeBase64] The second argument must be a boolean"));
                return promise.promise.get(1);
            }

            JSMData* jsmdPtr = nullptr;
            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                return JS_EXCEPTION;
            }

            std::thread t([=]() {

                BYTEBUFFER data = ToValue(ctx, js_data);
                if (!BaseXToBinary(&data, 64, isUrlEncoding)) {
                    promise.Reject(ctx, NewInternalError(ctx, "[bytebuffer.decodeBase64] Failed to decoding data"));
                    return;
                }
                promise.Resolve(ctx, NewUint8Array(ctx, data));
                return;

                });
            Thread td = std::move(t);
            td.detach();
            jsmdPtr->threadList.push_back(td);
            update(ctx);

            return promise.promise.get(1);
        }
        static JSValue bytebuffer_decodeBase62(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            Promise promise = NewPromise(ctx);
            if (argumentCount != 1) {
                promise.Reject(ctx, NewTypeError(ctx, "[bytebuffer.decodeBase62] Only 1 argument is supported: (data)"));
                return promise.promise.get(1);
            }

            JSV js_data = JSV(ctx, &argumentValues[0]).cget(1).cset(1);

            JSMData* jsmdPtr = nullptr;
            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                return JS_EXCEPTION;
            }

            std::thread t([=]() {
                BYTEBUFFER data = ToValue(ctx, js_data);
                if (!BaseXToBinary(&data, 62, false)) {
                    promise.Reject(ctx, NewInternalError(ctx, "[bytebuffer.decodeBase62] Failed to decoding data"));
                    return;
                }
                promise.Resolve(ctx, NewUint8Array(ctx, data));
                return;
                });
            Thread td = std::move(t);
            td.detach();
            jsmdPtr->threadList.push_back(td);
            update(ctx);

            return promise.promise.get(1);
        }
        static JSValue bytebuffer_decodeBase58(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            Promise promise = NewPromise(ctx);
            if (argumentCount != 1) {
                promise.Reject(ctx, NewTypeError(ctx, "[bytebuffer.decodeBase58] Only 1 argument is supported: (data)"));
                return promise.promise.get(1);
            }

            JSV js_data = JSV(ctx, &argumentValues[0]).cget(1).cset(1);

            JSMData* jsmdPtr = nullptr;
            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                return JS_EXCEPTION;
            }

            std::thread t([=]() {
                BYTEBUFFER data = ToValue(ctx, js_data);
                if (!BaseXToBinary(&data, 58, false)) {
                    promise.Reject(ctx, NewInternalError(ctx, "[bytebuffer.decodeBase58] Failed to decoding data"));
                    return;
                }
                promise.Resolve(ctx, NewUint8Array(ctx, data));
                return;
                });
            Thread td = std::move(t);
            td.detach();
            jsmdPtr->threadList.push_back(td);
            update(ctx);

            return promise.promise.get(1);
        }
        static JSValue bytebuffer_decodeBase32(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            Promise promise = NewPromise(ctx);
            if (argumentCount != 1) {
                promise.Reject(ctx, NewTypeError(ctx, "[bytebuffer.decodeBase32] Only 1 argument is supported: (data)"));
                return promise.promise.get(1);
            }

            JSV js_data = JSV(ctx, &argumentValues[0]).cget(1).cset(1);

            JSMData* jsmdPtr = nullptr;
            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                return JS_EXCEPTION;
            }

            std::thread t([=]() {
                BYTEBUFFER data = ToValue(ctx, js_data);
                if (!BaseXToBinary(&data, 32, false)) {
                    promise.Reject(ctx, NewInternalError(ctx, "[bytebuffer.decodeBase32] Failed to decoding data"));
                    return;
                }
                promise.Resolve(ctx, NewUint8Array(ctx, data));
                return;
                });
            Thread td = std::move(t);
            td.detach();
            jsmdPtr->threadList.push_back(td);
            update(ctx);

            return promise.promise.get(1);
        }
        static JSValue bytebuffer_decodeBase16(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            Promise promise = NewPromise(ctx);
            if (argumentCount != 1) {
                promise.Reject(ctx, NewTypeError(ctx, "[bytebuffer.decodeBase16] Only 1 argument is supported: (data)"));
                return promise.promise.get(1);
            }

            JSV js_data = JSV(ctx, &argumentValues[0]).cget(1).cset(1);

            JSMData* jsmdPtr = nullptr;
            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                return JS_EXCEPTION;
            }

            std::thread t([=]() {

                BYTEBUFFER data = ToValue(ctx, js_data);
                if (!BaseXToBinary(&data, 16, false)) {
                    promise.Reject(ctx, NewInternalError(ctx, "[bytebuffer.decodeBase16] Failed to decoding data"));
                    return;
                }
                promise.Resolve(ctx, NewUint8Array(ctx, data));
                return;

                });
            Thread td = std::move(t);
            td.detach();
            jsmdPtr->threadList.push_back(td);
            update(ctx);

            return promise.promise.get(1);
        }

        static JSValue bytebuffer_encodeBase91(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            Promise promise = NewPromise(ctx);
            if (argumentCount > 2) {
                promise.Reject(ctx, NewTypeError(ctx, "[bytebuffer.encodeBase91] Only 1 or 2 arguments are supported: (data, isUrlEncoding?)"));
                return promise.promise.get(1);
            }

            JSV js_data = JSV(ctx, &argumentValues[0]).cget(1).cset(1);
            JSV js_isUrlEncoding = (argumentCount == 2) ? JSV(ctx, &argumentValues[1]).cget(1).cset(1) : NewBool(ctx, false);
            bool isUrlEncoding = false;
            if (!JS_IsBool(js_isUrlEncoding.get(0)) || !ReadJSValueAsBool(ctx, js_isUrlEncoding, isUrlEncoding)) {
                promise.Reject(ctx, NewTypeError(ctx, "[bytebuffer.encodeBase91] The second argument must be a boolean"));
                return promise.promise.get(1);
            }

            JSMData* jsmdPtr = nullptr;
            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                return JS_EXCEPTION;
            }

            std::thread t([=]() {

                BYTEBUFFER data = ToValue(ctx, js_data);
                if (!BinaryToBaseX(&data, 91, isUrlEncoding)) {
                    promise.Reject(ctx, NewInternalError(ctx, "[bytebuffer.encodeBase91] Failed to encoding data"));
                    return;
                }
                promise.Resolve(ctx, NewString(ctx, GetTextFromBinary(&data)));
                return;

                });
            Thread td = std::move(t);
            td.detach();
            jsmdPtr->threadList.push_back(td);
            update(ctx);

            return promise.promise.get(1);
        }
        static JSValue bytebuffer_encodeBase85(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            Promise promise = NewPromise(ctx);
            if (argumentCount != 1) {
                promise.Reject(ctx, NewTypeError(ctx, "[bytebuffer.encodeBase85] Only 1 argument is supported: (data)"));
                return promise.promise.get(1);
            }

            JSV js_data = JSV(ctx, &argumentValues[0]).cget(1).cset(1);

            JSMData* jsmdPtr = nullptr;
            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                return JS_EXCEPTION;
            }

            std::thread t([=]() {

                BYTEBUFFER data = ToValue(ctx, js_data);
                if (!BinaryToBaseX(&data, 85, false)) {
                    promise.Reject(ctx, NewInternalError(ctx, "[bytebuffer.encodeBase85] Failed to encoding data"));
                    return;
                }
                promise.Resolve(ctx, NewString(ctx, GetTextFromBinary(&data)));
                return;

                });
            Thread td = std::move(t);
            td.detach();
            jsmdPtr->threadList.push_back(td);
            update(ctx);

            return promise.promise.get(1);
        }
        static JSValue bytebuffer_encodeBase64(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            Promise promise = NewPromise(ctx);
            if (argumentCount > 2) {
                promise.Reject(ctx, NewTypeError(ctx, "[bytebuffer.encodeBase64] Only 1 or 2 arguments are supported: (data, isUrlEncoding?)"));
                return promise.promise.get(1);
            }

            JSV js_data = JSV(ctx, &argumentValues[0]).cget(1).cset(1);
            JSV js_isUrlEncoding = (argumentCount == 2) ? JSV(ctx, &argumentValues[1]).cget(1).cset(1) : NewBool(ctx, false);
            bool isUrlEncoding = false;
            if (!JS_IsBool(js_isUrlEncoding.get(0)) || !ReadJSValueAsBool(ctx, js_isUrlEncoding, isUrlEncoding)) {
                promise.Reject(ctx, NewTypeError(ctx, "[bytebuffer.encodeBase64] The second argument must be a boolean"));
                return promise.promise.get(1);
            }

            JSMData* jsmdPtr = nullptr;
            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                return JS_EXCEPTION;
            }

            std::thread t([=]() {

                BYTEBUFFER data = ToValue(ctx, js_data);
                if (!BinaryToBaseX(&data, 64, isUrlEncoding)) {
                    promise.Reject(ctx, NewInternalError(ctx, "[bytebuffer.encodeBase64] Failed to encoding data"));
                    return;
                }
                promise.Resolve(ctx, NewString(ctx, GetTextFromBinary(&data)));
                return;

                });
            Thread td = std::move(t);
            td.detach();
            jsmdPtr->threadList.push_back(td);
            update(ctx);

            return promise.promise.get(1);
        }
        static JSValue bytebuffer_encodeBase62(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            Promise promise = NewPromise(ctx);
            if (argumentCount != 1) {
                promise.Reject(ctx, NewTypeError(ctx, "[bytebuffer.encodeBase62] Only 1 argument is supported: (data)"));
                return promise.promise.get(1);
            }

            JSV js_data = JSV(ctx, &argumentValues[0]).cget(1).cset(1);

            JSMData* jsmdPtr = nullptr;
            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                return JS_EXCEPTION;
            }

            std::thread t([=]() {

                BYTEBUFFER data = ToValue(ctx, js_data);
                if (!BinaryToBaseX(&data, 62, false)) {
                    promise.Reject(ctx, NewInternalError(ctx, "[bytebuffer.encodeBase62] Failed to encoding data"));
                    return;
                }
                promise.Resolve(ctx, NewString(ctx, GetTextFromBinary(&data)));
                return;

                });
            Thread td = std::move(t);
            td.detach();
            jsmdPtr->threadList.push_back(td);
            update(ctx);

            return promise.promise.get(1);
        }
        static JSValue bytebuffer_encodeBase58(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            Promise promise = NewPromise(ctx);
            if (argumentCount != 1) {
                promise.Reject(ctx, NewTypeError(ctx, "[bytebuffer.encodeBase58] Only 1 argument is supported: (data)"));
                return promise.promise.get(1);
            }

            JSV js_data = JSV(ctx, &argumentValues[0]).cget(1).cset(1);

            JSMData* jsmdPtr = nullptr;
            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                return JS_EXCEPTION;
            }

            std::thread t([=]() {

                BYTEBUFFER data = ToValue(ctx, js_data);
                if (!BinaryToBaseX(&data, 58, false)) {
                    promise.Reject(ctx, NewInternalError(ctx, "[bytebuffer.encodeBase58] Failed to encoding data"));
                    return;
                }
                promise.Resolve(ctx, NewString(ctx, GetTextFromBinary(&data)));
                return;

                });
            Thread td = std::move(t);
            td.detach();
            jsmdPtr->threadList.push_back(td);
            update(ctx);

            return promise.promise.get(1);
        }
        static JSValue bytebuffer_encodeBase32(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            Promise promise = NewPromise(ctx);
            if (argumentCount != 1) {
                promise.Reject(ctx, NewTypeError(ctx, "[bytebuffer.encodeBase32] Only 1 argument is supported: (data)"));
                return promise.promise.get(1);
            }

            JSV js_data = JSV(ctx, &argumentValues[0]).cget(1).cset(1);

            JSMData* jsmdPtr = nullptr;
            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                return JS_EXCEPTION;
            }

            std::thread t([=]() {

                BYTEBUFFER data = ToValue(ctx, js_data);
                if (!BinaryToBaseX(&data, 32, false)) {
                    promise.Reject(ctx, NewInternalError(ctx, "[bytebuffer.encodeBase32] Failed to encoding data"));
                    return;
                }
                promise.Resolve(ctx, NewString(ctx, GetTextFromBinary(&data)));
                return;

                });
            Thread td = std::move(t);
            td.detach();
            jsmdPtr->threadList.push_back(td);
            update(ctx);

            return promise.promise.get(1);
        }
        static JSValue bytebuffer_encodeBase16(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            Promise promise = NewPromise(ctx);
            if (argumentCount != 1) {
                promise.Reject(ctx, NewTypeError(ctx, "[bytebuffer.encodeBase16] Only 1 argument is supported: (data)"));
                return promise.promise.get(1);
            }

            JSV js_data = JSV(ctx, &argumentValues[0]).cget(1).cset(1);

            JSMData* jsmdPtr = nullptr;
            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                return JS_EXCEPTION;
            }

            std::thread t([=]() {

                BYTEBUFFER data = ToValue(ctx, js_data);
                if (!BinaryToBaseX(&data, 16, false)) {
                    promise.Reject(ctx, NewInternalError(ctx, "[bytebuffer.encodeBase16] Failed to encoding data"));
                    return;
                }
                promise.Resolve(ctx, NewString(ctx, GetTextFromBinary(&data)));
                return;

                });
            Thread td = std::move(t);
            td.detach();
            jsmdPtr->threadList.push_back(td);
            update(ctx);

            return promise.promise.get(1);
        }

        static JSValue bytebuffer_toBinary(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            Promise promise = NewPromise(ctx);
            if (argumentCount != 1) {
                promise.Reject(ctx, NewTypeError(ctx, "[bytebuffer.toBinary] Only 1 argument is supported: (data)"));
                return promise.promise.get(1);
            }

            JSV js_data = JSV(ctx, &argumentValues[0]).cget(1).cset(1);

            JSMData* jsmdPtr = nullptr;
            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                return JS_EXCEPTION;
            }

            std::thread t([=]() {
                promise.Resolve(ctx, NewUint8Array(ctx, ToValue(ctx, js_data)));
                return;
                });
            Thread td = std::move(t);
            td.detach();
            jsmdPtr->threadList.push_back(td);
            update(ctx);

            return promise.promise.get(1);
        }
        static JSValue bytebuffer_toString(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            Promise promise = NewPromise(ctx);
            if (argumentCount != 1) {
                promise.Reject(ctx, NewTypeError(ctx, "[bytebuffer.toString] Only 1 argument is supported: (data)"));
                return promise.promise.get(1);
            }

            JSV js_data = JSV(ctx, &argumentValues[0]).cget(1).cset(1);

            JSMData* jsmdPtr = nullptr;
            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                return JS_EXCEPTION;
            }

            std::thread t([=]() {
                promise.Resolve(ctx, NewString(ctx, ToString(ctx, js_data)));
                return;
                });
            Thread td = std::move(t);
            td.detach();
            jsmdPtr->threadList.push_back(td);
            update(ctx);

            return promise.promise.get(1);
        }

        static JSValue global_Promise_any(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            Promise promise = NewPromise(ctx);

            if (argumentCount != 1) {
                promise.Reject(ctx, NewTypeError(ctx, "[Promise.any] Only 1 argument is supported: (iterable)"));
                return promise.promise.get(1);
            }

            JSV js_it = JSV(ctx, argumentValues[0]).cget(1).cset(1);

            JSMData* jsmdPtr = nullptr;
            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                promise.Reject(ctx, NewInternalError(ctx, "[Promise.any] Invalid promise instance"));
                return promise.promise.get(1);
            }

            std::thread t([=]() {

                bool isFinished = false;
                vector_lock<JSV> error = {};
                unordered_map_lock<ULL, char> processedId = {};
                JSV result = {};
                JSV tempGlobalPromise = GetProperty(ctx, NewGlobalObject(ctx), "Promise");

                while (!isQuit && !jsmdPtr->isQuit) {

                    ForEach(ctx, js_it, [&](JSV i) {

                        if (isFinished) return;

                        JSV item = i;
                        if (GetSymbolName(ctx, item) != "Promise") {
                            item = CallFunction(ctx, GetProperty(ctx, tempGlobalPromise, "resolve"), tempGlobalPromise, { item });
                        }
                        JSV js_id = GetProperty(ctx, item, { {"internal"}, {"id"} });
                        ULL id = 0;
                        ReadJSValueAsUint64(ctx, js_id, id);
                        if (!jsmdPtr->promiseList.count(id) || processedId.count(id)) {
                            return;
                        }
                        if (jsmdPtr->promiseList[id].state == PromiseState::PENDING) return;
                        if (jsmdPtr->promiseList[id].state == PromiseState::FULFILLED) {
                            result = jsmdPtr->promiseList[id].result.front();
                            isFinished = true;
                        }
                        else {
                            processedId[id];
                            error.push_back(jsmdPtr->promiseList[id].error.front());
                            return;
                        }

                        return;

                        });

                    if (isFinished || error.size() >= ArrayGetLength(ctx, js_it)) break;

                    AdvSleep(1.0);
                }

                if (!isFinished) {
                    JSV returnValue = NewObject(ctx);
                    SetSymbolName(ctx, returnValue, "AggregateError");
                    SetAttribute(ctx, returnValue, "name", "AggregateError");
                    SetAttribute(ctx, returnValue, "message", "");
                    SetAttribute(ctx, returnValue, "errors", NewArray(ctx, error));
                    promise.Reject(ctx, returnValue);
                    return;
                }
                else {
                    promise.Resolve(ctx, result);
                    return;
                }

                return;
                });

            Thread td = std::move(t);
            td.detach();
            jsmdPtr->threadList.push_back(td);
            update(ctx);

            return promise.promise.get(1);
        }
        static JSValue global_Promise_race(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            Promise promise = NewPromise(ctx);

            if (argumentCount != 1) {
                promise.Reject(ctx, NewTypeError(ctx, "[Promise.race] Only 1 argument is supported: (iterable)"));
                return promise.promise.get(1);
            }

            JSV js_it = JSV(ctx, argumentValues[0]).cget(1).cset(1);

            JSMData* jsmdPtr = nullptr;
            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                promise.Reject(ctx, NewInternalError(ctx, "[Promise.race] Invalid promise instance"));
                return promise.promise.get(1);
            }

            std::thread t([=]() {

                struct ResultData {
                    bool isSuccess = false;
                    JSV data = JSV();
                };
                ResultData result = {};
                bool isRaced = false;
                JSV tempGlobalPromise = GetProperty(ctx, NewGlobalObject(ctx), "Promise");

                while (!isQuit && !jsmdPtr->isQuit) {

                    ForEach(ctx, js_it, [&](JSV i) {

                        if (isRaced) return;

                        JSV item = i;
                        if (GetSymbolName(ctx, item) != "Promise") {
                            item = CallFunction(ctx, GetProperty(ctx, tempGlobalPromise, "resolve"), tempGlobalPromise, { item });
                        }
                        JSV js_id = GetProperty(ctx, item, { {"internal"}, {"id"} });
                        ULL id = 0;
                        ReadJSValueAsUint64(ctx, js_id, id);
                        if (!jsmdPtr->promiseList.count(id)) {
                            return;
                        }
                        if (jsmdPtr->promiseList[id].state == PromiseState::PENDING) return;
                        if (jsmdPtr->promiseList[id].state == PromiseState::FULFILLED) {
                            ResultData rd = {};
                            rd.data = ((jsmdPtr->promiseList[id].result.size() == 0) ? JSV(JS_UNDEFINED) : jsmdPtr->promiseList[id].result.front());
                            rd.isSuccess = true;
                            result = rd;
                            isRaced = true;
                        }
                        else {
                            ResultData rd = {};
                            rd.data = ((jsmdPtr->promiseList[id].error.size() == 0) ? JSV(JS_UNDEFINED) : jsmdPtr->promiseList[id].error.front());
                            rd.isSuccess = false;
                            result = rd;
                            isRaced = true;
                        }

                        return;

                        });

                    if (isRaced) break;

                    AdvSleep(1.0);
                }

                if (result.isSuccess) promise.Resolve(ctx, result.data);
                else promise.Reject(ctx, result.data);
                return;
                });

            Thread td = std::move(t);
            td.detach();
            jsmdPtr->threadList.push_back(td);
            update(ctx);

            return promise.promise.get(1);
        }
        static JSValue global_Promise_allSettled(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            Promise promise = NewPromise(ctx);

            if (argumentCount != 1) {
                promise.Reject(ctx, NewTypeError(ctx, "[Promise.allSettled] Only 1 argument is supported: (iterable)"));
                return promise.promise.get(1);
            }

            JSV js_it = JSV(ctx, argumentValues[0]).cget(1).cset(1);

            JSMData* jsmdPtr = nullptr;
            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                promise.Reject(ctx, NewInternalError(ctx, "[Promise.allSettled] Invalid promise instance"));
                return promise.promise.get(1);
            }

            std::thread t([=]() {

                struct ResultData {
                    bool isSuccess = false;
                    JSV data = JSV();
                };
                vector_lock<ResultData> result = {};
                JSV tempGlobalPromise = GetProperty(ctx, NewGlobalObject(ctx), "Promise");

                ForEach(ctx, js_it, [&](JSV i) {

                    JSV item = i;
                    if (GetSymbolName(ctx, item) != "Promise") {
                        item = CallFunction(ctx, GetProperty(ctx, tempGlobalPromise, "resolve"), tempGlobalPromise, { item });
                    }
                    JSV js_id = GetProperty(ctx, item, { {"internal"}, {"id"} });
                    ULL id = 0;
                    ReadJSValueAsUint64(ctx, js_id, id);
                    if (!jsmdPtr->promiseList.count(id)) {
                        return;
                    }

                    while (!isQuit && !jsmdPtr->isQuit) {
                        if (jsmdPtr->promiseList[id].state != PromiseState::PENDING) {
                            break;
                        }
                        AdvSleep(1.0);
                    }

                    if (jsmdPtr->promiseList[id].state == PromiseState::FULFILLED) {
                        ResultData rd = {};
                        rd.data = ((jsmdPtr->promiseList[id].result.size() == 0) ? JSV(JS_UNDEFINED) : jsmdPtr->promiseList[id].result.front());
                        rd.isSuccess = true;
                        result.push_back(rd);
                    }
                    else {
                        ResultData rd = {};
                        rd.data = ((jsmdPtr->promiseList[id].error.size() == 0) ? JSV(JS_UNDEFINED) : jsmdPtr->promiseList[id].error.front());
                        rd.isSuccess = false;
                        result.push_back(rd);
                    }

                    return;
                    });

                std::vector<JSV> returnValue = {};
                for (ResultData& rd : result) {
                    JSV obj = NewObject(ctx);
                    SetAttribute(ctx, obj, "status", (rd.isSuccess) ? "fulfilled" : "rejected");
                    SetAttribute(ctx, obj, (rd.isSuccess) ? "value" : "reason", rd.data);
                    returnValue.push_back(obj);
                }
                result.clear();

                promise.Resolve(ctx, NewArray(ctx, returnValue));
                return;
                });

            Thread td = std::move(t);
            td.detach();
            jsmdPtr->threadList.push_back(td);
            update(ctx);

            return promise.promise.get(1);
        }
        static JSValue global_Promise_all(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            Promise promise = NewPromise(ctx);

            if (argumentCount != 1) {
                promise.Reject(ctx, NewTypeError(ctx, "[Promise.all] Only 1 argument is supported: (iterable)"));
                return promise.promise.get(1);
            }

            JSV js_it = JSV(ctx, argumentValues[0]).cget(1).cset(1);

            JSMData* jsmdPtr = nullptr;
            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                promise.Reject(ctx, NewInternalError(ctx, "[Promise.all] Invalid promise instance"));
                return promise.promise.get(1);
            }

            std::thread t([=]() {

                bool isSuccess = true;
                JSV tempGlobalPromise = GetProperty(ctx, NewGlobalObject(ctx), "Promise");
                JSV error = JSV();
                vector_lock<JSV> result = {};

                ForEach(ctx, js_it, [&](JSV i) {

                    JSV item = i;

                    if (!isSuccess) return;

                    if (GetSymbolName(ctx, item) != "Promise") {
                        item = CallFunction(ctx, GetProperty(ctx, tempGlobalPromise, "resolve"), tempGlobalPromise, { item });
                    }

                    JSV js_id = GetProperty(ctx, item, { {"internal"}, {"id"} });
                    ULL id = 0;
                    ReadJSValueAsUint64(ctx, js_id, id);
                    if (!jsmdPtr->promiseList.count(id)) {
                        return;
                    }

                    while (!isQuit && !jsmdPtr->isQuit) {
                        if (jsmdPtr->promiseList[id].state != PromiseState::PENDING) {
                            break;
                        }
                        AdvSleep(1.0);
                    }

                    if (jsmdPtr->promiseList[id].state == PromiseState::FULFILLED) {
                        result.push_back(((jsmdPtr->promiseList[id].result.size() == 0) ? JSV(JS_UNDEFINED) : jsmdPtr->promiseList[id].result.front()));
                    }
                    else {
                        isSuccess = false;
                        error = (jsmdPtr->promiseList[id].error.size() == 0) ? JSV(JS_UNDEFINED) : jsmdPtr->promiseList[id].error.front();
                    }

                    return;
                    });

                if (isSuccess) {
                    promise.Resolve(ctx, NewArray(ctx, result));
                }
                else {
                    promise.Reject(ctx, error);
                }

                return;
                });
            Thread td = std::move(t);
            td.detach();
            jsmdPtr->threadList.push_back(td);
            update(ctx);

            return promise.promise.get(1);
        }
        static JSValue global_Promise_resolve(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            JSV js_resolve = (argumentCount >= 1) ? JSV(ctx, argumentValues[0]).cget(1).cset(1) : JSV(JS_UNDEFINED);
            Promise promise = NewPromise(ctx);
            promise.Resolve(ctx, js_resolve);
            return promise.promise.get(1);
        }
        static JSValue global_Promise_reject(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            JSV js_reject = (argumentCount >= 1) ? JSV(ctx, argumentValues[0]).cget(1).cset(1) : JSV(JS_UNDEFINED);
            Promise promise = NewPromise(ctx);
            promise.Reject(ctx, js_reject);
            return promise.promise.get(1);
        }
        static JSValue global_Promise(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            if (argumentCount < 1) {
                JS_ThrowTypeError(ctx, "[Promise] Only 1 argument is supported: (resolver)");
                return JS_EXCEPTION;
            }
            JSV js_resolver = JSV(ctx, argumentValues[0]).cget(1).cset(1);
            JSV js_this = JSV(ctx, thisVal).cget(1).cset(1);
            if (!JS_IsFunction(ctx, js_resolver.get(0))) {
                JS_ThrowTypeError(ctx, ("[Promise] Promise resolver " + GetPrototypeName(ctx, js_resolver.get(0)) + " is not a function").c_str());
                return JS_EXCEPTION;
            }
            Promise promise = NewPromise(ctx);
            JSV internal = NewObject(ctx, NewGlobalObject(ctx), "internal");
            SetAttribute(ctx, internal, "_isPrivate", NewBool(ctx, true));
            SetAttribute(ctx, internal, "thisVal", promise.promise);
            SetAttribute(ctx, internal, "resolve", promise.resolve);
            SetAttribute(ctx, internal, "reject", promise.reject);
            JSV resolve = NewFunction(ctx, "resolve", [](JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues)->JSValue {
                JSV internal = GetProperty(ctx, NewGlobalObject(ctx), "internal");
                if (!internal.isValid()) return JS_UNDEFINED;
                JSV js_this = GetProperty(ctx, internal, "thisVal");
                JSV resolve = GetProperty(ctx, internal, "resolve");
                CallFunction(ctx, resolve, js_this, argumentCount, argumentValues);
                RemoveAttribute(ctx, NewGlobalObject(ctx), "internal");
                return JS_UNDEFINED;
                });
            JSV reject = NewFunction(ctx, "reject", [](JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues)->JSValue {
                JSV internal = GetProperty(ctx, NewGlobalObject(ctx), "internal");
                if (!internal.isValid()) return JS_UNDEFINED;
                JSV js_this = GetProperty(ctx, internal, "thisVal");
                JSV reject = GetProperty(ctx, internal, "reject");
                CallFunction(ctx, reject, js_this, argumentCount, argumentValues);
                RemoveAttribute(ctx, NewGlobalObject(ctx), "internal");
                return JS_UNDEFINED;
                });
            CallFunction(ctx, js_resolver, (IsArrowFunction(ctx, js_resolver) ? js_this : JS_UNDEFINED), { resolve, reject });
            return promise.promise.get(1);
        }

        static JSValue global_URL_revokeObjectURL(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            if (argumentCount != 1) {
                JS_ThrowTypeError(ctx, "[URL.revokeObjectURL] Only 1 argument is supported: (url)");
                return JS_EXCEPTION;
            }

            JSV js_url = JSV(ctx, &argumentValues[0]).cget(1).cset(1);
            std::string url = "";
            if (!ReadJSValueAsString(ctx, js_url, url)) {
                JS_ThrowTypeError(ctx, "[URL.revokeObjectURL] The first argument must be a string");
                return JS_EXCEPTION;
            }

            std::wstring wurl = stringToWstring(url);
            if (URLDataList.count(wurl)) URLDataList.erase(wurl);

            return JS_UNDEFINED;
        }
        static JSValue global_URL_createObjectURL(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            if (argumentCount != 1) {
                JS_ThrowTypeError(ctx, "[URL.createObjectURL] Only 1 argument is supported: (object)");
                return JS_EXCEPTION;
            }

            JSV js_object = JSV(ctx, &argumentValues[0]).cget(1).cset(1);

            JSV returnUrl = NewString(ctx, "");
            if (GetSymbolName(ctx, js_object) == "Blob") {
                JSV js_arrayBuffer = CallFunction(ctx, GetProperty(ctx, NewGlobalObject(ctx), "await"), JS_UNDEFINED, { {CallFunction(ctx, GetProperty(ctx, js_object, "arrayBuffer"), js_object, {})} });
                JSV js_type = GetProperty(ctx, js_object, "type");
                std::string type = "application/octet-stream";
                ReadJSValueAsString(ctx, js_type, type);
                BYTEBUFFER data = {};
                ReadJSValueAsArrayBufferView(ctx, js_object, data);
                BLOB blob = {};
                blob.data = data;
                blob.mimeType = type;
                std::string url = wstringToString(URL.createObjectURL(&blob));
                returnUrl = NewString(ctx, url);
            }
            else {
                JS_ThrowTypeError(ctx, "[URL.createObjectURL] The first argument must be a Blob");
                return JS_EXCEPTION;
            }

            return returnUrl.get(1);
        }
        static JSValue global_URL(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            if (argumentCount < 1 || argumentCount >2) {
                JS_ThrowTypeError(ctx, "[URL] Only 1 or 2 argument are supported: (url, base?)");
                return JS_EXCEPTION;
            }

            JSV js_url = JSV(ctx, &argumentValues[0]).cget(1).cset(1);
            JSV js_base = (argumentCount >= 2) ? JSV(ctx, &argumentValues[1]).cget(1).cset(1) : NewString(ctx, "");

            std::string url = "";
            if (!ReadJSValueAsString(ctx, js_url, url)) {
                JS_ThrowTypeError(ctx, "[URL] The first argument must be a string");
                return JS_EXCEPTION;
            }
            std::string base = "";
            if (!ReadJSValueAsString(ctx, js_base, base)) {
                JS_ThrowTypeError(ctx, "[URL] The second argument must be a string");
                return JS_EXCEPTION;
            }

            URL_T urlp;
            try {
                urlp = URLInstanceClass(stringToWstring(url));
            }
            catch (...) {
                JS_ThrowSyntaxError(ctx, "[URL] Failed to parse the URL");
                return JS_EXCEPTION;
            }

            JSV returnObject = NewObject(ctx);
            SetSymbolName(ctx, returnObject, "URL");
            SetAttribute(ctx, returnObject, "href", NewString(ctx, wstringToString(urlp.href)));
            SetAttribute(ctx, returnObject, "protocol", NewString(ctx, wstringToString(urlp.protocol)));
            SetAttribute(ctx, returnObject, "username", NewString(ctx, wstringToString(urlp.username)));
            SetAttribute(ctx, returnObject, "password", NewString(ctx, wstringToString(urlp.password)));
            SetAttribute(ctx, returnObject, "host", NewString(ctx, wstringToString(urlp.host)));
            SetAttribute(ctx, returnObject, "hostname", NewString(ctx, wstringToString(urlp.hostname)));
            SetAttribute(ctx, returnObject, "port", NewString(ctx, std::to_string(urlp.port)));
            SetAttribute(ctx, returnObject, "pathname", NewString(ctx, wstringToString(urlp.pathname)));
            SetAttribute(ctx, returnObject, "search", NewString(ctx, wstringToString(urlp.search)));
            SetAttribute(ctx, returnObject, "hash", NewString(ctx, wstringToString(urlp.hash)));

            return returnObject.get(1);
        }

        static JSValue global_Blob(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            if (argumentCount > 2 || argumentCount < 1) {
                JS_ThrowTypeError(ctx, "[Blob] Only 1 or 2 arguments are supported: (blobParts, options?)");
                return JS_EXCEPTION;
            }

            JSV js_blobParts = JSV(ctx, &argumentValues[0]).cget(1).cset(1);
            JSV js_options = (argumentCount >= 2) ? JSV(ctx, &argumentValues[1]).cget(1).cset(1) : NewObject(ctx);

            BYTEBUFFER blobData = ToAdvValue(ctx, js_blobParts);
            OBJECT options = {};
            if (argumentCount == 2) {
                if (!ReadJSValueAsObject(ctx, js_options, options)) {
                    JS_ThrowTypeError(ctx, "[Blob] Failed to read options");
                    return JS_EXCEPTION;
                }
            }

            std::string type = options.count(L"type") ? options[L"type"].get<std::string>() : "";
            if (!IsMimeTypeValid(type)) type = "";

            JSV blob = NewObject(ctx);
            SetSymbolName(ctx, blob, "Blob");
            JSV internal = NewObject(ctx, blob, "internal");
            SetAttribute(ctx, internal, "_isPrivate", NewBool(ctx, true), 0);
            SetAttribute(ctx, internal, "data", NewArrayBuffer(ctx, blobData), 0);
            SetAttribute(ctx, blob, "type", NewString(ctx, type), 0);
            SetAttribute(ctx, blob, "size", NewUint64(ctx, blobData.size()), 0);
            AppendMethod(ctx, blob, "slice", [](JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues)->JSValue {

                JSV size = GetProperty(ctx, thisVal, "size");
                JSV type = GetProperty(ctx, thisVal, "type");
                JSV js_data = GetProperty(ctx, thisVal, { {"internal"}, {"data"} });
                BYTEBUFFER data = {};
                ReadJSValueAsArrayBuffer(ctx, js_data, data);

                JSV js_start = (argumentCount >= 1) ? JSV(ctx, &argumentValues[0]).cget(1).cset(1) : NewUint64(ctx, 0);
                JSV js_end = (argumentCount >= 2) ? JSV(ctx, &argumentValues[1]).cget(1).cset(1) : size;
                JSV js_type = (argumentCount >= 3) ? JSV(ctx, &argumentValues[2]).cget(1).cset(1) : type;

                uint64_t start = 0;
                ReadJSValueAsUint64(ctx, js_start, start);
                uint64_t end = 0;
                ReadJSValueAsUint64(ctx, js_end, end);

                if (start > 0 && start < data.size()) {
                    data.erase(data.begin(), data.begin() + static_cast<const int>(start));
                }
                if (end - start < data.size()) {
                    data.erase(data.begin() + static_cast<const int>(end - start), data.end());
                }

                JSV newOptions = NewObject(ctx);
                SetAttribute(ctx, newOptions, "type", type);
                return CallConstructor(ctx, GetProperty(ctx, NewGlobalObject(ctx), "Blob"), { NewArray(ctx, {NewArrayBuffer(ctx, data)}), {newOptions} }).get(1);
                }, 0);
            AppendMethod(ctx, blob, "text", [](JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues)->JSValue {
                Promise promise = NewPromise(ctx);

                JSMData* jsmdPtr = nullptr;
                if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                    JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                    return JS_EXCEPTION;
                }

                std::thread t([=]() {

                    JSV js_data = GetProperty(ctx, thisVal, { {"internal"}, {"data"} });
                    BYTEBUFFER data = {};
                    ReadJSValueAsArrayBuffer(ctx, js_data, data);

                    promise.Resolve(ctx, NewString(ctx, GetTextFromBinarySafely(&data)));

                    return;
                    });

                Thread td = std::move(t);
                jsmdPtr->threadList.push_back(td);
                update(ctx);

                return promise.promise.get(1);
                }, 0);
            AppendMethod(ctx, blob, "arrayBuffer", [](JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues)->JSValue {
                Promise promise = NewPromise(ctx);

                JSMData* jsmdPtr = nullptr;
                if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                    JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                    return JS_EXCEPTION;
                }

                std::thread t([=]() {

                    JSV js_data = GetProperty(ctx, thisVal, { {"internal"}, {"data"} });
                    BYTEBUFFER data = {};
                    ReadJSValueAsArrayBuffer(ctx, js_data, data);

                    promise.Resolve(ctx, NewArrayBuffer(ctx, data));

                    return;
                    });

                Thread td = std::move(t);
                jsmdPtr->threadList.push_back(td);
                update(ctx);

                return promise.promise.get(1);
                }, 0);

            return blob.get(1);
        }
        static JSValue global_clearTimeout(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            if (argumentCount != 1) {
                JS_ThrowTypeError(ctx, "[clearTimeout] Only 1 argument is supported: (id)");
                return JS_EXCEPTION;
            }

            JSV js_id = JSV(ctx, &argumentValues[0]).cget(1).cset(1);
            ULL id = 0;
            if (!ReadJSValueAsUint64(ctx, js_id, id)) {
                return JS_UNDEFINED;
            }

            JSMData* jsmdPtr = nullptr;
            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                return JS_UNDEFINED;
            }

            if (!jsmdPtr->timeoutList.count(id)) {
                return JS_UNDEFINED;
            }

            jsmdPtr->timeoutList[id].shared = (void*)0x00000001;
            return JS_UNDEFINED;
        }
        static JSValue global_setTimeout(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            if (argumentCount < 1 || argumentCount >2) {
                JS_ThrowTypeError(ctx, "[setTimeout] Only 1 or 2 arguments are supported: (callback, milliseconds?)");
                return JS_EXCEPTION;
            }

            JSV js_callback = JSV(ctx, &argumentValues[0]).cget(1).cset(1);
            if (!JS_IsFunction(ctx, js_callback.get(0))) {
                JS_ThrowTypeError(ctx, "[setTimeout] The first argument must be a function");
                return JS_EXCEPTION;
            }
            uint64_t milliseconds = 0;
            if (argumentCount == 2) {
                JSV js_milliseconds = JSV(ctx, &argumentValues[1]).cget(1).cset(1);
                if (!ReadJSValueAsUint64(ctx, js_milliseconds, milliseconds)) {
                    JS_ThrowTypeError(ctx, "[setTimeout] The second argument must be a non-negative integer");
                    return JS_EXCEPTION;
                }
            }

            JSMData* jsmdPtr = nullptr;
            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                return JS_EXCEPTION;
            }

            ULL id = GetNewTimeoutId(ctx);

            std::thread t([=]() {

                JSMData* jsmdPtr = nullptr;
                if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                    return;
                }

                ULONGLONG timeNow = GetTickCount64();
                ULONGLONG targetTime = timeNow + milliseconds;
                while (GetTickCount64() < targetTime && !isQuit && jsmdPtr->timeoutList[id].shared == nullptr && !jsmdPtr->isQuit) {
                    ULONGLONG remaining = targetTime - GetTickCount64();
                    AdvSleep(static_cast<double>(remaining > 1 ? 1 : remaining));
                }

                if (!isQuit && jsmdPtr->timeoutList[id].shared == nullptr && !jsmdPtr->isQuit) {
                    CallFunction(ctx, js_callback, NewGlobalObject(ctx), {}, true);
                }

                jsmdPtr->timeoutList.erase(id);

                });
            Thread td = std::move(t);
            td.detach();
            jsmdPtr->threadList.push_back(td);
            jsmdPtr->timeoutList[id].thread = td;
            jsmdPtr->timeoutList[id].shared = nullptr;
            update(ctx);

            return NewUint64(ctx, id).get(1);
        }
        static JSValue global_wait(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {

            if (argumentCount != 1) {
                JS_ThrowTypeError(ctx, "[wait] Only 1 argument is supported: (milliseconds)");
                return JS_EXCEPTION;
            }

            JSV js_milliseconds = JSV(ctx, &argumentValues[0]).cget(1).cset(1);
            uint64_t milliseconds = 0;
            if (!ReadJSValueAsUint64(ctx, js_milliseconds, milliseconds)) {
                JS_ThrowTypeError(ctx, "[wait] The first argument must be a non-negative integer");
                return JS_EXCEPTION;
            }

            ULONGLONG timeNow = GetTickCount64();
            ULONGLONG targetTime = timeNow + milliseconds;
            while (GetTickCount64() < targetTime && !isQuit) {
                ULONGLONG remaining = targetTime - GetTickCount64();
                AdvSleep(static_cast<double>(remaining > 1 ? 1 : remaining));
            }

            return JS_UNDEFINED;
        }
        static JSValue global_FormData(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            if (argumentCount > 1) {
                JS_ThrowTypeError(ctx, "[FormData] Only 1 argument is supported: (formData?)");
                return JS_EXCEPTION;
            }

            JSMData* jsmdPtr = nullptr;
            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                return JS_EXCEPTION;
            }

            ULL id = GetNewFormDataId(ctx);

            if (argumentCount == 1) {
                JSV js_binary = JSV(ctx, &argumentValues[0]);
                BYTEBUFFER binary = {};
                if (!ReadJSValueAsArrayBufferView(ctx, js_binary, binary)) {
                    JS_ThrowTypeError(ctx, "[FormData] Failed to read the form data binary");
                    return JS_EXCEPTION;
                }
                if (!ReadBinaryAsFormData(ctx, &binary, jsmdPtr->formDataList[id])) {
                    JS_ThrowTypeError(ctx, "[FormData] Failed to parse the form data binary");
                    return JS_EXCEPTION;
                }
            }
            else {
                jsmdPtr->formDataList[id] = {};
            }

            JSV returnValue = NewObject(ctx);
            SetSymbolName(ctx, returnValue, "FormData");
            JSV internal = NewObject(ctx);
            SetAttribute(ctx, returnValue, "internal", internal);
            SetAttribute(ctx, internal, "_isPrivate", NewBool(ctx, true));
            SetAttribute(ctx, internal, "id", NewUint64(ctx, static_cast<uint64_t>(id)));
            SetAttribute(ctx, internal, "thisValue", JSV(ctx, &thisVal).cget(1).cset(1));

            AppendMethod(ctx, returnValue, "append", [](JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues)-> JSValue {
                if (argumentCount > 3 || argumentCount < 2) {
                    JS_ThrowTypeError(ctx, "[FormData->append] Only 2 or 3 arguments are supported: (name, value, filename?)");
                    return JS_EXCEPTION;
                }

                JSMData* jsmdPtr = nullptr;
                if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                    JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                    return JS_EXCEPTION;
                }

                JSV js_id = GetProperty(ctx, thisVal, { {"internal"},{"id"} });
                uint64_t uid = 0;
                if (!ReadJSValueAsUint64(ctx, js_id, uid) || !jsmdPtr->formDataList.count(static_cast<uint64_t>(uid))) {
                    JS_ThrowInternalError(ctx, "[FormData->append] This instance is invalid");
                    return JS_EXCEPTION;

                }
                ULL id = static_cast<ULL>(uid);

                JSV vName = JSV(ctx, &argumentValues[0]).cget(1).cset(1);
                JSV vValue = JSV(ctx, &argumentValues[1]).cget(1).cset(1);
                JSV vFilename = (argumentCount == 3) ? JSV(ctx, &argumentValues[2]).cget(1).cset(1) : JSV();
                std::string name = ToString(ctx, vName);
                std::string fileName = ToString(ctx, vFilename);
                BYTEBUFFER value = ToValue(ctx, vValue);

                FORMDATAITEM fd = {};
                fd.key = vName;
                fd.value = vValue;
                fd.binary = value;
                fd.fileName = fileName;
                fd.name = name;
                fd.contentType = wstringToString(GetMIMETypeFromBYTEBUFFER(&value));

                jsmdPtr->formDataList[id][name] = fd;

                return JS_UNDEFINED;
                });
            AppendMethod(ctx, returnValue, "set", [](JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues)-> JSValue {
                if (argumentCount > 3 || argumentCount < 2) {
                    JS_ThrowTypeError(ctx, "[FormData->set] Only 2 or 3 arguments are supported: (name, value, filename?)");
                    return JS_EXCEPTION;
                }

                JSMData* jsmdPtr = nullptr;
                if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                    JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                    return JS_EXCEPTION;
                }

                JSV js_id = GetProperty(ctx, thisVal, { {"internal"},{"id"} });
                uint64_t uid = 0;
                if (!ReadJSValueAsUint64(ctx, js_id, uid) || !jsmdPtr->formDataList.count(static_cast<uint64_t>(uid))) {
                    JS_ThrowInternalError(ctx, "[FormData->set] This instance is invalid");
                    return JS_EXCEPTION;

                }

                ULL id = static_cast<ULL>(uid);

                JSV vName = JSV(ctx, &argumentValues[0]).cget(1).cset(1);
                JSV vValue = JSV(ctx, &argumentValues[1]).cget(1).cset(1);
                JSV vFilename = (argumentCount == 3) ? JSV(ctx, &argumentValues[2]).cget(1).cset(1) : JSV();
                std::string name = ToString(ctx, vName);
                std::string fileName = ToString(ctx, vFilename);
                BYTEBUFFER value = ToValue(ctx, vValue);


                jsmdPtr->formDataList[id].erase(name);

                FORMDATAITEM fd = {};
                fd.key = vName;
                fd.value = vValue;
                fd.binary = value;
                fd.fileName = fileName;
                fd.name = name;
                fd.contentType = wstringToString(GetMIMETypeFromBYTEBUFFER(&value));

                jsmdPtr->formDataList[id][name] = fd;

                return JS_UNDEFINED;
                });
            AppendMethod(ctx, returnValue, "delete", [](JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues)-> JSValue {
                if (argumentCount != 1) {
                    JS_ThrowTypeError(ctx, "[FormData->delete] Only 1 argument is supported: (name)");
                    return JS_EXCEPTION;
                }

                JSMData* jsmdPtr = nullptr;
                if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                    JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                    return JS_EXCEPTION;
                }

                JSV js_id = GetProperty(ctx, thisVal, { {"internal"},{"id"} });
                uint64_t uid = 0;
                if (!ReadJSValueAsUint64(ctx, js_id, uid) || !jsmdPtr->formDataList.count(static_cast<uint64_t>(uid))) {
                    JS_ThrowInternalError(ctx, "[FormData->delete] This instance is invalid");
                    return JS_EXCEPTION;

                }

                ULL id = static_cast<ULL>(uid);

                JSV vName = JSV(ctx, &argumentValues[0]);
                std::string name = ToString(ctx, vName);

                jsmdPtr->formDataList[id].erase(name);

                return JS_UNDEFINED;
                });

            AppendMethod(ctx, returnValue, "get", [](JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues)-> JSValue {
                if (argumentCount != 1) {
                    JS_ThrowTypeError(ctx, "[FormData->get] Only 1 argument is supported: (name)");
                    return JS_EXCEPTION;
                }

                JSMData* jsmdPtr = nullptr;
                if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                    JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                    return JS_EXCEPTION;
                }

                JSV js_id = GetProperty(ctx, thisVal, { {"internal"},{"id"} });
                uint64_t uid = 0;
                if (!ReadJSValueAsUint64(ctx, js_id, uid) || !jsmdPtr->formDataList.count(static_cast<uint64_t>(uid))) {
                    JS_ThrowInternalError(ctx, "[FormData->get] This instance is invalid");
                    return JS_EXCEPTION;

                }

                ULL id = static_cast<ULL>(uid);

                JSV vName = JSV(ctx, &argumentValues[0]);
                std::string name = ToString(ctx, vName);

                auto result = jsmdPtr->formDataList[id].find(name);
                if (result != jsmdPtr->formDataList[id].end()) {
                    return result->second.value.get(1);
                }
                else {
                    return JS_NULL;
                }

                return JS_UNDEFINED;
                });
            AppendMethod(ctx, returnValue, "getAll", [](JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues)-> JSValue {
                if (argumentCount != 1) {
                    JS_ThrowTypeError(ctx, "[FormData->getAll] Only 1 argument is supported: (name)");
                    return JS_EXCEPTION;
                }

                JSMData* jsmdPtr = nullptr;
                if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                    JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                    return JS_EXCEPTION;
                }

                JSV js_id = GetProperty(ctx, thisVal, { {"internal"},{"id"} });
                uint64_t uid = 0;
                if (!ReadJSValueAsUint64(ctx, js_id, uid) || !jsmdPtr->formDataList.count(static_cast<uint64_t>(uid))) {
                    JS_ThrowInternalError(ctx, "[FormData->getAll] This instance is invalid");
                    return JS_EXCEPTION;

                }

                ULL id = static_cast<ULL>(uid);

                JSV vName = JSV(ctx, &argumentValues[0]);
                std::string name = ToString(ctx, vName);

                if (!jsmdPtr->formDataList[id].empty()) {
                    std::vector<JSV> returnArray = {};
                    for (auto& [id, fl] : jsmdPtr->formDataList[id]) {
                        if (fl.name != name) continue;
                        returnArray.push_back(fl.value);
                    }
                    return NewArray(ctx, returnArray).get(1);
                }
                else {
                    return NewArray(ctx, {}).get(1);
                }

                return JS_UNDEFINED;
                });
            AppendMethod(ctx, returnValue, "has", [](JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues)-> JSValue {
                if (argumentCount != 1) {
                    JS_ThrowTypeError(ctx, "[FormData->has] Only 1 argument is supported: (name)");
                    return JS_EXCEPTION;
                }

                JSMData* jsmdPtr = nullptr;
                if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                    JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                    return JS_EXCEPTION;
                }

                JSV js_id = GetProperty(ctx, thisVal, { {"internal"},{"id"} });
                uint64_t uid = 0;
                if (!ReadJSValueAsUint64(ctx, js_id, uid) || !jsmdPtr->formDataList.count(static_cast<uint64_t>(uid))) {
                    JS_ThrowInternalError(ctx, "[FormData->has] This instance is invalid");
                    return JS_EXCEPTION;

                }

                ULL id = static_cast<ULL>(uid);

                JSV vName = JSV(ctx, &argumentValues[0]);
                std::string name = ToString(ctx, vName);

                auto result = jsmdPtr->formDataList[id].find(name);
                if (result != jsmdPtr->formDataList[id].end()) {
                    return NewBool(ctx, true).get(1);
                }
                else {
                    return NewBool(ctx, false).get(1);
                }

                return JS_UNDEFINED;
                });

            AppendMethod(ctx, returnValue, "entries", [](JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues)-> JSValue {
                if (argumentCount != 0) {
                    JS_ThrowTypeError(ctx, "[FormData->entries] No arguments are supported");
                    return JS_EXCEPTION;
                }

                JSMData* jsmdPtr = nullptr;
                if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                    JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                    return JS_EXCEPTION;
                }

                JSV js_id = GetProperty(ctx, thisVal, { {"internal"},{"id"} });
                uint64_t uid = 0;
                if (!ReadJSValueAsUint64(ctx, js_id, uid) || !jsmdPtr->formDataList.count(static_cast<uint64_t>(uid))) {
                    JS_ThrowInternalError(ctx, "[FormData->entries] This instance is invalid");
                    return JS_EXCEPTION;

                }
                ULL id = static_cast<ULL>(uid);

                JSV iterator = NewIterator(ctx, thisVal, "FormData Interator", [](JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues)-> JSValue {

                    JSMData* jsmdPtr = nullptr;
                    if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                        JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                        return JS_EXCEPTION;
                    }

                    JSV internal = GetProperty(ctx, thisVal, "internal");

                    JSV js_id = GetProperty(ctx, internal, "id");
                    uint64_t uid = 0;
                    if (!ReadJSValueAsUint64(ctx, js_id, uid) || !jsmdPtr->formDataList.count(static_cast<uint64_t>(uid))) {
                        JS_ThrowInternalError(ctx, "[FormData->entries] This instance is invalid");
                        return JS_EXCEPTION;

                    }
                    ULL id = static_cast<ULL>(uid);

                    JSV array = GetProperty(ctx, internal, "data");
                    uint64_t index = 0;
                    FORMDATA& dataList = jsmdPtr->formDataList[id];

                    if (!ReadJSValueAsUint64(ctx, GetProperty(ctx, internal, "index"), index)) {
                        JS_ThrowInternalError(ctx, "[FormData->entries] This instance is invalid");
                        return JS_EXCEPTION;
                    }

                    JSV returnObject = NewObject(ctx);
                    SetAttribute(ctx, returnObject, "done", NewBool(ctx, index >= dataList.size()));
                    if (index < dataList.size()) {
                        auto& fd = dataList.at(static_cast<size_t>(index));
                        SetAttribute(ctx, returnObject, "value", NewArray(ctx, { {fd.second.key}, {fd.second.value} }));
                        SetAttribute(ctx, internal, "index", NewUint64(ctx, ++index));
                    }
                    else SetAttribute(ctx, returnObject, "value", JS_UNDEFINED);

                    return returnObject.get(1);
                    }, 0);

                JSV internal = NewObject(ctx);
                SetAttribute(ctx, internal, "_isPrivate", NewBool(ctx, true));
                SetAttribute(ctx, internal, "id", js_id);
                SetAttribute(ctx, internal, "index", NewUint64(ctx, 0));

                SetAttribute(ctx, iterator, "internal", internal);

                return iterator.get(1);
                });
            AppendMethod(ctx, returnValue, "keys", [](JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues)-> JSValue {
                if (argumentCount != 0) {
                    JS_ThrowTypeError(ctx, "[FormData->keys] No arguments are supported");
                    return JS_EXCEPTION;
                }

                JSMData* jsmdPtr = nullptr;
                if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                    JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                    return JS_EXCEPTION;
                }

                JSV js_id = GetProperty(ctx, thisVal, { {"internal"},{"id"} });
                uint64_t uid = 0;
                if (!ReadJSValueAsUint64(ctx, js_id, uid) || !jsmdPtr->formDataList.count(static_cast<uint64_t>(uid))) {
                    JS_ThrowInternalError(ctx, "[FormData->keys] This instance is invalid");
                    return JS_EXCEPTION;

                }
                ULL id = static_cast<ULL>(uid);

                JSV iterator = NewIterator(ctx, thisVal, "FormData Interator", [](JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues)-> JSValue {

                    JSMData* jsmdPtr = nullptr;
                    if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                        JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                        return JS_EXCEPTION;
                    }

                    JSV internal = GetProperty(ctx, thisVal, "internal");

                    JSV js_id = GetProperty(ctx, internal, "id");
                    uint64_t uid = 0;
                    if (!ReadJSValueAsUint64(ctx, js_id, uid) || !jsmdPtr->formDataList.count(static_cast<uint64_t>(uid))) {
                        JS_ThrowInternalError(ctx, "[FormData->keys] This instance is invalid");
                        return JS_EXCEPTION;

                    }
                    ULL id = static_cast<ULL>(uid);

                    JSV array = GetProperty(ctx, internal, "data");
                    uint64_t index = 0;
                    FORMDATA& dataList = jsmdPtr->formDataList[id];

                    if (!ReadJSValueAsUint64(ctx, GetProperty(ctx, internal, "index"), index)) {
                        JS_ThrowInternalError(ctx, "[FormData->keys] This instance is invalid");
                        return JS_EXCEPTION;
                    }

                    JSV returnObject = NewObject(ctx);
                    SetAttribute(ctx, returnObject, "done", NewBool(ctx, index >= dataList.size()));
                    if (index < dataList.size()) {
                        auto& fd = dataList.at(static_cast<size_t>(index));
                        SetAttribute(ctx, returnObject, "value", fd.second.key);
                        SetAttribute(ctx, internal, "index", NewUint64(ctx, ++index));
                    }
                    else SetAttribute(ctx, returnObject, "value", JS_UNDEFINED);

                    return returnObject.get(1);
                    }, 0);

                JSV internal = NewObject(ctx);
                SetAttribute(ctx, internal, "_isPrivate", NewBool(ctx, true));
                SetAttribute(ctx, internal, "id", js_id);
                SetAttribute(ctx, internal, "index", NewUint64(ctx, 0));

                SetAttribute(ctx, iterator, "internal", internal);

                return iterator.get(1);
                });
            AppendMethod(ctx, returnValue, "values", [](JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues)-> JSValue {
                if (argumentCount != 0) {
                    JS_ThrowTypeError(ctx, "[FormData->values] No arguments are supported");
                    return JS_EXCEPTION;
                }

                JSMData* jsmdPtr = nullptr;
                if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                    JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                    return JS_EXCEPTION;
                }

                JSV js_id = GetProperty(ctx, thisVal, { {"internal"},{"id"} });
                uint64_t uid = 0;
                if (!ReadJSValueAsUint64(ctx, js_id, uid) || !jsmdPtr->formDataList.count(static_cast<uint64_t>(uid))) {
                    JS_ThrowInternalError(ctx, "[FormData->values] This instance is invalid");
                    return JS_EXCEPTION;

                }
                ULL id = static_cast<ULL>(uid);

                JSV iterator = NewIterator(ctx, thisVal, "FormData Interator", [](JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues)-> JSValue {

                    JSMData* jsmdPtr = nullptr;
                    if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                        JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                        return JS_EXCEPTION;
                    }

                    JSV internal = GetProperty(ctx, thisVal, "internal");

                    JSV js_id = GetProperty(ctx, internal, "id");
                    uint64_t uid = 0;
                    if (!ReadJSValueAsUint64(ctx, js_id, uid) || !jsmdPtr->formDataList.count(static_cast<uint64_t>(uid))) {
                        JS_ThrowInternalError(ctx, "[FormData->values] This instance is invalid");
                        return JS_EXCEPTION;

                    }
                    ULL id = static_cast<ULL>(uid);

                    JSV array = GetProperty(ctx, internal, "data");
                    uint64_t index = 0;
                    FORMDATA& dataList = jsmdPtr->formDataList[id];

                    if (!ReadJSValueAsUint64(ctx, GetProperty(ctx, internal, "index"), index)) {
                        JS_ThrowInternalError(ctx, "[FormData->values] This instance is invalid");
                        return JS_EXCEPTION;
                    }

                    JSV returnObject = NewObject(ctx);
                    SetAttribute(ctx, returnObject, "done", NewBool(ctx, index >= dataList.size()));
                    if (index < dataList.size()) {
                        auto& fd = dataList.at(static_cast<size_t>(index));
                        SetAttribute(ctx, returnObject, "value", fd.second.value);
                        SetAttribute(ctx, internal, "index", NewUint64(ctx, ++index));
                    }
                    else SetAttribute(ctx, returnObject, "value", JS_UNDEFINED);

                    return returnObject.get(1);
                    }, 0);

                JSV internal = NewObject(ctx);
                SetAttribute(ctx, internal, "_isPrivate", NewBool(ctx, true));
                SetAttribute(ctx, internal, "id", js_id);
                SetAttribute(ctx, internal, "index", NewUint64(ctx, 0));

                SetAttribute(ctx, iterator, "internal", internal);

                return iterator.get(1);
                });
            AppendMethod(ctx, returnValue, "forEach", [](JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues)-> JSValue {
                if (argumentCount < 1 || argumentCount > 2) {
                    JS_ThrowTypeError(ctx, "[FormData->forEach] 1 or 2 arguments are supported: (callback, thisArg?)");
                    return JS_EXCEPTION;
                }
                JSV callback = JSV(ctx, &argumentValues[0]).cget(1).cset(1);
                JSV thisArg = (argumentCount == 2) ? JSV(ctx, &argumentValues[1]).cget(1).cset(1) : NewGlobalObject(ctx);
                if (!JS_IsFunction(ctx, callback.get(0))) {
                    JS_ThrowTypeError(ctx, "[FormData->forEach] The first must be a function");
                    return JS_EXCEPTION;
                }

                JSMData* jsmdPtr = nullptr;
                if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                    JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                    return JS_EXCEPTION;
                }

                JSV js_id = GetProperty(ctx, thisVal, { {"internal"},{"id"} });
                uint64_t uid = 0;
                if (!ReadJSValueAsUint64(ctx, js_id, uid) || !jsmdPtr->formDataList.count(static_cast<uint64_t>(uid))) {
                    JS_ThrowInternalError(ctx, "[FormData->forEach] This instance is invalid");
                    return JS_EXCEPTION;

                }
                ULL id = static_cast<ULL>(uid);

                for (auto& [iId, fd] : jsmdPtr->formDataList[id]) {
                    CallFunction(ctx, callback, thisArg, {
                        fd.value,
                        fd.key,
                        JSV(ctx, &thisVal).cget(1).cset(1)
                        });
                }

                return JS_UNDEFINED;
                });

            return returnValue.get(1);
        }
        static JSValue global_await(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            if (argumentCount != 1) {
                JS_ThrowTypeError(ctx, "[await] Only 1 argument is supported: (promise)");
                return JS_EXCEPTION;
            }

            JSV js_promise = JSV(ctx, argumentValues[0]);
            if (GetSymbolName(ctx, js_promise) != "Promise") {
                return js_promise.get(1);
            }

            JSV js_id = GetProperty(ctx, js_promise, { {"internal"}, {"id"} });
            ULL id = 0;
            ReadJSValueAsUint64(ctx, js_id, id);

            JSMData* jsmdPtr = nullptr;
            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr || !jsmdPtr->promiseList.count(id)) {
                JS_ThrowInternalError(ctx, "[await] Invalid promise instance");
                return JS_EXCEPTION;
            }

            RunTask(ctx);

            while (!isQuit && !jsmdPtr->isQuit) {

                if (jsmdPtr->promiseList[id].state != PromiseState::PENDING) {
                    break;
                }
                AdvSleep(1.0);

            }

            if (jsmdPtr->promiseList[id].state == PromiseState::FULFILLED) {
                return (jsmdPtr->promiseList[id].result.size() == 0) ? JS_UNDEFINED : jsmdPtr->promiseList[id].result[0].get(1);
            }
            else {
                JSV error = (jsmdPtr->promiseList[id].error.size() == 0) ? JS_UNDEFINED : jsmdPtr->promiseList[id].error[0];
                JS_ThrowPlainError(ctx, ("(in promise) " + ToString(ctx, JS_IsError(error.get(0)) ? GetProperty(ctx, error, "message") : error)).c_str());
                return JS_EXCEPTION;
            }

            return JS_UNDEFINED;
        }
        static JSValue global_using(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            if (argumentCount > 2) {
                JS_ThrowTypeError(ctx, "[using] Only 1 or 2 argument are supported: (object, where?)");
                return JS_EXCEPTION;
            }

            JSV global = NewGlobalObject(ctx);

            JSValue jsObject = argumentValues[0];
            JSV object = JSV(ctx, jsObject);

            if (!JS_IsObject(jsObject)) {
                JS_ThrowTypeError(ctx, "[using] The first argument must be a object");
                return JS_EXCEPTION;
            }
            if (IsSameValue(ctx, global, object)) {
                JS_ThrowTypeError(ctx, "[using] The first object cannot be equal to the global object");
                return JS_EXCEPTION;
            }

            JSValue jsWhere = JS_UNDEFINED;
            std::string sWhere = "";
            bool isString = false;
            if (argumentCount >= 2) {
                jsWhere = argumentValues[1];
                if (!JS_IsObject(jsWhere) && !JS_IsString(jsWhere)) {
                    JS_ThrowTypeError(ctx, "[using] The second argument must be a object or string");
                    return JS_EXCEPTION;
                }
                if (JS_IsString(jsWhere)) {
                    JSV tempVWhere = jsWhere;
                    if (!ReadJSValueAsString(ctx, tempVWhere, sWhere)) {
                        JS_ThrowTypeError(ctx, "[using] The second argument must be a valid string");
                        return JS_EXCEPTION;
                    }
                    isString = true;
                    jsWhere = JS_UNDEFINED;
                }
                if (JS_IsObject(jsWhere) && IsSameValue(ctx, JSV(ctx, jsWhere), JSV(ctx, jsObject))) {
                    JS_ThrowTypeError(ctx, "[using] The first object cannot be equal to the second object");
                    return JS_EXCEPTION;
                }
            }

            JSV where = JSV(ctx, jsWhere);
            if (JS_IsUndefined(where.get(0))) {
                if (!isString) {
                    where = global;
                }
                else {
                    where = NewObject(ctx, global, sWhere);
                }
            }

            bool ret = ForEach(ctx, object, [&](JSV& vKey, JSV& vValue) {
                std::string key = "";
                if (!JS_IsString(vKey.get(0)) || !ReadJSValueAsString(ctx, vKey, key)) {
                    return;
                }
                SetAttribute(ctx, where, key, vValue);
                });

            return JS_NewBool(ctx, ret);
        }
        static JSValue global_btoa(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            if (argumentCount != 1) {
                JS_ThrowTypeError(ctx, "[btoa] Only 1 argument is supported: (data)");
                return JS_EXCEPTION;
            }
            if (!JS_IsString(argumentValues[0])) {
                JS_ThrowTypeError(ctx, "[btoa] The first argument must be a string");
                return JS_EXCEPTION;
            }
            BYTEBUFFER data = ToValue(ctx, JSV(ctx, &argumentValues[0]));
            if (!BinaryToBaseX(&data, 64, false)) {
                JS_ThrowInternalError(ctx, "[btoa] Failed to convert binary to base64");
                return JS_EXCEPTION;
            }
            return NewString(ctx, wstringToString(GetTextFromBYTEBUFFER(&data))).get(1);
        }
        static JSValue global_atob(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            if (argumentCount != 1) {
                JS_ThrowTypeError(ctx, "[atob] Only 1 argument is supported: (data)");
                return JS_EXCEPTION;
            }
            if (!JS_IsString(argumentValues[0])) {
                JS_ThrowTypeError(ctx, "[atob] The first argument must be a string");
                return JS_EXCEPTION;
            }
            BYTEBUFFER data = ToValue(ctx, JSV(ctx, &argumentValues[0]));
            if (!BaseXToBinary(&data, 64, false)) {
                JS_ThrowInternalError(ctx, "[atob] Failed to convert base64 to binary");
                return JS_EXCEPTION;
            }
            return NewString(ctx, wstringToString(GetTextFromBYTEBUFFER(&data))).get(1);
        }
        static JSValue global_eval(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            if (argumentCount != 1) {
                JS_ThrowTypeError(ctx, "[eval] Only 1 argument is supported: (string)");
                return JS_EXCEPTION;
            }

            JSMData* jsmdPtr = nullptr;
            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr || jsmdPtr->js == nullptr) {
                JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                return JS_EXCEPTION;
            }

            JSV vString = JSV(&argumentValues[0]);
            std::string string = "";
            if (JS_IsString(vString.get(0)) && ReadJSValueAsString(ctx, vString, string)) {
                JSINFO ji = EvalInstance(jsmdPtr->js, stringToWstring(string), L"<eval>");
                if (ji.isValid && !ji.isSuccess) {
                    std::string errorMsg = std::string("[eval]") + ": " + wstringToString(ji.errorFront) + ":" + wstringToString(ji.message);
                    JS_ThrowPlainError(ctx, errorMsg.c_str());
                    return JS_EXCEPTION;
                }
                else if (ji.isValid && ji.isSuccess) {
                    return ji.result.get(1);
                }
                return JS_UNDEFINED;
            }
            return vString.get(1);
        }

        static JSValue script_execute(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            if (argumentCount > 1) {
                JS_ThrowTypeError(ctx, "[script.execute] Only 1 argument is supported: (path?)");
                return JS_EXCEPTION;
            }

            JSMData* jsmdPtr = nullptr;
            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                return JS_EXCEPTION;
            }

            JavaScript* js = NewInstance();
            if (js == nullptr || !InitInstance(js, jsmdPtr->rt, nullptr)) {
                if (js != nullptr) DeleteInstance(js);
                JS_ThrowInternalError(ctx, "[script.execute] Failed to create a new context");
                return JS_EXCEPTION;
            }

            if (argumentCount == 1) {
                JSValue jsPath = argumentValues[0];
                JSV vPath = JSV(&jsPath);
                std::string path = "";
                if (!JS_IsString(jsPath) || !ReadJSValueAsString(ctx, vPath, path)) {
                    DeleteInstance(js);
                    JS_ThrowTypeError(ctx, "[script.execute] The first argument must be a string");
                    return JS_EXCEPTION;
                }

                FileController* fc = NewInstance<FileController>(stringToWstring(path), stringToWstring(GetCurrentWorkDirectory(ctx)));
                if (fc == nullptr || !fc->exists()) {
                    if (fc != nullptr) delete fc;
                    DeleteInstance(js);
                    JS_ThrowTypeError(ctx, "[script.execute] Failed to read file");
                    return JS_EXCEPTION;
                }
                BYTEBUFFER data = {};
                bool result = fc->read(0, fc->size(), &data);
                delete fc;

                if (result && !data.empty()) {
                    std::wstring code = GetTextFromBYTEBUFFER(&data);
                    JSINFO ji = EvalInstance(js, code, GetFileNameFromPath(stringToWstring(path)));
                    if (ji.isValid && !ji.isSuccess) {
                        DeleteInstance(js);
                        std::string errorMsg = std::string("[script.execute]") + ": " + wstringToString(ji.errorFront) + ":" + wstringToString(ji.message);
                        JS_ThrowPlainError(ctx, errorMsg.c_str());
                        return JS_EXCEPTION;
                    }
                }

            }

            ULL id = GetNewExecuteJsId(ctx);
            jsmdPtr->executeJsList[id] = js;

            JSContext* newCtx = GetContextThis(js);
            JSMData* newJsmdPtr = nullptr;
            if (!GetData(newCtx, &newJsmdPtr)) {
                JSMData newJsmd = {};

                newJsmd.rt = jsmdPtr->rt;
                newJsmd.ctx = newCtx;
                newJsmd.parentCtx = jsmdPtr->ctx;

                newJsmd.js = js;
                newJsmd.jsm = GetInstanceMethodThis(newJsmd.js);

                SetData(newJsmd.ctx, &newJsmd);
                if (!GetData(newCtx, &newJsmdPtr)) {
                    jsmdPtr->executeJsList.erase(id);
                    DeleteInstance(js);
                    JS_ThrowInternalError(ctx, "[script.execute] Failed to init a new context");
                    return JS_EXCEPTION;
                }
            }
            newJsmdPtr->parentCtx = ctx;

            JSV global = NewGlobalObject(newCtx);
            AppendMethod(newCtx, global, "this_close", [](JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) -> JSValue {

                if (argumentCount != 0) {
                    JS_ThrowTypeError(ctx, "[script.execute->this_close] No arguments are supported");
                    return JS_EXCEPTION;
                }

                JSMData* jsmdPtr = nullptr;
                if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr || jsmdPtr->parentCtx == nullptr) {
                    JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                    return JS_EXCEPTION;
                }

                JSMData* parentJsmdPtr = nullptr;
                if (!GetData(jsmdPtr->parentCtx, &parentJsmdPtr) || parentJsmdPtr == nullptr || parentJsmdPtr->ctx == nullptr) {
                    JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                    return JS_EXCEPTION;
                }

                for (auto it = parentJsmdPtr->executeJsList.begin(); it != parentJsmdPtr->executeJsList.end(); ++it) {
                    if (GetContextThis(it->second) == ctx) {
                        it = parentJsmdPtr->executeJsList.erase(it);
                        break;
                    }
                    else {
                        ++it;
                    }
                }

                ClearObject(ctx, thisVal);
                DeleteInstance(jsmdPtr->js);

                return JS_UNDEFINED;
                }, 0);

            return global.get(1);
        }
        static JSValue script_include(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            if (argumentCount <= 0) {
                JS_ThrowTypeError(ctx, "[script.include] Only 1 or more arguments are supported: (...path)");
                return JS_EXCEPTION;
            }

            std::vector<std::string> pathList = {};
            for (ULL i = 0; i < argumentCount; i++) {
                JSValue jsPath = argumentValues[i];
                if (!JS_IsString(jsPath)) {
                    JS_ThrowTypeError(ctx, ("[script.include] Argument " + std::to_string(i + 1) + " must be a string").c_str());
                    return JS_EXCEPTION;
                }
                JSV vPath = JSV(&jsPath);
                std::string path = "";
                bool result = ReadJSValueAsString(ctx, vPath, path);
                if (result) pathList.push_back(path);
            }

            JSMData* jsmdPtr = nullptr;
            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                return JS_EXCEPTION;
            }

            for (std::string path : pathList) {
                FileController* fc = nullptr;
                try {

                    fc = new FileController(stringToWstring(path), stringToWstring(GetCurrentWorkDirectory(ctx)));
                    if (fc == nullptr) continue;
                    if (!fc->exists()) {
                        delete fc;
                        std::string errorMsg = std::string("[script.include]") + ": The file '" + path + "' does not exist";
                        JS_ThrowPlainError(ctx, errorMsg.c_str());
                        return JS_EXCEPTION;
                    }
                    BYTEBUFFER data = {};
                    bool result = fc->read(0, fc->size(), &data);
                    delete fc;
                    if (!result || data.size() == 0) {
                        continue;
                    }
                    std::wstring code = GetTextFromBYTEBUFFER(&data);
                    JSINFO ji = EvalInstance(jsmdPtr->js, code, GetFileNameFromPath(stringToWstring(path)));
                    if (ji.isValid && !ji.isSuccess) {
                        std::string errorMsg = std::string("[script.include]") + ": " + wstringToString(ji.errorFront) + ":" + wstringToString(ji.message);
                        JS_ThrowPlainError(ctx, errorMsg.c_str());
                        return JS_EXCEPTION;
                    }
                }
                catch (...) {
                    if (fc != nullptr) delete fc;
                }
            }
            pathList.clear();

            return JS_UNDEFINED;
        }

        static JSValue system_updateConfig(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            if (argumentCount != 1) {
                JS_ThrowTypeError(ctx, "[system.updateConfig] Only 1 argument is supported: (configObject)");
                return JS_EXCEPTION;
            }
            bool result = false;

            JSV vConfigObject = argumentValues[0];
            OBJECT newConfigObject = {};
            if (!ReadJSValueAsObject(ctx, vConfigObject, newConfigObject)) {
                JS_ThrowTypeError(ctx, "[system.updateConfig] The first argument must be a object");
                return JS_EXCEPTION;
            }

            configObject = newConfigObject;
            updateConfig();

            return JS_UNDEFINED;
        }
        static JSValue system_saveConfig(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            if (argumentCount != 0) {
                JS_ThrowTypeError(ctx, "[system.saveConfig] No arguments are supported");
                return JS_EXCEPTION;
            }
            bool result = false;
            std::wstring json = JSON.stringify(configObject, std::monostate(), 4);
            BYTEBUFFER writeData = ToBinary(json);
            FileController* fc = NewInstance<FileController>(L"./config.json", apppath(0));
            if (fc != nullptr) {
                fc->clear();
                ULL size = fc->write(&writeData);
                delete fc;
                if (size == writeData.size()) result = true;
            }
            return JS_NewBool(ctx, result);
        }
        static JSValue system_execute(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            Promise promise = NewPromise(ctx);
            if (argumentCount != 1) {
                promise.Reject(ctx, NewTypeError(ctx, "[system.execute] Only 1 argument is supported: (cmd)"));
                return promise.promise.get(1);
            }
            JSV vCmd = JSV(&argumentValues[0]);
            std::string cmd = "";
            if (!JS_IsString(vCmd.get(0)) || !ReadJSValueAsString(ctx, vCmd, cmd)) {
                JS_ThrowTypeError(ctx, "[system.execute] The first argument must be a string");
                return JS_EXCEPTION;
            }
            JSMData* jsmdPtr = nullptr;
            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                return JS_EXCEPTION;
            }
            std::thread t([=]() {
                std::wstring result = L"";
                DWORD returnCode = EXIT_SUCCESS;
                bool ret = ExecuteCmdCommand(stringToWstring(cmd), result, &returnCode);
                JSV returnValue = NewObject(ctx);
                JSV vIsSuccess = NewBool(ctx, ret);
                SetAttribute(ctx, returnValue, "isSuccess", vIsSuccess);
                JSV vExitCode = NewUint64(ctx, static_cast<uint64_t>(returnCode));
                SetAttribute(ctx, returnValue, "exitCode", vExitCode);
                JSV vOutput = NewString(ctx, wstringToString(result));
                SetAttribute(ctx, returnValue, "output", vOutput);
                promise.Resolve(ctx, returnValue);
                });
            Thread td = std::move(t);
            td.detach();
            jsmdPtr->threadList.push_back(td);
            update(ctx);

            return promise.promise.get(1);
        }
        static JSValue system_cmd(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            if (argumentCount != 0) {
                JS_ThrowTypeError(ctx, "[system.cmd] No arguments are supported");
                return JS_EXCEPTION;
            }
            return JS_NewString(ctx, wstringToString(GetCommandLineW()).c_str());
        }
        static JSValue system_cwd(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            if (argumentCount != 0) {
                JS_ThrowTypeError(ctx, "[system.cwd] No arguments are supported");
                return JS_EXCEPTION;
            }
            return JS_NewString(ctx, FormatPath(GetCurrentWorkDirectory(ctx)).c_str());
        }
        static JSValue system_ecwd(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            if (argumentCount != 0) {
                JS_ThrowTypeError(ctx, "[system.ecwd] No arguments are supported");
                return JS_EXCEPTION;
            }
            return JS_NewString(ctx, wstringToString(FormatPath(apppath(0))).c_str());
        }
        static JSValue system_exit(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            if (argumentCount != 0) {
                JS_ThrowTypeError(ctx, "[system.exit] No arguments are supported");
                return JS_EXCEPTION;
            }

            JSMData* jsmdPtr = nullptr;
            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                return JS_EXCEPTION;
            }

            if (jsmdPtr->js == nullptr || IsAliveInstance(jsmdPtr->js) == false) {
                JS_ThrowInternalError(ctx, "[system.exit] This context has exited already");
                return JS_EXCEPTION;
            }

            ChildSystemExitInstance(jsmdPtr->js);

            JS_Throw(ctx, JS_NewInternalError(ctx, "[native code] Quit the context"));
            return JS_EXCEPTION;
        }

        static JSValue crypto_getRandomValues(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            if (argumentCount != 1) {
                JS_ThrowTypeError(ctx, "[crypto.getRandomValues] Only 1 argument is supported: (ArrayBufferView)");
                return JS_EXCEPTION;
            }

            JSValue jsArray = argumentValues[0];
            JSV uArray = JSV(&jsArray);

            BYTEBUFFER temp = {};
            std::string arrayType = "";
            if (ReadJSValueAsUint8Array(ctx, uArray, temp)) {
                arrayType = "Uint8Array";
            }
            else if (ReadJSValueAsUint16Array(ctx, uArray, temp)) {
                arrayType = "Uint16Array";
            }
            else if (ReadJSValueAsUint32Array(ctx, uArray, temp)) {
                arrayType = "Uint32Array";
            }
            else if (ReadJSValueAsInt8Array(ctx, uArray, temp)) {
                arrayType = "Int8Array";
            }
            else if (ReadJSValueAsInt16Array(ctx, uArray, temp)) {
                arrayType = "Int16Array";
            }
            else if (ReadJSValueAsInt32Array(ctx, uArray, temp)) {
                arrayType = "Int32Array";
            }
            else {
                JS_ThrowTypeError(ctx, "[crypto.getRandomValues] The first argument must be a ArrayBufferView");
                return JS_EXCEPTION;
            }

            if (temp.size() > UINT16_MAX + 1) {
                JS_ThrowDOMException(ctx, "QuotaExceededError", "[crypto.getRandomValues] The requested length exceeds the quota");
                return JS_EXCEPTION;
            }
            BYTEBUFFER data = crypto_getRandomValues_core(temp.size());
            if (data.size() != temp.size()) {
                JS_ThrowDOMException(ctx, "OperationError", "[crypto.getRandomValues] The operation failed for an unspecified transient reason");
                return JS_EXCEPTION;
            }

            JSV jsData = {};
            if (arrayType == "Uint8Array") {
                jsData = NewUint8Array(ctx, data);
                if (!ModifyJSValue(ctx, uArray, jsData)) goto ErrorProcess;
            }
            else if (arrayType == "Uint16Array") {
                jsData = NewUint16Array(ctx, data);
                if (!ModifyJSValue(ctx, uArray, jsData)) goto ErrorProcess;
            }
            else if (arrayType == "Uint32Array") {
                jsData = NewUint32Array(ctx, data);
                if (!ModifyJSValue(ctx, uArray, jsData)) goto ErrorProcess;
            }
            else if (arrayType == "Int8Array") {
                jsData = NewInt8Array(ctx, data);
                if (!ModifyJSValue(ctx, uArray, jsData)) goto ErrorProcess;
            }
            else if (arrayType == "Int16Array") {
                jsData = NewInt16Array(ctx, data);
                if (!ModifyJSValue(ctx, uArray, jsData)) goto ErrorProcess;
            }
            else if (arrayType == "Int32Array") {
                jsData = NewInt32Array(ctx, data);
                if (!ModifyJSValue(ctx, uArray, jsData)) goto ErrorProcess;
            }

            if (false) {
            ErrorProcess:;
                JS_ThrowDOMException(ctx, "OperationError", "[crypto.getRandomValues] Failed to apply result");
                return JS_EXCEPTION;
            }

            return jsData.get(1);
        }
        static JSValue crypto_subtle_deriveBits(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            Promise promise = NewPromise(ctx);

            if (argumentCount < 2 || argumentCount > 3) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.deriveBits] Only 2 or 3 arguments are supported: (algorithm, baseKey, length?)"));
                return promise.promise.get(1);
            }

            JSValue jsAlgorithm = argumentValues[0];
            JSV uAlgorithm = JSV(ctx, &jsAlgorithm).cget(1).cset(1);
            if (!JS_IsObject(jsAlgorithm)) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.deriveBits] The first argument (algorithm) must be an object"));
                return promise.promise.get(1);
            }

            JSValue jsBaseKey = argumentValues[1];
            JSV uBaseKey = JSV(ctx, &jsBaseKey).cget(1).cset(1);
            if (!JS_IsObject(jsBaseKey) || GetSymbolName(ctx, jsBaseKey) != "CryptoKey") {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.deriveBits] The second argument (baseKey) must be a CryptoKey object"));
                return promise.promise.get(1);
            }

            uint64_t length_val = 0;
            bool hasLength = (argumentCount == 3);
            if (hasLength) {
                uint64_t temp_len = 0;
                if (!ReadJSValueAsUint64(ctx, JSV(ctx, &argumentValues[2]), temp_len) || temp_len == 0 || temp_len % 8 != 0) {
                    promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.deriveBits] The third argument (length) must be a positive integer multiple of 8"));
                    return promise.promise.get(1);
                }
                length_val = temp_len;
            }

            JSV jsKeyUsages = GetProperty(ctx, uBaseKey, "usages");
            std::vector<JSV> jkeyUsages = {};
            if (!JS_IsArray(jsKeyUsages.get()) || !ReadJSValueAsArray(ctx, jsKeyUsages, jkeyUsages)) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.deriveBits] The baseKey 'usages' property must be an array"));
                return promise.promise.get(1);
            }

            bool hasValidUsage = false;
            for (JSV& jsv : jkeyUsages) {
                std::string usage = "";
                if (!JS_IsString(jsv.get()) || !ReadJSValueAsString(ctx, jsv, usage)) {
                    promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.deriveBits] The baseKey 'usages' array items must all be strings"));
                    return promise.promise.get(1);
                }
                if (usage == "deriveBits" || usage == "deriveKey") {
                    hasValidUsage = true;
                }
            }

            if (!hasValidUsage) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.deriveBits] baseKey does not have valid usage (deriveBits/deriveKey)"));
                return promise.promise.get(1);
            }

            JSV js_a_name;
            std::string a_name = "";
            if (!ReadObjectProperty(ctx, uAlgorithm, "name", js_a_name) || !ReadJSValueAsString(ctx, js_a_name, a_name)) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.deriveBits] The algorithm must have a 'name' string property"));
                return promise.promise.get(1);
            }

            if (!allowedKeyUsagesList.count(a_name)) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.deriveBits] The algorithm name '" + a_name + "' is not supported"));
                return promise.promise.get(1);
            }

            std::vector<std::string> invalidAlgorithmList = {};
            ForEach(ctx, uAlgorithm, [&](JSV& key, JSV& value) {
                std::string cKey = "";
                if (!ReadJSValueAsString(ctx, key, cKey)) return;
                if (!allowedDeriveBitsAlgorithm[a_name].count(cKey)) {
                    invalidAlgorithmList.push_back(cKey);
                }
                });
            for (std::string key : invalidAlgorithmList) {
                RemoveAttribute(ctx, jsAlgorithm, key);
            }

            JSMData* jsmdPtr = nullptr;
            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                return JS_EXCEPTION;
            }

            uint64_t length_capture = length_val;
            std::string a_name_capture = a_name;
            JSV uAlgorithm_capture = uAlgorithm;
            JSV uBaseKey_capture = uBaseKey;

            std::thread t([=]() {

                uint64_t length = length_capture;
                std::string alg_name = a_name_capture;
                JSV alg = uAlgorithm_capture;
                JSV baseKey = uBaseKey_capture;

                JSV jsKeyInternal = GetProperty(ctx, baseKey, "internal");
                if (!jsKeyInternal.isValid()) {
                    promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.deriveBits] Invalid CryptoKey object (missing internal data)"));
                    return;
                }

                JSV jsKeyData = GetProperty(ctx, jsKeyInternal, "data");
                BYTEBUFFER keyBinary;
                if (!jsKeyData.isValid() || !ReadJSValueAsArrayBufferView(ctx, jsKeyData, keyBinary)) {
                    promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.deriveBits] Failed to read baseKey binary data"));
                    return;
                }

                BYTEBUFFER derivedBits;
                bool deriveResult = false;

                if (alg_name == "PBKDF2") {
                    BYTEBUFFER saltBinary;
                    JSV jsSalt = GetProperty(ctx, alg, "salt");
                    if (!jsSalt.isValid() || !ReadJSValueAsArrayBufferView(ctx, jsSalt, saltBinary)) {
                        promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.deriveBits] PBKDF2 algorithm must have a valid 'salt' property"));
                        return;
                    }

                    uint64_t iterations = 0;
                    JSV jsIterations = GetProperty(ctx, alg, "iterations");
                    if (!jsIterations.isValid() || !ReadJSValueAsUint64(ctx, jsIterations, iterations) || iterations == 0) {
                        promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.deriveBits] PBKDF2 algorithm must have a positive 'iterations' property"));
                        return;
                    }

                    std::string hashName = "SHA-256";
                    JSV jsHash = GetProperty(ctx, alg, "hash");
                    if (jsHash.isValid()) {
                        JSV jsHashName = GetProperty(ctx, jsHash, "name");
                        if (!jsHashName.isValid() || !ReadJSValueAsString(ctx, jsHashName, hashName) || !allowedShaName.count(hashName)) {
                            promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.deriveBits] PBKDF2 hash must have a valid 'name' property"));
                            return;
                        }
                    }

                    if (!hasLength) {
                        promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.deriveBits] PBKDF2 requires the 'length' argument"));
                        return;
                    }

                    deriveResult = crypto_subtle_deriveBits_PBKDF2(&keyBinary, &derivedBits, (size_t)length, &saltBinary, iterations, hashName);
                }
                else if (alg_name == "ECDH") {
                    JSV jsPublicKey = GetProperty(ctx, alg, "public");
                    if (!jsPublicKey.isValid()) jsPublicKey = GetProperty(ctx, uAlgorithm, "publicKey");
                    if (!jsPublicKey.isValid() || !JS_IsObject(jsPublicKey.get()) || GetSymbolName(ctx, jsPublicKey) != "CryptoKey") {
                        promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.deriveBits] ECDH algorithm must have a valid 'public' or 'publicKey' property"));
                        return;
                    }

                    JSV jsCurve = GetProperty(ctx, alg, "namedCurve");

                    std::string curve = "P-256";
                    ReadJSValueAsString(ctx, jsCurve, curve);

                    JSV jsPubKeyInternal = GetProperty(ctx, jsPublicKey, "internal");
                    JSV jsPubKeyData = GetProperty(ctx, jsPubKeyInternal, "data");
                    BYTEBUFFER publicKeyBinary;
                    if (!jsPubKeyData.isValid() || !ReadJSValueAsArrayBufferView(ctx, jsPubKeyData, publicKeyBinary)) {
                        promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.deriveBits] Failed to read ECDH publicKey binary data"));
                        return;
                    }

                    if (!hasLength) {
                        JSV jsBaseKeyAlg = GetProperty(ctx, baseKey, "algorithm");
                        JSV jsNamedCurve = GetProperty(ctx, jsBaseKeyAlg, "namedCurve");
                        std::string curve = "";
                        if (!jsNamedCurve.isValid() || !ReadJSValueAsString(ctx, jsNamedCurve, curve)) {
                            promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.deriveBits] ECDH baseKey algorithm must have a 'namedCurve' property"));
                            return;
                        }

                        if (curve == "P-256") length = 256;
                        else if (curve == "P-384") length = 384;
                        else if (curve == "P-521") length = 521;
                        else if (curve == "X25519") length = 256;
                        else {
                            promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.deriveBits] Unsupported ECDH curve: " + curve));
                            return;
                        }
                    }

                    deriveResult = crypto_subtle_deriveBits_ECDH(&keyBinary, &derivedBits, (size_t)length, &publicKeyBinary, curve);
                }
                else if (alg_name == "HKDF") {
                    std::string hashName = "";
                    JSV jsHash = GetProperty(ctx, alg, "hash");
                    if (!jsHash.isValid()) {
                        promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.deriveBits] HKDF algorithm must have a 'hash' object property"));
                        return;
                    }
                    JSV jsHashName = GetProperty(ctx, jsHash, "name");
                    if (!jsHashName.isValid() || !ReadJSValueAsString(ctx, jsHashName, hashName) || !allowedShaName.count(hashName)) {
                        promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.deriveBits] HKDF hash must have a valid 'name' property"));
                        return;
                    }

                    BYTEBUFFER saltBinary;
                    JSV jsSalt = GetProperty(ctx, alg, "salt");
                    if (jsSalt.isValid() && !ReadJSValueAsArrayBufferView(ctx, jsSalt, saltBinary)) {
                        promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.deriveBits] HKDF 'salt' must be an ArrayBuffer/ArrayBufferView"));
                        return;
                    }

                    BYTEBUFFER infoBinary;
                    JSV jsInfo = GetProperty(ctx, alg, "info");
                    if (jsInfo.isValid() && !ReadJSValueAsArrayBufferView(ctx, jsInfo, infoBinary)) {
                        promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.deriveBits] HKDF 'info' must be an ArrayBuffer/ArrayBufferView"));
                        return;
                    }

                    if (!hasLength) {
                        promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.deriveBits] HKDF requires the 'length' argument"));
                        return;
                    }

                    deriveResult = crypto_subtle_deriveBits_HKDF(&keyBinary, &derivedBits, (size_t)length, &infoBinary, hashName, &saltBinary);
                }
                else {
                    promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.deriveBits] Unsupported algorithm: " + alg_name));
                    return;
                }

                if (!deriveResult || derivedBits.empty()) {
                    promise.Reject(ctx, NewInternalError(ctx, "[crypto.subtle.deriveBits] Failed to derive bits with algorithm: " + alg_name));
                    return;
                }

                promise.Resolve(ctx, NewArrayBuffer(ctx, derivedBits));
                });

            Thread td = std::move(t);
            td.detach();
            jsmdPtr->threadList.push_back(td);
            update(ctx);

            return promise.promise.get(1);
        }
        static JSValue crypto_subtle_deriveKey(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            Promise promise = NewPromise(ctx);

            if (argumentCount != 5) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.deriveKey] Only 5 arguments are supported: (algorithm, baseKey, derivedKeyAlgorithm, extractable, keyUsages)"));
                return promise.promise.get(1);
            }

            JSValue jsAlgorithm = argumentValues[0];
            JSV uAlgorithm = JSV(ctx, &jsAlgorithm).cget(1).cset(1);
            if (!JS_IsObject(jsAlgorithm)) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.deriveKey] The first argument must be a object"));
                return promise.promise.get(1);
            }

            JSValue jsBaseKey = argumentValues[1];
            JSV uBaseKey = JSV(ctx, &jsBaseKey).cget(1).cset(1);
            if (!JS_IsObject(jsBaseKey) || GetSymbolName(ctx, jsBaseKey) != "CryptoKey") {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.deriveKey] The second argument must be a CryptoKey object"));
                return promise.promise.get(1);
            }

            JSValue jsDerivedKeyAlgorithm = argumentValues[2];
            JSV uDerivedKeyAlgorithm = JSV(ctx, &jsDerivedKeyAlgorithm).cget(1).cset(1);
            if (!JS_IsObject(jsDerivedKeyAlgorithm)) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.deriveKey] The third argument must be a object"));
                return promise.promise.get(1);
            }

            bool extractable = false;
            if (!ReadJSValueAsBool(ctx, JSV(ctx, &argumentValues[3]), extractable)) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.deriveKey] The fourth argument (extractable) must be a boolean"));
                return promise.promise.get(1);
            }

            JSValue jsKeyUsages = argumentValues[4];
            std::vector<JSV> jDerivedKeyUsages = {};
            if (!JS_IsArray(jsKeyUsages) || !ReadJSValueAsArray(ctx, JSV(ctx, &jsKeyUsages), jDerivedKeyUsages)) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.deriveKey] The fifth argument (keyUsages) must be an array of strings"));
                return promise.promise.get(1);
            }

            JSV jsBaseKeyUsages = GetProperty(ctx, uBaseKey, "usages");
            std::vector<JSV> jBaseKeyUsages = {};
            if (!JS_IsArray(jsBaseKeyUsages.get()) || !ReadJSValueAsArray(ctx, jsBaseKeyUsages, jBaseKeyUsages)) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.deriveKey] The base CryptoKey 'usages' property must be an array"));
                return promise.promise.get(1);
            }

            JSV js_a_name;
            std::string a_name = "";
            if (!ReadObjectProperty(ctx, uAlgorithm, "name", js_a_name) || !ReadJSValueAsString(ctx, js_a_name, a_name)) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.deriveKey] The algorithm must have the 'name' property"));
                return promise.promise.get(1);
            }

            if (!allowedKeyUsagesList.count(a_name)) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.deriveKey] The algorithm name '" + a_name + "' is not supported"));
                return promise.promise.get(1);
            }

            std::vector<std::string> baseKeyUsages = {};
            for (JSV& jsv : jBaseKeyUsages) {
                std::string usage = "";
                if (!JS_IsString(jsv.get()) || !ReadJSValueAsString(ctx, jsv, usage)) {
                    promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.deriveKey] The base CryptoKey 'usages' array items must all be strings"));
                    return promise.promise.get(1);
                }
                if (!allowedKeyUsagesList[a_name].count(usage)) {
                    promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.deriveKey] Invalid base keyUsage '" + usage + "' for algorithm '" + a_name + "'"));
                    return promise.promise.get(1);
                }
                baseKeyUsages.push_back(usage);
            }

            bool hasValidBaseUsage = false;
            for (const std::string& usage : baseKeyUsages) {
                if (usage == "deriveBits" || usage == "deriveKey") {
                    hasValidBaseUsage = true;
                    break;
                }
            }
            if (!hasValidBaseUsage) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.deriveKey] Base CryptoKey does not have valid usage (deriveBits/deriveKey) for algorithm '" + a_name + "'"));
                return promise.promise.get(1);
            }

            JSV jsDerivedAlgName;
            std::string derivedAlgName = "";
            if (!ReadObjectProperty(ctx, uDerivedKeyAlgorithm, "name", jsDerivedAlgName) || !ReadJSValueAsString(ctx, jsDerivedAlgName, derivedAlgName)) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.deriveKey] The derived key algorithm must have the 'name' property"));
                return promise.promise.get(1);
            }

            if (!allowedKeyUsagesList.count(derivedAlgName)) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.deriveKey] The derived key algorithm name '" + derivedAlgName + "' is not supported"));
                return promise.promise.get(1);
            }

            std::vector<std::string> derivedKeyUsages = {};
            for (JSV& jsv : jDerivedKeyUsages) {
                std::string usage = "";
                if (!JS_IsString(jsv.get()) || !ReadJSValueAsString(ctx, jsv, usage)) {
                    promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.deriveKey] The derived keyUsages array items must all be strings"));
                    return promise.promise.get(1);
                }
                if (!allowedKeyUsagesList[derivedAlgName].count(usage)) {
                    promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.deriveKey] Invalid derived keyUsage '" + usage + "' for algorithm '" + derivedAlgName + "'"));
                    return promise.promise.get(1);
                }
                derivedKeyUsages.push_back(usage);
            }

            if (derivedKeyUsages.empty()) {
                promise.Reject(ctx, NewSyntaxError(ctx, "[crypto.subtle.deriveKey] Usages cannot be empty when creating a derived key"));
                return promise.promise.get(1);
            }

            std::vector<std::string> invalidAlgorithmList = {};
            ForEach(ctx, uAlgorithm, [&](JSV& key, JSV& value) {
                std::string cKey = "";
                if (!ReadJSValueAsString(ctx, key, cKey)) return;
                if (!allowedDeriveKeyAlgorithm[a_name].count(cKey)) {
                    invalidAlgorithmList.push_back(cKey);
                }
                });
            for (std::string key : invalidAlgorithmList) {
                RemoveAttribute(ctx, jsAlgorithm, key);
            }

            JSMData* jsmdPtr = nullptr;
            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                return JS_EXCEPTION;
            }

            std::thread t([=]() {
                JSV jsKeyInternal = GetProperty(ctx, uBaseKey, "internal");
                if (!jsKeyInternal.isValid()) {
                    promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.deriveKey] Invalid base CryptoKey object"));
                    return;
                }

                JSV jsKeyData = GetProperty(ctx, jsKeyInternal, "data");
                BYTEBUFFER keyBinary = {};
                if (!jsKeyData.isValid() || !ReadJSValueAsArrayBufferView(ctx, jsKeyData, keyBinary)) {
                    promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.deriveKey] Failed to read base key data"));
                    return;
                }

                JSV jsDerivedAlgLength = GetProperty(ctx, uDerivedKeyAlgorithm, "length");
                uint64_t derivedLength = 0;
                if (jsDerivedAlgLength.isValid()) {
                    if (!ReadJSValueAsUint64(ctx, jsDerivedAlgLength, derivedLength) || derivedLength == 0 || derivedLength % 8 != 0) {
                        promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.deriveKey] Derived key length must be a positive multiple of 8"));
                        return;
                    }
                }
                else {
                    if (derivedAlgName == "AES-CBC" || derivedAlgName == "AES-GCM" || derivedAlgName == "AES-CTR" || derivedAlgName == "AES-KW") {
                        derivedLength = 256;
                    }
                    else if (derivedAlgName == "HMAC") {
                        derivedLength = 256;
                    }
                    else {
                        promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.deriveKey] Derived key algorithm requires explicit length"));
                        return;
                    }
                }

                BYTEBUFFER derivedKey = {};
                bool deriveResult = false;

                if (a_name == "PBKDF2") {
                    BYTEBUFFER saltBinary = {};
                    JSV jsSalt = GetProperty(ctx, uAlgorithm, "salt");
                    if (!jsSalt.isValid() || !ReadJSValueAsArrayBufferView(ctx, jsSalt, saltBinary)) {
                        promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.deriveKey] PBKDF2 algorithm must have a valid 'salt' property"));
                        return;
                    }

                    uint64_t iterations = 0;
                    JSV jsIterations = GetProperty(ctx, uAlgorithm, "iterations");
                    if (!jsIterations.isValid() || !ReadJSValueAsUint64(ctx, jsIterations, iterations) || iterations == 0) {
                        promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.deriveKey] PBKDF2 algorithm must have a valid positive 'iterations' property"));
                        return;
                    }

                    std::string hashName = "SHA-256";
                    JSV jsHash = GetProperty(ctx, uAlgorithm, "hash");
                    if (jsHash.isValid()) {
                        JSV jsHashName = GetProperty(ctx, jsHash, "name");
                        if (!jsHashName.isValid() || !ReadJSValueAsString(ctx, jsHashName, hashName) || !allowedShaName.count(hashName)) {
                            promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.deriveKey] PBKDF2 must have a valid hash algorithm"));
                            return;
                        }
                    }

                    deriveResult = crypto_subtle_deriveKey_PBKDF2(&keyBinary, &derivedKey, derivedLength, &saltBinary, iterations, hashName);
                }
                else if (a_name == "ECDH") {
                    JSV jsPublicKey = GetProperty(ctx, uAlgorithm, "public");
                    if (!jsPublicKey.isValid()) jsPublicKey = GetProperty(ctx, uAlgorithm, "publicKey");
                    if (!jsPublicKey.isValid() || !JS_IsObject(jsPublicKey.get()) || GetSymbolName(ctx, jsPublicKey) != "CryptoKey") {
                        promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.deriveKey] ECDH algorithm must have a valid 'public' or 'publicKey' CryptoKey property"));
                        return;
                    }

                    JSV jsPublicKeyInternal = GetProperty(ctx, jsPublicKey, "internal");
                    JSV jsPublicKeyData = GetProperty(ctx, jsPublicKeyInternal, "data");
                    BYTEBUFFER publicKeyBinary = {};
                    if (!jsPublicKeyData.isValid() || !ReadJSValueAsArrayBufferView(ctx, jsPublicKeyData, publicKeyBinary)) {
                        promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.deriveKey] ECDH public key data is invalid"));
                        return;
                    }

                    JSV jsBaseKeyAlgorithm = GetProperty(ctx, uBaseKey, "algorithm");
                    std::string curve = "";
                    JSV jsKeyAlgCurve = GetProperty(ctx, jsBaseKeyAlgorithm, "namedCurve");
                    if (!jsKeyAlgCurve.isValid() || !ReadJSValueAsString(ctx, jsKeyAlgCurve, curve) || !allowedCurveName.count(curve)) {
                        promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.deriveKey] ECDH base key must have a valid 'namedCurve' property"));
                        return;
                    }

                    deriveResult = crypto_subtle_deriveKey_ECDH(&keyBinary, &derivedKey, derivedLength, &publicKeyBinary, curve);
                }
                else if (a_name == "HKDF") {
                    std::string hashName = "SHA-256";
                    JSV jsHash = GetProperty(ctx, uAlgorithm, "hash");
                    if (jsHash.isValid()) {
                        JSV jsHashName = GetProperty(ctx, jsHash, "name");
                        if (!jsHashName.isValid() || !ReadJSValueAsString(ctx, jsHashName, hashName) || !allowedShaName.count(hashName)) {
                            promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.deriveKey] HKDF must have a valid hash algorithm"));
                            return;
                        }
                    }

                    BYTEBUFFER saltBinary = {};
                    JSV jsSalt = GetProperty(ctx, uAlgorithm, "salt");
                    if (jsSalt.isValid() && !ReadJSValueAsArrayBufferView(ctx, jsSalt, saltBinary)) {
                        promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.deriveKey] HKDF salt must be a ArrayBuffer or ArrayBufferView"));
                        return;
                    }

                    BYTEBUFFER infoBinary = {};
                    JSV jsInfo = GetProperty(ctx, uAlgorithm, "info");
                    if (jsInfo.isValid() && !ReadJSValueAsArrayBufferView(ctx, jsInfo, infoBinary)) {
                        promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.deriveKey] HKDF info must be a ArrayBuffer or ArrayBufferView"));
                        return;
                    }

                    deriveResult = crypto_subtle_deriveKey_HKDF(&keyBinary, &derivedKey, derivedLength, &infoBinary, hashName, &saltBinary);
                }

                if (!deriveResult || derivedKey.empty()) {
                    promise.Reject(ctx, NewInternalError(ctx, "[crypto.subtle.deriveKey] Failed to derive key with " + a_name));
                    return;
                }

                JSV cryptoKey = NewObject(ctx);
                SetSymbolName(ctx, cryptoKey, "CryptoKey");

                SetAttribute(ctx, cryptoKey, "type", "secret", 0);
                SetAttribute(ctx, cryptoKey, "algorithm", uDerivedKeyAlgorithm, 0);
                SetAttribute(ctx, cryptoKey, "extractable", NewBool(ctx, extractable), 0);

                std::vector<JSV> jUsages;
                for (const std::string& usage : derivedKeyUsages) {
                    jUsages.push_back(NewString(ctx, usage));
                }
                JSV uUsages = NewArray(ctx, jUsages);
                SetAttribute(ctx, cryptoKey, "usages", uUsages, 0);

                JSV privateObject = NewObject(ctx);
                JSV data = NewUint8Array(ctx, derivedKey);
                SetAttribute(ctx, privateObject, "data", data, 0);
                SetAttribute(ctx, privateObject, "_isPrivate", NewBool(ctx, true), 0);
                SetAttribute(ctx, cryptoKey, "internal", privateObject, 0);

                promise.Resolve(ctx, cryptoKey);
                });

            Thread td = std::move(t);
            td.detach();
            jsmdPtr->threadList.push_back(td);
            update(ctx);

            return promise.promise.get(1);
        }
        static JSValue crypto_subtle_sign(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            Promise promise = NewPromise(ctx);

            if (argumentCount != 3) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.sign] Only 3 arguments are supported: (algorithm, key, data)"));
                return promise.promise.get(1);
            }

            JSValue jsAlgorithm = argumentValues[0];
            JSV uAlgorithm = JSV(ctx, &jsAlgorithm).cget(1).cset(1);
            if (!JS_IsObject(jsAlgorithm)) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.sign] The first argument must be a object"));
                return promise.promise.get(1);
            }

            JSValue jsKey = argumentValues[1];
            JSV uKey = JSV(ctx, &jsKey).cget(1).cset(1);
            if (!JS_IsObject(jsKey) || GetSymbolName(ctx, jsKey) != "CryptoKey") {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.sign] The second argument must be a CryptoKey object"));
                return promise.promise.get(1);
            }

            JSV jsKeyUsages = GetProperty(ctx, uKey, "usages");
            std::vector<JSV> jkeyUsages = {};
            if (!JS_IsArray(jsKeyUsages.get()) || !ReadJSValueAsArray(ctx, jsKeyUsages, jkeyUsages)) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.sign] The CryptoKey 'usages' property must be an array"));
                return promise.promise.get(1);
            }

            JSV js_a_name;
            std::string a_name = "";
            if (!ReadObjectProperty(ctx, uAlgorithm, "name", js_a_name) || !ReadJSValueAsString(ctx, js_a_name, a_name)) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.sign] The algorithm must have the 'name' property"));
                return promise.promise.get(1);
            }

            if (!allowedKeyUsagesList.count(a_name)) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.sign] The algorithm name '" + a_name + "' is not supported"));
                return promise.promise.get(1);
            }

            std::vector<std::string> keyUsages = {};
            for (JSV& jsv : jkeyUsages) {
                std::string usage = "";
                if (!JS_IsString(jsv.get()) || !ReadJSValueAsString(ctx, jsv, usage)) {
                    promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.sign] The CryptoKey 'usages' array items must all be strings"));
                    return promise.promise.get(1);
                }
                if (!allowedKeyUsagesList[a_name].count(usage)) {
                    promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.sign] Invalid keyUsage '" + usage + "' for algorithm '" + a_name + "'"));
                    return promise.promise.get(1);
                }
                keyUsages.push_back(usage);
            }

            bool hasValidUsage = false;
            for (const std::string& usage : keyUsages) {
                if (usage == "sign") {
                    hasValidUsage = true;
                    break;
                }
            }
            if (!hasValidUsage) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.sign] CryptoKey does not have valid usage (sign) for algorithm '" + a_name + "'"));
                return promise.promise.get(1);
            }

            JSV jsKeyAlgorithm = GetProperty(ctx, uKey, "algorithm");
            if (!jsKeyAlgorithm.isValid() || !JS_IsObject(jsKeyAlgorithm.get())) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.sign] CryptoKey must have a valid 'algorithm' object property"));
                return promise.promise.get(1);
            }
            JSV jsKeyAlgName = GetProperty(ctx, jsKeyAlgorithm, "name");
            std::string keyAlgName = "";
            if (!jsKeyAlgName.isValid() || !ReadJSValueAsString(ctx, jsKeyAlgName, keyAlgName) || keyAlgName != a_name) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.sign] CryptoKey algorithm '" + keyAlgName + "' does not match input algorithm '" + a_name + "'"));
                return promise.promise.get(1);
            }

            JSV jsExtractable = GetProperty(ctx, uKey, "extractable");
            if (!jsExtractable.isValid() || !JS_IsBool(jsExtractable.get())) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.sign] CryptoKey 'extractable' property must be a boolean"));
                return promise.promise.get(1);
            }

            JSValue jsData = argumentValues[2];
            JSV uData = JSV(ctx, &jsData).cget(1).cset(1);

            std::vector<std::string> invalidAlgorithmList = {};
            ForEach(ctx, uAlgorithm, [&](JSV& key, JSV& value) {
                std::string cKey = "";
                if (!ReadJSValueAsString(ctx, key, cKey)) return;
                if (!allowedSignAlgorithm[a_name].count(cKey)) {
                    invalidAlgorithmList.push_back(cKey);
                }
                });
            for (std::string key : invalidAlgorithmList) {
                RemoveAttribute(ctx, jsAlgorithm, key);
            }

            JSMData* jsmdPtr = nullptr;
            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                return JS_EXCEPTION;
            }

            std::thread t([=]() {
                BYTEBUFFER data = {};
                if (!ReadJSValueAsArrayBufferView(ctx, uData, data)) {
                    promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.sign] The data must be a ArrayBuffer or ArrayBufferView"));
                    return;
                }

                JSV jsKeyInternal = GetProperty(ctx, uKey, "internal");
                if (!jsKeyInternal.isValid()) {
                    promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.sign] Invalid CryptoKey object"));
                    return;
                }

                JSV jsKeyData = GetProperty(ctx, jsKeyInternal, "data");
                BYTEBUFFER keyBinary = {};
                if (!jsKeyData.isValid() || !ReadJSValueAsArrayBufferView(ctx, jsKeyData, keyBinary)) {
                    promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.sign] Failed to read key data"));
                    return;
                }

                BYTEBUFFER signature = {};
                bool signResult = false;

                if (a_name == "RSA-PSS") {
                    std::string hashName = "SHA-256";
                    JSV jsHash = GetProperty(ctx, uAlgorithm, "hash");
                    if (jsHash.isValid()) {
                        JSV jsHashName = GetProperty(ctx, jsHash, "name");
                        if (!jsHashName.isValid() || !ReadJSValueAsString(ctx, jsHashName, hashName) || !allowedShaName.count(hashName)) {
                            promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.sign] RSA-PSS must have a valid hash algorithm"));
                            return;
                        }
                    }
                    signResult = crypto_subtle_sign_RSA_PSS(&data, &keyBinary, &signature, hashName);
                }
                else if (a_name == "RSASSA-PKCS1-v1_5") {
                    std::string hashName = "SHA-256";
                    JSV jsHash = GetProperty(ctx, uAlgorithm, "hash");
                    if (jsHash.isValid()) {
                        JSV jsHashName = GetProperty(ctx, jsHash, "name");
                        if (!jsHashName.isValid() || !ReadJSValueAsString(ctx, jsHashName, hashName) || !allowedShaName.count(hashName)) {
                            promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.sign] RSASSA-PKCS1-v1_5 must have a valid hash algorithm"));
                            return;
                        }
                    }
                    signResult = crypto_subtle_sign_RSA_PKCS1_v1_5(&data, &keyBinary, &signature, hashName);
                }
                else if (a_name == "ECDSA") {
                    std::string hashName = "SHA-256";
                    JSV jsHash = GetProperty(ctx, uAlgorithm, "hash");
                    if (jsHash.isValid()) {
                        JSV jsHashName = GetProperty(ctx, jsHash, "name");
                        if (!jsHashName.isValid() || !ReadJSValueAsString(ctx, jsHashName, hashName) || !allowedShaName.count(hashName)) {
                            promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.sign] ECDSA must have a valid hash algorithm"));
                            return;
                        }
                    }
                    std::string curve = "P-256";
                    JSV jsCurve = GetProperty(ctx, uAlgorithm, "namedCurve");
                    if (jsCurve.isValid()) {
                        if (!ReadJSValueAsString(ctx, jsCurve, curve) || !allowedCurveName.count(curve)) {
                            promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.sign] ECDSA must have a valid namedCurve"));
                            return;
                        }
                    }
                    signResult = crypto_subtle_sign_ECDSA(&data, &keyBinary, &signature, hashName, curve);
                }
                else if (a_name == "HMAC") {
                    std::string hashName = "SHA-256";
                    JSV jsHash = GetProperty(ctx, uAlgorithm, "hash");
                    if (jsHash.isValid()) {
                        JSV jsHashName = GetProperty(ctx, jsHash, "name");
                        if (!jsHashName.isValid() || !ReadJSValueAsString(ctx, jsHashName, hashName) || !allowedShaName.count(hashName)) {
                            promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.sign] HMAC must have a valid hash algorithm"));
                            return;
                        }
                    }
                    signResult = crypto_subtle_sign_HMAC(&data, &keyBinary, &signature, hashName);
                }

                if (!signResult) {
                    promise.Reject(ctx, NewInternalError(ctx, "[crypto.subtle.sign] Failed to sign data with " + a_name));
                    return;
                }

                promise.Resolve(ctx, NewArrayBuffer(ctx, signature));
                });

            Thread td = std::move(t);
            td.detach();
            jsmdPtr->threadList.push_back(td);
            update(ctx);

            return promise.promise.get(1);
        }
        static JSValue crypto_subtle_verify(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            Promise promise = NewPromise(ctx);

            if (argumentCount != 4) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.verify] Only 4 arguments are supported: (algorithm, key, signature, data)"));
                return promise.promise.get(1);
            }

            JSValue jsAlgorithm = argumentValues[0];
            JSV uAlgorithm = JSV(ctx, &jsAlgorithm).cget(1).cset(1);
            if (!JS_IsObject(jsAlgorithm)) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.verify] The first argument must be a object"));
                return promise.promise.get(1);
            }

            JSValue jsKey = argumentValues[1];
            JSV uKey = JSV(ctx, &jsKey).cget(1).cset(1);
            if (!JS_IsObject(jsKey) || GetSymbolName(ctx, jsKey) != "CryptoKey") {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.verify] The second argument must be a CryptoKey object"));
                return promise.promise.get(1);
            }

            JSValue jsSignature = argumentValues[2];
            JSV uSignature = JSV(ctx, &jsSignature).cget(1).cset(1);

            JSValue jsData = argumentValues[3];
            JSV uData = JSV(ctx, &jsData).cget(1).cset(1);

            JSV jsKeyUsages = GetProperty(ctx, uKey, "usages");
            std::vector<JSV> jkeyUsages = {};
            if (!JS_IsArray(jsKeyUsages.get()) || !ReadJSValueAsArray(ctx, jsKeyUsages, jkeyUsages)) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.verify] The CryptoKey 'usages' property must be an array"));
                return promise.promise.get(1);
            }

            JSV js_a_name;
            std::string a_name = "";
            if (!ReadObjectProperty(ctx, uAlgorithm, "name", js_a_name) || !ReadJSValueAsString(ctx, js_a_name, a_name)) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.verify] The algorithm must have the 'name' property"));
                return promise.promise.get(1);
            }

            if (!allowedKeyUsagesList.count(a_name)) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.verify] The algorithm name '" + a_name + "' is not supported"));
                return promise.promise.get(1);
            }

            std::vector<std::string> keyUsages = {};
            for (JSV& jsv : jkeyUsages) {
                std::string usage = "";
                if (!JS_IsString(jsv.get()) || !ReadJSValueAsString(ctx, jsv, usage)) {
                    promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.verify] The CryptoKey 'usages' array items must all be strings"));
                    return promise.promise.get(1);
                }
                if (!allowedKeyUsagesList[a_name].count(usage)) {
                    promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.verify] Invalid keyUsage '" + usage + "' for algorithm '" + a_name + "'"));
                    return promise.promise.get(1);
                }
                keyUsages.push_back(usage);
            }

            bool hasValidUsage = false;
            for (const std::string& usage : keyUsages) {
                if (usage == "verify") {
                    hasValidUsage = true;
                    break;
                }
            }
            if (!hasValidUsage) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.verify] CryptoKey does not have valid usage (verify) for algorithm '" + a_name + "'"));
                return promise.promise.get(1);
            }

            JSV jsKeyAlgorithm = GetProperty(ctx, uKey, "algorithm");
            if (!jsKeyAlgorithm.isValid() || !JS_IsObject(jsKeyAlgorithm.get())) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.verify] CryptoKey must have a valid 'algorithm' object property"));
                return promise.promise.get(1);
            }
            JSV jsKeyAlgName = GetProperty(ctx, jsKeyAlgorithm, "name");
            std::string keyAlgName = "";
            if (!jsKeyAlgName.isValid() || !ReadJSValueAsString(ctx, jsKeyAlgName, keyAlgName) || keyAlgName != a_name) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.verify] CryptoKey algorithm '" + keyAlgName + "' does not match input algorithm '" + a_name + "'"));
                return promise.promise.get(1);
            }

            JSV jsExtractable = GetProperty(ctx, uKey, "extractable");
            if (!jsExtractable.isValid() || !JS_IsBool(jsExtractable.get())) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.verify] CryptoKey 'extractable' property must be a boolean"));
                return promise.promise.get(1);
            }

            std::vector<std::string> invalidAlgorithmList = {};
            ForEach(ctx, uAlgorithm, [&](JSV& key, JSV& value) {
                std::string cKey = "";
                if (!ReadJSValueAsString(ctx, key, cKey)) return;
                if (!allowedVerifyAlgorithm[a_name].count(cKey)) {
                    invalidAlgorithmList.push_back(cKey);
                }
                });
            for (std::string key : invalidAlgorithmList) {
                RemoveAttribute(ctx, jsAlgorithm, key);
            }

            JSMData* jsmdPtr = nullptr;
            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                return JS_EXCEPTION;
            }

            std::thread t([=]() {
                BYTEBUFFER signature = {};
                if (!ReadJSValueAsArrayBufferView(ctx, uSignature, signature)) {
                    promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.verify] The signature must be a ArrayBuffer or ArrayBufferView"));
                    return;
                }

                BYTEBUFFER data = {};
                if (!ReadJSValueAsArrayBufferView(ctx, uData, data)) {
                    promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.verify] The data must be a ArrayBuffer or ArrayBufferView"));
                    return;
                }

                JSV jsKeyInternal = GetProperty(ctx, uKey, "internal");
                if (!jsKeyInternal.isValid()) {
                    promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.verify] Invalid CryptoKey object"));
                    return;
                }

                JSV jsKeyData = GetProperty(ctx, jsKeyInternal, "data");
                BYTEBUFFER keyBinary = {};
                if (!jsKeyData.isValid() || !ReadJSValueAsArrayBufferView(ctx, jsKeyData, keyBinary)) {
                    promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.verify] Failed to read key data"));
                    return;
                }

                bool verifyResult = false;

                if (a_name == "RSA-PSS") {
                    std::string hashName = "SHA-256";
                    JSV jsHash = GetProperty(ctx, uAlgorithm, "hash");
                    if (jsHash.isValid()) {
                        JSV jsHashName = GetProperty(ctx, jsHash, "name");
                        if (!jsHashName.isValid() || !ReadJSValueAsString(ctx, jsHashName, hashName) || !allowedShaName.count(hashName)) {
                            promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.verify] RSA-PSS must have a valid hash algorithm"));
                            return;
                        }
                    }
                    verifyResult = crypto_subtle_verify_RSA_PSS(&data, &keyBinary, &signature, hashName);
                }
                else if (a_name == "RSASSA-PKCS1-v1_5") {
                    std::string hashName = "SHA-256";
                    JSV jsHash = GetProperty(ctx, uAlgorithm, "hash");
                    if (jsHash.isValid()) {
                        JSV jsHashName = GetProperty(ctx, jsHash, "name");
                        if (!jsHashName.isValid() || !ReadJSValueAsString(ctx, jsHashName, hashName) || !allowedShaName.count(hashName)) {
                            promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.verify] RSASSA-PKCS1-v1_5 must have a valid hash algorithm"));
                            return;
                        }
                    }
                    verifyResult = crypto_subtle_verify_RSA_PKCS1_v1_5(&data, &keyBinary, &signature, hashName);
                }
                else if (a_name == "ECDSA") {
                    std::string hashName = "SHA-256";
                    JSV jsHash = GetProperty(ctx, uAlgorithm, "hash");
                    if (jsHash.isValid()) {
                        JSV jsHashName = GetProperty(ctx, jsHash, "name");
                        if (!jsHashName.isValid() || !ReadJSValueAsString(ctx, jsHashName, hashName) || !allowedShaName.count(hashName)) {
                            promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.verify] ECDSA must have a valid hash algorithm"));
                            return;
                        }
                    }
                    std::string curve = "P-256";
                    JSV jsCurve = GetProperty(ctx, uAlgorithm, "namedCurve");
                    if (jsCurve.isValid()) {
                        if (!ReadJSValueAsString(ctx, jsCurve, curve) || !allowedCurveName.count(curve)) {
                            promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.verify] ECDSA must have a valid namedCurve"));
                            return;
                        }
                    }
                    verifyResult = crypto_subtle_verify_ECDSA(&data, &keyBinary, &signature, hashName, curve);
                }
                else if (a_name == "HMAC") {
                    std::string hashName = "SHA-256";
                    JSV jsHash = GetProperty(ctx, uAlgorithm, "hash");
                    if (jsHash.isValid()) {
                        JSV jsHashName = GetProperty(ctx, jsHash, "name");
                        if (!jsHashName.isValid() || !ReadJSValueAsString(ctx, jsHashName, hashName) || !allowedShaName.count(hashName)) {
                            promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.verify] HMAC must have a valid hash algorithm"));
                            return;
                        }
                    }
                    verifyResult = crypto_subtle_verify_HMAC(&data, &keyBinary, &signature, hashName);
                }

                promise.Resolve(ctx, JS_NewBool(ctx, verifyResult));
                });

            Thread td = std::move(t);
            td.detach();
            jsmdPtr->threadList.push_back(td);
            update(ctx);

            return promise.promise.get(1);
        }
        static JSValue crypto_subtle_encrypt(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            Promise promise = NewPromise(ctx);

            if (argumentCount != 3) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.encrypt] Only 3 arguments are supported: (algorithm, key, data)"));
                return promise.promise.get(1);
            }

            JSValue jsAlgorithm = argumentValues[0];
            JSV uAlgorithm = JSV(ctx, &jsAlgorithm).cget(1).cset(1);
            if (!JS_IsObject(jsAlgorithm)) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.encrypt] The first argument must be a object"));
                return promise.promise.get(1);
            }

            JSValue jsKey = argumentValues[1];
            JSV uKey = JSV(ctx, &jsKey).cget(1).cset(1);
            if (!JS_IsObject(jsKey) || GetSymbolName(ctx, jsKey) != "CryptoKey") {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.encrypt] The second argument must be a CryptoKey object"));
                return promise.promise.get(1);
            }

            JSV jsKeyUsages = GetProperty(ctx, uKey, "usages");
            std::vector<JSV> jkeyUsages = {};
            if (!JS_IsArray(jsKeyUsages.get()) || !ReadJSValueAsArray(ctx, jsKeyUsages, jkeyUsages)) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.encrypt] The CryptoKey 'usages' property must be an array"));
                return promise.promise.get(1);
            }

            JSV js_a_name;
            std::string a_name = "";
            if (!ReadObjectProperty(ctx, uAlgorithm, "name", js_a_name) || !ReadJSValueAsString(ctx, js_a_name, a_name)) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.encrypt] The algorithm must have the 'name' property"));
                return promise.promise.get(1);
            }

            if (!allowedKeyUsagesList.count(a_name)) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.encrypt] The algorithm name '" + a_name + "' is not supported"));
                return promise.promise.get(1);
            }

            std::vector<std::string> keyUsages = {};
            for (JSV& jsv : jkeyUsages) {
                std::string usage = "";
                if (!JS_IsString(jsv.get()) || !ReadJSValueAsString(ctx, jsv, usage)) {
                    promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.encrypt] The CryptoKey 'usages' array items must all be strings"));
                    return promise.promise.get(1);
                }
                if (!allowedKeyUsagesList[a_name].count(usage)) {
                    promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.encrypt] Invalid keyUsage '" + usage + "' for algorithm '" + a_name + "'"));
                    return promise.promise.get(1);
                }
                keyUsages.push_back(usage);
            }

            bool hasValidUsage = false;
            if (a_name == "RSA-OAEP" || a_name == "AES-KW") {
                for (const std::string& usage : keyUsages) {
                    if (usage == "encrypt" || usage == "wrapKey") {
                        hasValidUsage = true;
                        break;
                    }
                }
            }
            else {
                for (const std::string& usage : keyUsages) {
                    if (usage == "encrypt") {
                        hasValidUsage = true;
                        break;
                    }
                }
            }
            if (!hasValidUsage) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.encrypt] CryptoKey does not have valid usage (encrypt/wrapKey) for algorithm '" + a_name + "'"));
                return promise.promise.get(1);
            }

            JSV jsKeyAlgorithm = GetProperty(ctx, uKey, "algorithm");
            if (!jsKeyAlgorithm.isValid() || !JS_IsObject(jsKeyAlgorithm.get())) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.encrypt] CryptoKey must have a valid 'algorithm' object property"));
                return promise.promise.get(1);
            }
            JSV jsKeyAlgName = GetProperty(ctx, jsKeyAlgorithm, "name");
            std::string keyAlgName = "";
            if (!jsKeyAlgName.isValid() || !ReadJSValueAsString(ctx, jsKeyAlgName, keyAlgName) || keyAlgName != a_name) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.encrypt] CryptoKey algorithm '" + keyAlgName + "' does not match input algorithm '" + a_name + "'"));
                return promise.promise.get(1);
            }

            JSV jsExtractable = GetProperty(ctx, uKey, "extractable");
            if (!jsExtractable.isValid() || !JS_IsBool(jsExtractable.get())) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.encrypt] CryptoKey 'extractable' property must be a boolean"));
                return promise.promise.get(1);
            }

            JSValue jsData = argumentValues[2];
            JSV uData = JSV(ctx, &jsData).cget(1).cset(1);

            std::vector<std::string> invalidAlgorithmList = {};
            ForEach(ctx, uAlgorithm, [&](JSV& key, JSV& value) {
                std::string cKey = "";
                if (!ReadJSValueAsString(ctx, key, cKey)) return;
                if (!allowedEncryptAlgorithm[a_name].count(cKey)) {
                    invalidAlgorithmList.push_back(cKey);
                }
                });
            for (std::string key : invalidAlgorithmList) {
                RemoveAttribute(ctx, jsAlgorithm, key);
            }

            JSMData* jsmdPtr = nullptr;
            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                return JS_EXCEPTION;
            }

            std::thread t([=]() {
                BYTEBUFFER plaintext = {};
                if (!ReadJSValueAsArrayBufferView(ctx, uData, plaintext)) {
                    promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.encrypt] The data must be a ArrayBuffer or ArrayBufferView"));
                    return;
                }

                JSV jsKeyInternal = GetProperty(ctx, uKey, "internal");
                if (!jsKeyInternal.isValid()) {
                    promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.encrypt] Invalid CryptoKey object"));
                    return;
                }

                JSV jsKeyData = GetProperty(ctx, jsKeyInternal, "data");
                BYTEBUFFER keyBinary = {};
                if (!jsKeyData.isValid() || !ReadJSValueAsArrayBufferView(ctx, jsKeyData, keyBinary)) {
                    promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.encrypt] Failed to read key data"));
                    return;
                }

                BYTEBUFFER ciphertext = {};
                bool encryptResult = false;

                if (a_name == "AES-GCM") {
                    JSV jsIv = GetProperty(ctx, uAlgorithm, "iv");
                    BYTEBUFFER ivBinary = {};
                    if (!jsIv.isValid() || !ReadJSValueAsArrayBufferView(ctx, jsIv, ivBinary)) {
                        promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.encrypt] AES-GCM algorithm must have a valid 'iv' property"));
                        return;
                    }

                    uint64_t tagLength = 128;
                    JSV jsTagLength = GetProperty(ctx, uAlgorithm, "tagLength");
                    if (jsTagLength.isValid()) {
                        uint64_t tempTagLength = 0;
                        if (!ReadJSValueAsUint64(ctx, jsTagLength, tempTagLength) || tempTagLength % 8 != 0 || tempTagLength < 32 || tempTagLength > 128) {
                            promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.encrypt] AES-GCM tagLength must be a multiple of 8 bits between 32 and 128"));
                            return;
                        }
                        tagLength = tempTagLength;
                    }

                    BYTEBUFFER additionalDataBinary = {};
                    JSV jsAdditionalData = GetProperty(ctx, uAlgorithm, "additionalData");
                    if (jsAdditionalData.isValid() && !ReadJSValueAsArrayBufferView(ctx, jsAdditionalData, additionalDataBinary)) {
                        promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.encrypt] AES-GCM additionalData must be a ArrayBuffer or ArrayBufferView"));
                        return;
                    }

                    encryptResult = crypto_subtle_encrypt_AES_GCM(&plaintext, &keyBinary, &ciphertext, &ivBinary, tagLength, &additionalDataBinary);
                }
                else if (a_name == "AES-CBC") {
                    JSV jsIv = GetProperty(ctx, uAlgorithm, "iv");
                    BYTEBUFFER ivBinary = {};
                    if (!jsIv.isValid() || !ReadJSValueAsArrayBufferView(ctx, jsIv, ivBinary)) {
                        promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.encrypt] AES-CBC algorithm must have a valid 'iv' property"));
                        return;
                    }

                    encryptResult = crypto_subtle_encrypt_AES_CBC(&plaintext, &keyBinary, &ciphertext, &ivBinary);
                }
                else if (a_name == "AES-CTR") {
                    JSV jsIv = GetProperty(ctx, uAlgorithm, "iv");
                    BYTEBUFFER ivBinary = {};
                    if (!jsIv.isValid() || !ReadJSValueAsArrayBufferView(ctx, jsIv, ivBinary)) {
                        promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.encrypt] AES-CTR algorithm must have a valid 'iv' property"));
                        return;
                    }

                    encryptResult = crypto_subtle_encrypt_AES_CTR(&plaintext, &keyBinary, &ciphertext, &ivBinary);
                }
                else if (a_name == "ChaCha20-Poly1305") {
                    JSV jsIv = GetProperty(ctx, uAlgorithm, "iv");
                    BYTEBUFFER ivBinary = {};
                    if (!jsIv.isValid() || !ReadJSValueAsArrayBufferView(ctx, jsIv, ivBinary)) {
                        promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.encrypt] ChaCha20-Poly1305 algorithm must have a valid 'iv' property"));
                        return;
                    }

                    BYTEBUFFER additionalDataBinary = {};
                    JSV jsAdditionalData = GetProperty(ctx, uAlgorithm, "additionalData");
                    if (jsAdditionalData.isValid() && !ReadJSValueAsArrayBufferView(ctx, jsAdditionalData, additionalDataBinary)) {
                        promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.encrypt] ChaCha20-Poly1305 additionalData must be a ArrayBuffer or ArrayBufferView"));
                        return;
                    }

                    encryptResult = crypto_subtle_encrypt_ChaCha20_Poly1305(&plaintext, &keyBinary, &ciphertext, &ivBinary, &additionalDataBinary);
                }
                else if (a_name == "RSA-OAEP") {
                    std::string hashName = "SHA-256";
                    JSV jsHash = GetProperty(ctx, uAlgorithm, "hash");
                    if (jsHash.isValid()) {
                        JSV jsHashName = GetProperty(ctx, jsHash, "name");
                        if (!jsHashName.isValid() || !ReadJSValueAsString(ctx, jsHashName, hashName) || !allowedShaName.count(hashName)) {
                            promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.encrypt] RSA-OAEP must have a valid hash algorithm"));
                            return;
                        }
                    }

                    encryptResult = crypto_subtle_encrypt_RSA_OAEP(&plaintext, &keyBinary, &ciphertext, hashName);
                }

                if (!encryptResult) {
                    promise.Reject(ctx, NewInternalError(ctx, "[crypto.subtle.encrypt] Failed to encrypt data with " + a_name));
                    return;
                }

                promise.Resolve(ctx, NewArrayBuffer(ctx, ciphertext));
                });

            Thread td = std::move(t);
            td.detach();
            jsmdPtr->threadList.push_back(td);
            update(ctx);

            return promise.promise.get(1);
        }
        static JSValue crypto_subtle_decrypt(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            Promise promise = NewPromise(ctx);

            if (argumentCount != 3) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.decrypt] Only 3 arguments are supported: (algorithm, key, data)"));
                return promise.promise.get(1);
            }

            JSValue jsAlgorithm = argumentValues[0];
            JSV uAlgorithm = JSV(ctx, &jsAlgorithm).cget(1).cset(1);
            if (!JS_IsObject(jsAlgorithm)) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.decrypt] The first argument must be a object"));
                return promise.promise.get(1);
            }

            JSValue jsKey = argumentValues[1];
            JSV uKey = JSV(ctx, &jsKey).cget(1).cset(1);
            if (!JS_IsObject(jsKey) || GetSymbolName(ctx, jsKey) != "CryptoKey") {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.decrypt] The second argument must be a CryptoKey object"));
                return promise.promise.get(1);
            }

            JSV jsKeyUsages = GetProperty(ctx, uKey, "usages");
            std::vector<JSV> jkeyUsages = {};
            if (!JS_IsArray(jsKeyUsages.get()) || !ReadJSValueAsArray(ctx, jsKeyUsages, jkeyUsages)) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.decrypt] The CryptoKey 'usages' property must be an array"));
                return promise.promise.get(1);
            }

            JSV js_a_name;
            std::string a_name = "";
            if (!ReadObjectProperty(ctx, uAlgorithm, "name", js_a_name) || !ReadJSValueAsString(ctx, js_a_name, a_name)) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.decrypt] The algorithm must have the 'name' property"));
                return promise.promise.get(1);
            }

            if (!allowedKeyUsagesList.count(a_name)) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.decrypt] The algorithm name '" + a_name + "' is not supported"));
                return promise.promise.get(1);
            }

            std::vector<std::string> keyUsages = {};
            for (JSV& jsv : jkeyUsages) {
                std::string usage = "";
                if (!JS_IsString(jsv.get()) || !ReadJSValueAsString(ctx, jsv, usage)) {
                    promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.decrypt] The CryptoKey 'usages' array items must all be strings"));
                    return promise.promise.get(1);
                }
                if (!allowedKeyUsagesList[a_name].count(usage)) {
                    promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.decrypt] Invalid keyUsage '" + usage + "' for algorithm '" + a_name + "'"));
                    return promise.promise.get(1);
                }
                keyUsages.push_back(usage);
            }

            bool hasValidUsage = false;
            if (a_name == "RSA-OAEP" || a_name == "AES-KW") {
                for (const std::string& usage : keyUsages) {
                    if (usage == "decrypt" || usage == "unwrapKey") {
                        hasValidUsage = true;
                        break;
                    }
                }
            }
            else {
                for (const std::string& usage : keyUsages) {
                    if (usage == "decrypt") {
                        hasValidUsage = true;
                        break;
                    }
                }
            }
            if (!hasValidUsage) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.decrypt] CryptoKey does not have valid usage (decrypt/unwrapKey) for algorithm '" + a_name + "'"));
                return promise.promise.get(1);
            }

            JSV jsKeyAlgorithm = GetProperty(ctx, uKey, "algorithm");
            if (!jsKeyAlgorithm.isValid() || !JS_IsObject(jsKeyAlgorithm.get())) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.decrypt] CryptoKey must have a valid 'algorithm' object property"));
                return promise.promise.get(1);
            }
            JSV jsKeyAlgName = GetProperty(ctx, jsKeyAlgorithm, "name");
            std::string keyAlgName = "";
            if (!jsKeyAlgName.isValid() || !ReadJSValueAsString(ctx, jsKeyAlgName, keyAlgName) || keyAlgName != a_name) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.decrypt] CryptoKey algorithm '" + keyAlgName + "' does not match input algorithm '" + a_name + "'"));
                return promise.promise.get(1);
            }

            JSV jsExtractable = GetProperty(ctx, uKey, "extractable");
            if (!jsExtractable.isValid() || !JS_IsBool(jsExtractable.get())) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.decrypt] CryptoKey 'extractable' property must be a boolean"));
                return promise.promise.get(1);
            }

            JSValue jsData = argumentValues[2];
            JSV uData = JSV(ctx, &jsData).cget(1).cset(1);

            std::vector<std::string> invalidAlgorithmList = {};
            ForEach(ctx, uAlgorithm, [&](JSV& key, JSV& value) {
                std::string cKey = "";
                if (!ReadJSValueAsString(ctx, key, cKey)) return;
                if (!allowedDecryptAlgorithm[a_name].count(cKey)) {
                    invalidAlgorithmList.push_back(cKey);
                }
                });
            for (std::string key : invalidAlgorithmList) {
                RemoveAttribute(ctx, jsAlgorithm, key);
            }

            JSMData* jsmdPtr = nullptr;
            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                return JS_EXCEPTION;
            }

            std::thread t([=]() {
                BYTEBUFFER ciphertext = {};
                if (!ReadJSValueAsArrayBufferView(ctx, uData, ciphertext)) {
                    promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.decrypt] The data must be a ArrayBuffer or ArrayBufferView"));
                    return;
                }

                JSV jsKeyInternal = GetProperty(ctx, uKey, "internal");
                if (!jsKeyInternal.isValid()) {
                    promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.decrypt] Invalid CryptoKey object"));
                    return;
                }

                JSV jsKeyData = GetProperty(ctx, jsKeyInternal, "data");
                BYTEBUFFER keyBinary = {};
                if (!jsKeyData.isValid() || !ReadJSValueAsArrayBufferView(ctx, jsKeyData, keyBinary)) {
                    promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.decrypt] Failed to read key data"));
                    return;
                }

                BYTEBUFFER plaintext = {};
                bool decryptResult = false;

                if (a_name == "AES-GCM") {
                    JSV jsIv = GetProperty(ctx, uAlgorithm, "iv");
                    BYTEBUFFER ivBinary = {};
                    if (!jsIv.isValid() || !ReadJSValueAsArrayBufferView(ctx, jsIv, ivBinary)) {
                        promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.decrypt] AES-GCM algorithm must have a valid 'iv' property"));
                        return;
                    }

                    uint64_t tagLength = 128;
                    JSV jsTagLength = GetProperty(ctx, uAlgorithm, "tagLength");
                    if (jsTagLength.isValid()) {
                        uint64_t tempTagLength = 0;
                        if (!ReadJSValueAsUint64(ctx, jsTagLength, tempTagLength) || tempTagLength % 8 != 0 || tempTagLength < 32 || tempTagLength > 128) {
                            promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.decrypt] AES-GCM tagLength must be a multiple of 8 bits between 32 and 128"));
                            return;
                        }
                        tagLength = tempTagLength;
                    }

                    BYTEBUFFER additionalDataBinary = {};
                    JSV jsAdditionalData = GetProperty(ctx, uAlgorithm, "additionalData");
                    if (jsAdditionalData.isValid() && !ReadJSValueAsArrayBufferView(ctx, jsAdditionalData, additionalDataBinary)) {
                        promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.decrypt] AES-GCM additionalData must be a ArrayBuffer or ArrayBufferView"));
                        return;
                    }

                    decryptResult = crypto_subtle_decrypt_AES_GCM(&ciphertext, &keyBinary, &plaintext, &ivBinary, tagLength, &additionalDataBinary);
                }
                else if (a_name == "AES-CBC") {
                    JSV jsIv = GetProperty(ctx, uAlgorithm, "iv");
                    BYTEBUFFER ivBinary = {};
                    if (!jsIv.isValid() || !ReadJSValueAsArrayBufferView(ctx, jsIv, ivBinary)) {
                        promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.decrypt] AES-CBC algorithm must have a valid 'iv' property"));
                        return;
                    }

                    decryptResult = crypto_subtle_decrypt_AES_CBC(&ciphertext, &keyBinary, &plaintext, &ivBinary);
                }
                else if (a_name == "AES-CTR") {
                    JSV jsIv = GetProperty(ctx, uAlgorithm, "iv");
                    BYTEBUFFER ivBinary = {};
                    if (!jsIv.isValid() || !ReadJSValueAsArrayBufferView(ctx, jsIv, ivBinary)) {
                        promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.decrypt] AES-CTR algorithm must have a valid 'iv' property"));
                        return;
                    }

                    decryptResult = crypto_subtle_decrypt_AES_CTR(&ciphertext, &keyBinary, &plaintext, &ivBinary);
                }
                else if (a_name == "ChaCha20-Poly1305") {
                    JSV jsIv = GetProperty(ctx, uAlgorithm, "iv");
                    BYTEBUFFER ivBinary = {};
                    if (!jsIv.isValid() || !ReadJSValueAsArrayBufferView(ctx, jsIv, ivBinary)) {
                        promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.decrypt] ChaCha20-Poly1305 algorithm must have a valid 'iv' property"));
                        return;
                    }

                    BYTEBUFFER additionalDataBinary = {};
                    JSV jsAdditionalData = GetProperty(ctx, uAlgorithm, "additionalData");
                    if (jsAdditionalData.isValid() && !ReadJSValueAsArrayBufferView(ctx, jsAdditionalData, additionalDataBinary)) {
                        promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.decrypt] ChaCha20-Poly1305 additionalData must be a ArrayBuffer or ArrayBufferView"));
                        return;
                    }

                    decryptResult = crypto_subtle_decrypt_ChaCha20_Poly1305(&ciphertext, &keyBinary, &plaintext, &ivBinary, &additionalDataBinary);
                }
                else if (a_name == "RSA-OAEP") {
                    std::string hashName = "SHA-256";
                    JSV jsHash = GetProperty(ctx, uAlgorithm, "hash");
                    if (jsHash.isValid()) {
                        JSV jsHashName = GetProperty(ctx, jsHash, "name");
                        if (!jsHashName.isValid() || !ReadJSValueAsString(ctx, jsHashName, hashName) || !allowedShaName.count(hashName)) {
                            promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.decrypt] RSA-OAEP must have a valid hash algorithm"));
                            return;
                        }
                    }

                    decryptResult = crypto_subtle_decrypt_RSA_OAEP(&ciphertext, &keyBinary, &plaintext, hashName);
                }

                if (!decryptResult) {
                    promise.Reject(ctx, NewInternalError(ctx, "[crypto.subtle.decrypt] Failed to decrypt data with " + a_name));
                    return;
                }

                promise.Resolve(ctx, NewArrayBuffer(ctx, plaintext));
                });

            Thread td = std::move(t);
            td.detach();
            jsmdPtr->threadList.push_back(td);
            update(ctx);

            return promise.promise.get(1);
        }
        static JSValue crypto_subtle_digest(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            Promise promise = NewPromise(ctx);

            if (argumentCount != 2) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.digest] Only 2 arguments are supported: (algorithm, data)"));
                return promise.promise.get(1);
            }

            JSV js_algorithm = JSV(ctx, argumentValues[0]).cget(1).cset(1);
            JSV js_data = JSV(ctx, argumentValues[1]).cget(1).cset(1);

            JSMData* jsmdPtr = nullptr;
            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                return JS_EXCEPTION;
            }

            std::thread t([=]() {

                JSV js_name = GetProperty(ctx, js_algorithm, "name");
                std::string name = "";
                if (!js_name.isValid() || !ReadJSValueAsString(ctx, js_name, name)) {
                    if (!js_name.isValid()) promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.digest] The algorithm must have 'name' property"));
                    else promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.digest] The algorithm name must be a string"));
                    return;
                }

                BYTEBUFFER data = {};
                if (!ReadJSValueAsArrayBufferView(ctx, js_data, data)) {
                    promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.digest] The data must be a ArrayBufferView"));
                    return;
                }

                if (!allowedShaName.count(name)) {
                    promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.digest] The hash '" + name + "' is not supported"));
                    return;
                }

                BYTEBUFFER outData = {};
                if (!crypto_subtle_digest_core(name, &data, &outData)) {
                    promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.digest] Failed to digest data"));
                    return;
                }

                promise.Resolve(ctx, NewArrayBuffer(ctx, outData));
                return;
                });
            Thread td = std::move(t);
            td.detach();
            jsmdPtr->threadList.push_back(td);
            update(ctx);

            return promise.promise.get(1);
        }
        static JSValue crypto_subtle_exportKey(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            Promise promise = NewPromise(ctx);

            if (argumentCount != 2) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.exportKey] Only 2 arguments are supported: (format, key)"));
                return promise.promise.get(1);
            }

            JSV js_format = JSV(ctx, argumentValues[0]).cget(1).cset(1);
            JSV js_key = JSV(ctx, argumentValues[1]).cget(1).cset(1);
            std::string format = "";
            if (!ReadJSValueAsString(ctx, js_format, format)) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.exportKey] The first argument must be a string"));
                return promise.promise.get(1);
            }
            if (GetSymbolName(ctx, js_key) != "CryptoKey") {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.exportKey] The second argument must be a CryptoKey"));
                return promise.promise.get(1);
            }

            JSMData* jsmdPtr = nullptr;
            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                return JS_EXCEPTION;
            }

            std::thread t([=]() {

                JSV js_extractable = GetProperty(ctx, js_key, "extractable");
                bool extractable = false;
                if (!js_extractable.isValid() || !ReadJSValueAsBool(ctx, js_extractable, extractable)) {
                    promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.exportKey] The CryptoKey is invalid"));
                    return;
                }
                if (!extractable) {
                    promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.exportKey] The key is not extractable"));
                    return;
                }

                JSV js_algorithm = GetProperty(ctx, js_key, "algorithm");
                if (!js_algorithm.isValid()) {
                    promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.exportKey] The CryptoKey is invalid"));
                    return;
                }

                JSV js_keyUsages = GetProperty(ctx, js_key, "usages");
                if (!js_keyUsages.isValid()) {
                    promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.exportKey] The CryptoKey is invalid"));
                    return;
                }

                BYTEBUFFER keyBinary = {};
                ReadJSValueAsArrayBufferView(ctx, GetProperty(ctx, js_key, { {"internal"}, {"data"} }), keyBinary);
                if (keyBinary.empty()) {
                    promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.exportKey] The CryptoKey is invalid"));
                    return;
                }

                std::string name = "";
                ReadJSValueAsString(ctx, GetProperty(ctx, js_algorithm, "name"), name);

                if (!allowedExportAlgorithm.count(format)) {
                    promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.exportKey] The format is not supported"));
                    return;
                }

                if (!allowedExportAlgorithm[format].count(name)) {
                    promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.exportKey] Cannot export the '" + name + "' key with '" + format + "' format"));
                    return;
                }

                if (format == "jwk") {

                    OBJECT jwk = {};

                    bool ext = true;
                    ARRAY key_ops = {};

                    ForEach(ctx, js_keyUsages, [&](JSV item) {
                        key_ops.push_back(ToString(ctx, item));
                        });
                    jwk[L"key_ops"] = key_ops;
                    jwk[L"ext"] = ext;

                    if (name == "HMAC" || name.starts_with("AES-") || name == "ChaCha20-Poly1305") {
                        std::string kty = "oct";
                        std::string alg = "";
                        std::string k = "";

                        if (name == "HMAC") {
                            std::string hash_name = "";
                            ReadJSValueAsString(ctx, GetProperty(ctx, js_algorithm, { {"hash"}, {"name"} }), hash_name);
                            if (hash_name.empty()) {
                                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.exportKey] The CryptoKey is invalid"));
                                return;
                            }

                            std::vector<std::string> hash_name_vc = SplitString(hash_name, "-");
                            size_t hash_name_vcs = hash_name_vc.size();
                            if (hash_name_vcs == 2) {
                                alg = "HS" + hash_name_vc[1];
                            }
                            else if (hash_name_vcs == 3) {
                                alg = "HS" + hash_name_vc[1] + "-" + hash_name_vc[2];
                            }
                            else {
                                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.exportKey] The CryptoKey is invalid"));
                                return;
                            }

                            if (!BinaryToBaseX(&keyBinary, 64, true)) {
                                promise.Reject(ctx, NewInternalError(ctx, "[crypto.subtle.exportKey] Failed to export key"));
                                return;
                            }
                            k = GetTextFromBinary(&keyBinary);

                            kty = "oct";
                            jwk[L"kty"] = kty;
                            jwk[L"alg"] = alg;
                            jwk[L"k"] = k;
                        }
                        else if (name.starts_with("AES-")) {
                            uint64_t length = 0;
                            ReadJSValueAsUint64(ctx, GetProperty(ctx, js_algorithm, "length"), length);
                            if (length == 0) {
                                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.exportKey] The CryptoKey is invalid"));
                                return;
                            }

                            std::vector<std::string> name_vc = SplitString(name, "-");
                            size_t name_vcs = name_vc.size();
                            if (name_vcs == 2) {
                                alg = "A" + std::to_string(length) + name_vc[1];
                            }
                            else {
                                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.exportKey] The CryptoKey is invalid"));
                                return;
                            }

                            ForEach(ctx, js_keyUsages, [&](JSV item) {
                                key_ops.push_back(ToString(ctx, item));
                                });

                            if (!BinaryToBaseX(&keyBinary, 64, true)) {
                                promise.Reject(ctx, NewInternalError(ctx, "[crypto.subtle.exportKey] Failed to export key"));
                                return;
                            }
                            k = GetTextFromBinary(&keyBinary);

                            kty = "oct";
                            jwk[L"kty"] = kty;
                            jwk[L"alg"] = alg;
                            jwk[L"ext"] = ext;
                            jwk[L"key_ops"] = key_ops;
                            jwk[L"k"] = k;
                        }
                        else if (name == "ChaCha20-Poly1305") {
                            ForEach(ctx, js_keyUsages, [&](JSV item) {
                                key_ops.push_back(ToString(ctx, item));
                                });

                            if (!BinaryToBaseX(&keyBinary, 64, true)) {
                                promise.Reject(ctx, NewInternalError(ctx, "[crypto.subtle.exportKey] Failed to export key"));
                                return;
                            }
                            k = GetTextFromBinary(&keyBinary);

                            kty = "oct";
                            alg = "ChaCha20-Poly1305";
                            jwk[L"kty"] = kty;
                            jwk[L"alg"] = alg;
                            jwk[L"ext"] = ext;
                            jwk[L"key_ops"] = key_ops;
                            jwk[L"k"] = k;
                        }
                        else {
                            promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.exportKey] The CryptoKey is invalid"));
                            return;
                        }
                    }
                    else if (name.starts_with("RSA-")) {
                        std::string kty = "RSA";

                        std::string hash_name = "";
                        ReadJSValueAsString(ctx, GetProperty(ctx, js_algorithm, { {"hash"}, {"name"} }), hash_name);
                        std::vector<std::string> hash_name_vc = SplitString(hash_name, "-");
                        size_t hash_name_vcs = hash_name_vc.size();
                        if (hash_name_vcs == 2) {
                        }
                        else {
                            promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.exportKey] The CryptoKey is invalid"));
                            return;
                        }
                        std::string alg = (name == "RSA-OAEP" ? name + "-" : (name == "RSA-PSS" ? "PS" : (name == "RSASSA-PKCS1-v1_5" ? "RS" : ""))) + hash_name_vc[1];

                        RSAJWKDATA rjd = crypto_subtle_exportKey_jwk_RSA(&keyBinary);
                        if (rjd.isValid) {
                        }
                        else {
                            promise.Reject(ctx, NewInternalError(ctx, "[crypto.subtle.exportKey] Failed to export key"));
                            return;
                        }

                        jwk[L"alg"] = alg;
                        BinaryToBaseX(&rjd.e, 64, true);
                        BinaryToBaseX(&rjd.n, 64, true);
                        jwk[L"e"] = GetTextFromBinary(&rjd.e);
                        jwk[L"n"] = GetTextFromBinary(&rjd.n);

                        if (rjd.isPrivate) {
                            BinaryToBaseX(&rjd.d, 64, true);
                            BinaryToBaseX(&rjd.p, 64, true);
                            BinaryToBaseX(&rjd.q, 64, true);
                            BinaryToBaseX(&rjd.dp, 64, true);
                            BinaryToBaseX(&rjd.dq, 64, true);
                            BinaryToBaseX(&rjd.qi, 64, true);
                            jwk[L"d"] = GetTextFromBinary(&rjd.d);
                            jwk[L"p"] = GetTextFromBinary(&rjd.p);
                            jwk[L"q"] = GetTextFromBinary(&rjd.q);
                            jwk[L"dp"] = GetTextFromBinary(&rjd.dp);
                            jwk[L"dq"] = GetTextFromBinary(&rjd.dq);
                            jwk[L"qi"] = GetTextFromBinary(&rjd.qi);
                        }

                    }
                    else if (name == "ECDSA" || name == "ECDH") {
                        std::string kty = "EC";

                        std::string namedCurve = "";
                        ReadJSValueAsString(ctx, GetProperty(ctx, js_algorithm, "namedCurve"), namedCurve);

                        ECJWKDATA ejd = crypto_subtle_exportKey_jwk_EC(&keyBinary);
                        if (ejd.isValid) {
                        }
                        else {
                            promise.Reject(ctx, NewInternalError(ctx, "[crypto.subtle.exportKey] Failed to export key"));
                            return;
                        }

                        jwk[L"crv"] = namedCurve;

                        BinaryToBaseX(&ejd.x, 64, true);
                        BinaryToBaseX(&ejd.y, 64, true);
                        jwk[L"x"] = GetTextFromBinary(&ejd.x);
                        jwk[L"y"] = GetTextFromBinary(&ejd.y);

                        if (ejd.isPrivate) {
                            BinaryToBaseX(&ejd.d, 64, true);
                            jwk[L"d"] = GetTextFromBinary(&ejd.d);
                        }

                    }
                    else if (name == "Ed25519" || name == "X25519") {
                        std::string kty = "OKP";

                        std::string namedCurve = "";
                        ReadJSValueAsString(ctx, GetProperty(ctx, js_algorithm, "namedCurve"), namedCurve);

                        std::string type = "";
                        ReadJSValueAsString(ctx, GetProperty(ctx, js_key, "type"), type);

                        BYTEBUFFER publicKeyBinary = {};
                        if (crypto_subtle_exportKey_jwk_Ed25519_X25519(&keyBinary, &publicKeyBinary)) {
                        }
                        else {
                            promise.Reject(ctx, NewInternalError(ctx, "[crypto.subtle.exportKey] Failed to export key"));
                            return;
                        }

                        jwk[L"crv"] = name;

                        BinaryToBaseX(&publicKeyBinary, 64, true);
                        jwk[L"x"] = GetTextFromBinary(&publicKeyBinary);

                        if (type == "private") {
                            BinaryToBaseX(&keyBinary, 64, true);
                            jwk[L"d"] = GetTextFromBinary(&keyBinary);
                        }
                    }
                    else {
                        promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.exportKey] The algorithm name '" + name + "' is not supported"));
                    }

                    promise.Resolve(ctx, NewObject(ctx, jwk));
                    return;
                }
                else {
                    if (format == "spki" || format == "pkcs8") {
                        std::string type = "";
                        ReadJSValueAsString(ctx, GetProperty(ctx, js_key, "type"), type);
                        if ((type == "public" && format == "pkcs8") || (type == "private" && format == "spki") || type == "") {
                            promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.exportKey] Cannot export " + type + " key as format '" + format + "'"));
                            return;
                        }
                    }

                    promise.Resolve(ctx, NewArrayBuffer(ctx, keyBinary));
                    return;
                }

                return;
                });
            Thread td = std::move(t);
            td.detach();
            jsmdPtr->threadList.push_back(td);
            update(ctx);

            return promise.promise.get(1);
        }
        static JSValue crypto_subtle_importKey(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            Promise promise = NewPromise(ctx);

            if (argumentCount != 5) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] Only 5 arguments are supported: (format, keyData, algorithm, extractable, keyUsages)"));
                return promise.promise.get(1);
            }

            JSV js_format = JSV(ctx, &argumentValues[0]).cget(1).cset(1);
            JSV js_keyData = JSV(ctx, &argumentValues[1]).cget(1).cset(1);
            JSV js_algorithm = JSV(ctx, &argumentValues[2]).cget(1).cset(1);
            JSV js_extractable = JSV(ctx, &argumentValues[3]).cget(1).cset(1);
            JSV js_keyUsages = JSV(ctx, &argumentValues[4]).cget(1).cset(1);

            std::string format = "";
            if (!ReadJSValueAsString(ctx, js_format, format)) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The format must be a string"));
                return promise.promise.get(1);
            }
            if (!allowedImportAlgorithm.count(format)) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The format '" + format + "' is not supported"));
                return promise.promise.get(1);
            }

            JSV js_a_name = {};
            std::string a_name = "";
            if (!ReadObjectProperty(ctx, js_algorithm, "name", js_a_name) || !ReadJSValueAsString(ctx, js_a_name, a_name)) {
                if (!js_algorithm.isValid()) promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The algorithm must be an object"));
                else promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The algorithm name must be a string"));
                return promise.promise.get(1);
            }

            if (!allowedImportAlgorithm[format].count(a_name) || !allowedKeyUsagesList.count(a_name)) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The algorithm is not supported"));
                return promise.promise.get(1);
            }

            std::vector<std::string> invalidAlgorithmList = {};
            ForEach(ctx, js_algorithm, [&](JSV& key, JSV& value) {
                std::string cKey = "";
                if (!ReadJSValueAsString(ctx, key, cKey)) return;
                if (!allowedImportAlgorithm[format][a_name].count(cKey)) {
                    invalidAlgorithmList.push_back(cKey);
                }
                });
            for (std::string key : invalidAlgorithmList) {
                RemoveAttribute(ctx, js_algorithm, key);
            }

            std::vector<JSV> tjs_keyUsages = {};
            if (!JS_IsArray(js_keyUsages.get(0)) || !ReadJSValueAsArray(ctx, js_keyUsages, tjs_keyUsages)) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The keyUsages must be an array"));
                return promise.promise.get(1);
            }

            std::vector<std::string> keyUsages = {};
            for (JSV& jsv : tjs_keyUsages) {
                std::string usage = "";
                if (!JS_IsString(jsv.get()) || !ReadJSValueAsString(ctx, jsv, usage)) {
                    promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The keyUsages must be a string array"));
                    return promise.promise.get(1);
                }
                if (!allowedKeyUsagesList[a_name].count(usage)) {
                    promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The keyUsage '" + usage + "' is not supported"));
                    return promise.promise.get(1);
                }
                keyUsages.push_back(usage);
            }

            JSMData* jsmdPtr = nullptr;
            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                return JS_EXCEPTION;
            }

            std::thread t([=]() {

                BYTEBUFFER keyBinary = {};
                PKDATA pkd = {};

                if (format != "jwk") {
                    if (!ReadJSValueAsArrayBufferView(ctx, js_keyData, keyBinary)) {
                        promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The keyData must be an ArrayBuffer or ArrayBufferView"));
                        return;
                    }
                }
                else {
                    OBJECT jwk = {};
                    if (!ReadJSValueAsObject(ctx, js_keyData, jwk)) {
                        promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The keyData must be an object"));
                        return;
                    }
                    if (!jwk.count(L"kty") || !jwk[L"kty"].isString()) {
                        promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The keyData must have a 'kty' string property"));
                        return;
                    }
                    if (jwk[L"kty"].get<std::string>() == "oct") {

                        std::string name = "";
                        std::string hash = "";
                        uint64_t length = 0;

                        if (jwk.count(L"alg")) {

                            std::string alg = jwk[L"alg"].get<std::string>();
                            uint64_t alen = alg.length();

                            std::string alg1 = (alg.length() >= 1) ? alg.substr(0, 1) : "";
                            std::string alg2 = (alg.length() >= 2) ? alg.substr(1, 1) : "";
                            std::string alg3 = (alg.length() >= 3) ? alg.substr(2, 1) : "";
                            std::string alg4 = (alg.length() >= 4) ? alg.substr(3, 1) : "";
                            std::string alg5 = (alg.length() >= 5) ? alg.substr(4, 1) : "";
                            std::string alg6 = (alg.length() >= 6) ? alg.substr(5, 1) : "";
                            std::string alg7 = (alg.length() >= 7) ? alg.substr(6, 1) : "";
                            std::string alg8 = (alg.length() >= 8) ? alg.substr(7, 1) : "";
                            if (alg1 + alg2 == "HS") {
                                name = "HMAC";
                                if (alg4 != "-" && alen >= 5) {
                                    hash = "SHA-" + alg3 + alg4 + alg5;
                                }
                                else if (alg4 == "-" && alen >= 7) {
                                    hash = "SHA-" + alg3 + "-" + alg5 + alg6 + alg7;
                                }
                                else if (alg4 == "-" && alen >= 8) {
                                    hash = "SHA-" + alg3 + "-" + alg5 + alg6 + alg7 + alg8;
                                }
                            }
                            else if (alg1 == "A" && alen >= 7) {
                                name = "AES-" + alg5 + alg6 + alg7;
                                length = stoullSafely(stringToWstring(alg2 + alg3 + alg4));
                            }
                            else if (alg == "CHACHA20-POLY1305") {
                                name = "ChaCha20-Poly1305";
                            }
                            else {
                                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The algorithm '" + alg + "' is not supported"));
                                return;
                            }
                            if (name != "" && name != a_name) {
                                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The algorithm does not match the keyData"));
                                return;
                            }

                        }

                        BYTEBUFFER tempKeyBinary = {};
                        if (!jwk.count(L"k") || !jwk[L"k"].isString()) {
                            promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The keyData must have a 'k' string property"));
                            return;
                        }
                        tempKeyBinary = ToBinary(jwk[L"k"].get<std::string>());
                        if (!BaseXToBinary(&tempKeyBinary, 64, true)) {
                            promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The 'k' value is not a valid base64url string"));
                            return;
                        }

                        JSV js_a_hash = {};
                        JSV js_hash_name = {};
                        std::string a_hash_name = "";
                        if (name == "HMAC" && (!ReadObjectProperty(ctx, js_algorithm, "hash", js_a_hash) || !ReadObjectProperty(ctx, js_a_hash, "name", js_hash_name) || !ReadJSValueAsString(ctx, js_hash_name, a_hash_name))) {
                            if (!js_a_hash.isValid()) promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The algorithm must have a 'hash' object"));
                            else if (!js_hash_name.isValid()) promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The hash must have a 'name' string"));
                            else promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The hash does not match the keyData"));
                            return;
                        }
                        bool lengthCheckPass = true;
                        if (name.find("AES") != std::string::npos && length > 0) {
                            lengthCheckPass = (tempKeyBinary.size() * 8 >= 128 && tempKeyBinary.size() * 8 <= 512 && tempKeyBinary.size() * 8 % 8 == 0);
                        }
                        else if (name == "ChaCha20-Poly1305") {
                            lengthCheckPass = (tempKeyBinary.size() >= 16 && tempKeyBinary.size() <= 32 && tempKeyBinary.size() % 8 == 0);
                        }
                        else if (name == "HMAC" && hash != "") {
                            lengthCheckPass = (hash == a_hash_name);
                        }
                        if (!lengthCheckPass) {
                            promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The algorithm does not match the keyData"));
                            return;
                        }

                        keyBinary = std::move(tempKeyBinary);
                    }
                    else if (jwk[L"kty"].get<std::string>() == "RSA") {

                        if (!jwk.count(L"e") || !jwk[L"e"].isString()) {
                            promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The keyData must have an 'e' string property"));
                            return;
                        }
                        if (!jwk.count(L"n") || !jwk[L"n"].isString()) {
                            promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The keyData must have an 'n' string property"));
                            return;
                        }

                        std::string name = "";
                        std::string hash = "";

                        if (jwk.count(L"alg")) {

                            std::string alg = jwk[L"alg"].get<std::string>();
                            uint64_t alen = alg.length();
                            std::string alg1 = (alg.length() >= 1) ? alg.substr(0, 1) : "";
                            std::string alg2 = (alg.length() >= 2) ? alg.substr(1, 1) : "";
                            std::string alg3 = (alg.length() >= 3) ? alg.substr(2, 1) : "";
                            std::string alg4 = (alg.length() >= 4) ? alg.substr(3, 1) : "";
                            std::string alg5 = (alg.length() >= 5) ? alg.substr(4, 1) : "";
                            std::string alg6 = (alg.length() >= 6) ? alg.substr(5, 1) : "";
                            std::string alg7 = (alg.length() >= 7) ? alg.substr(6, 1) : "";
                            std::string alg8 = (alg.length() >= 8) ? alg.substr(7, 1) : "";
                            std::string alg9 = (alg.length() >= 9) ? alg.substr(8, 1) : "";
                            std::string alg10 = (alg.length() >= 10) ? alg.substr(9, 1) : "";
                            std::string alg11 = (alg.length() >= 11) ? alg.substr(10, 1) : "";
                            std::string alg12 = (alg.length() >= 12) ? alg.substr(11, 1) : "";

                            if (alg1 + alg2 == "PS") {
                                name = "RSA-PSS";
                                if (alg4 != "-" && alen >= 5) hash = "SHA-" + alg3 + alg4 + alg5;
                                else if (alg4 == "-" && alen >= 7) hash = "SHA-" + alg3 + "-" + alg5 + alg6 + alg7;
                            }
                            else if (alg1 + alg2 == "RS") {
                                name = "RSASSA-PKCS1-v1_5";
                                if (alg4 != "-" && alen >= 5) hash = "SHA-" + alg3 + alg4 + alg5;
                                else if (alg4 == "-" && alen >= 7) hash = "SHA-" + alg3 + "-" + alg5 + alg6 + alg7;
                            }
                            else if (alg1 + alg2 + alg3 == "RSA" && alg4 == "-" && alg5 + alg6 + alg7 + alg8 == "OAEP") {
                                name = "RSA-OAEP";
                                hash = "";
                            }
                            else {
                                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The algorithm '" + alg + "' is not supported"));
                                return;
                            }

                            JSV js_a_hash = {};
                            JSV js_hash_name = {};
                            std::string a_hash_name = "";
                            if (!ReadObjectProperty(ctx, js_algorithm, "hash", js_a_hash) || !ReadObjectProperty(ctx, js_a_hash, "name", js_hash_name) || !ReadJSValueAsString(ctx, js_hash_name, a_hash_name)) {
                                if (!js_a_hash.isValid()) promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The algorithm must have a 'hash' object"));
                                else if (!js_hash_name.isValid()) promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The hash must have a 'name' string"));
                                else promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The hash does not match the keyData"));
                                return;
                            }

                            if (name != a_name || (hash != "" && hash != a_hash_name)) {
                                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The algorithm does not match the keyData"));
                                return;
                            }

                        }

                        BYTEBUFFER tempKeyBinary = {};
                        BYTEBUFFER e = ToBinary(jwk[L"e"].get<std::string>());
                        BYTEBUFFER n = ToBinary(jwk[L"n"].get<std::string>());
                        if (e.empty()) {
                            promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The 'e' property must not be empty"));
                            return;
                        }
                        if (n.empty()) {
                            promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The 'n' property must not be empty"));
                            return;
                        }
                        if (!BaseXToBinary(&e, 64, true)) {
                            promise.Reject(ctx, NewSyntaxError(ctx, "[crypto.subtle.importKey] The 'e' value is not a valid base64url string"));
                            return;
                        }
                        if (!BaseXToBinary(&n, 64, true)) {
                            promise.Reject(ctx, NewSyntaxError(ctx, "[crypto.subtle.importKey] The 'n' value is not a valid base64url string"));
                            return;
                        }

                        BYTEBUFFER d = {}, p = {}, q = {}, dp = {}, dq = {}, qi = {};
                        bool hasPrivateParams = jwk.count(L"d") && jwk[L"d"].isString();
                        if (hasPrivateParams) {
                            d = ToBinary(jwk[L"d"].get<std::string>());
                            if (d.empty()) {
                                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The 'd' property must not be empty"));
                                return;
                            }
                            if (!BaseXToBinary(&d, 64, true)) {
                                promise.Reject(ctx, NewSyntaxError(ctx, "[crypto.subtle.importKey] The 'd' value is not a valid base64url string"));
                                return;
                            }

                            if (jwk.count(L"p") && jwk[L"p"].isString()) {
                                p = ToBinary(jwk[L"p"].get<std::string>());
                                if (!p.empty() && !BaseXToBinary(&p, 64, true)) {
                                    promise.Reject(ctx, NewSyntaxError(ctx, "[crypto.subtle.importKey] The 'p' value is not a valid base64url string"));
                                    return;
                                }
                            }
                            if (jwk.count(L"q") && jwk[L"q"].isString()) {
                                q = ToBinary(jwk[L"q"].get<std::string>());
                                if (!q.empty() && !BaseXToBinary(&q, 64, true)) {
                                    promise.Reject(ctx, NewSyntaxError(ctx, "[crypto.subtle.importKey] The 'q' value is not a valid base64url string"));
                                    return;
                                }
                            }
                            if (jwk.count(L"dp") && jwk[L"dp"].isString()) {
                                dp = ToBinary(jwk[L"dp"].get<std::string>());
                                if (!dp.empty() && !BaseXToBinary(&dp, 64, true)) {
                                    promise.Reject(ctx, NewSyntaxError(ctx, "[crypto.subtle.importKey] The 'dp' value is not a valid base64url string"));
                                    return;
                                }
                            }
                            if (jwk.count(L"dq") && jwk[L"dq"].isString()) {
                                dq = ToBinary(jwk[L"dq"].get<std::string>());
                                if (!dq.empty() && !BaseXToBinary(&dq, 64, true)) {
                                    promise.Reject(ctx, NewSyntaxError(ctx, "[crypto.subtle.importKey] The 'dq' value is not a valid base64url string"));
                                    return;
                                }
                            }
                            if (jwk.count(L"qi") && jwk[L"qi"].isString()) {
                                qi = ToBinary(jwk[L"qi"].get<std::string>());
                                if (!qi.empty() && !BaseXToBinary(&qi, 64, true)) {
                                    promise.Reject(ctx, NewSyntaxError(ctx, "[crypto.subtle.importKey] The 'qi' value is not a valid base64url string"));
                                    return;
                                }
                            }

                            if (!crypto_subtle_importKey_jwk_RSA(&e, &n, &tempKeyBinary, &d, &p, &q, &dp, &dq, &qi)) {
                                promise.Reject(ctx, NewInternalError(ctx, "[crypto.subtle.importKey] Failed to parse the key"));
                                return;
                            }
                        }
                        else {
                            if (!crypto_subtle_importKey_jwk_RSA(&e, &n, &tempKeyBinary)) {
                                promise.Reject(ctx, NewInternalError(ctx, "[crypto.subtle.importKey] Failed to parse the key"));
                                return;
                            }
                        }

                        keyBinary = std::move(tempKeyBinary);
                    }
                    else if (jwk[L"kty"].get<std::string>() == "EC") {

                        if (!jwk.count(L"crv") || !jwk[L"crv"].isString()) {
                            promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The keyData must have a 'crv' string property"));
                            return;
                        }
                        std::string crv = jwk[L"crv"].get<std::string>();

                        if (!allowedCurveName.count(crv)) {
                            promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The namedCurve '" + crv + "' is not supported"));
                            return;
                        }

                        JSV js_a_namedCurve = {};
                        std::string a_named_curve = "";
                        if (!ReadObjectProperty(ctx, js_algorithm, "namedCurve", js_a_namedCurve) || !ReadJSValueAsString(ctx, js_a_namedCurve, a_named_curve)) {
                            promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The algorithm must have a 'namedCurve' string"));
                            return;
                        }

                        if (a_named_curve != crv) {
                            promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The algorithm does not match the keyData"));
                            return;
                        }

                        BYTEBUFFER tempKeyBinary = {};
                        bool hasPrivateKey = jwk.count(L"d") && jwk[L"d"].isString();
                        if (hasPrivateKey) {
                            BYTEBUFFER d = ToBinary(jwk[L"d"].get<std::string>());
                            if (d.empty()) {
                                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The 'd' property must not be empty"));
                                return;
                            }
                            if (!BaseXToBinary(&d, 64, true)) {
                                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The 'd' value is not a valid base64url string"));
                                return;
                            }
                            if (!crypto_subtle_importKey_jwk_EC(crv, &tempKeyBinary, &d)) {
                                promise.Reject(ctx, NewInternalError(ctx, "[crypto.subtle.importKey] Failed to parse the key"));
                                return;
                            }
                        }
                        else {
                            if (!jwk.count(L"x") || !jwk[L"x"].isString()) {
                                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The keyData must have an 'x' string property"));
                                return;
                            }
                            if (!jwk.count(L"y") || !jwk[L"y"].isString()) {
                                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The keyData must have a 'y' string property"));
                                return;
                            }
                            BYTEBUFFER x = ToBinary(jwk[L"x"].get<std::string>());
                            BYTEBUFFER y = ToBinary(jwk[L"y"].get<std::string>());
                            if (x.empty()) {
                                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The 'x' property must not be empty"));
                                return;
                            }
                            if (y.empty()) {
                                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The 'y' property must not be empty"));
                                return;
                            }
                            if (!BaseXToBinary(&x, 64, true)) {
                                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The 'x' value is not a valid base64url string"));
                                return;
                            }
                            if (!BaseXToBinary(&y, 64, true)) {
                                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The 'y' value is not a valid base64url string"));
                                return;
                            }
                            if (!crypto_subtle_importKey_jwk_EC(crv, &tempKeyBinary, nullptr, &x, &y)) {
                                promise.Reject(ctx, NewInternalError(ctx, "[crypto.subtle.importKey] Failed to parse the key"));
                                return;
                            }
                        }

                        keyBinary = std::move(tempKeyBinary);
                    }
                    else if (jwk[L"kty"].get<std::string>() == "OKP") {
                        if (!jwk.count(L"crv") || !jwk[L"crv"].isString()) {
                            promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The keyData must have a 'crv' string property"));
                            return;
                        }
                        std::string crv = jwk[L"crv"].get<std::string>();

                        if (crv != a_name) {
                            promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The algorithm does not match the keyData"));
                            return;
                        }

                        BYTEBUFFER tempKeyBinary = {};

                        if (crv == "Ed25519" || crv == "X25519") {
                            bool hasPrivateKey = jwk.count(L"d") && jwk[L"d"].isString();
                            if (hasPrivateKey) {
                                BYTEBUFFER d = ToBinary(jwk[L"d"].get<std::string>());
                                if (d.empty()) {
                                    promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The 'd' property must not be empty"));
                                    return;
                                }
                                if (!BaseXToBinary(&d, 64, true)) {
                                    promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The 'd' value is not a valid base64url string"));
                                    return;
                                }
                                if (d.size() != 32) {
                                    promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The 'd' value must be 32 bytes"));
                                    return;
                                }
                                pkd.isValid = true;
                                pkd.isPrivate = true;
                                pkd.name = crv;
                                tempKeyBinary = std::move(d);
                            }
                            else {
                                if (!jwk.count(L"x") || !jwk[L"x"].isString()) {
                                    promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The keyData must have an 'x' string property"));
                                    return;
                                }
                                BYTEBUFFER x = ToBinary(jwk[L"x"].get<std::string>());
                                if (x.empty()) {
                                    promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The 'x' property must not be empty"));
                                    return;
                                }
                                if (!BaseXToBinary(&x, 64, true)) {
                                    promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The 'x' value is not a valid base64url string"));
                                    return;
                                }
                                if (x.size() != 32) {
                                    promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The 'x' value must be 32 bytes"));
                                    return;
                                }
                                pkd.isValid = true;
                                pkd.isPrivate = false;
                                pkd.name = crv;
                                tempKeyBinary = std::move(x);
                            }
                        }
                        else {
                            promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The curve '" + crv + "' is not supported"));
                            return;
                        }

                        keyBinary = std::move(tempKeyBinary);
                    }
                }

                if ((a_name.find("AES") == std::string::npos && a_name != "HMAC" && a_name != "ChaCha20-Poly1305") && a_name != "Ed25519" && a_name != "X25519" && a_name != "HKDF" && a_name != "PBKDF2") pkd = GetPKData(&keyBinary);

                if (pkd.isValid) {

                    if (format == "raw" || (pkd.isPrivate && format == "spki") || (!pkd.isPrivate && format == "pkcs8")) {
                        promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] Cannot import " + std::string(pkd.isPrivate ? "private" : "public") + " key as format '" + format + "'"));
                        return;
                    }

                    if (pkd.name == a_name || (a_name.find("RSA") != std::string::npos && pkd.name == "RSA")) {
                        if (pkd.modulusLength != 0) {
                            if (pkd.modulusLength >= 1024 && pkd.modulusLength <= 16384 && pkd.modulusLength % 8 == 0) {
                                SetAttribute(ctx, js_algorithm, "modulusLength", NewUint64(ctx, pkd.modulusLength), 0);
                            }
                            else {
                                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] RSA modulus length must be 1024-16384 bits and multiple of 8"));
                                return;
                            }
                        }
                        if (pkd.publicExponent != 0) {
                            if (pkd.publicExponent > 1 && pkd.publicExponent % 2 == 1) {
                                SetAttribute(ctx, js_algorithm, "publicExponent", NewUint64(ctx, pkd.publicExponent), 0);
                            }
                            else {
                                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] RSA public exponent must be odd and greater than 1"));
                                return;
                            }
                        }
                    }
                    else {
                        promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The algorithm does not match the key"));
                        return;
                    }

                    for (std::string usage : keyUsages) {
                        if (!allowedKeyUsagesList[a_name].count(usage) || (allowedKeyUsagesList[a_name][usage] != "" && allowedKeyUsagesList[a_name][usage] != std::string((pkd.isPrivate) ? "b" : "a"))) {
                            promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The keyUsage '" + usage + "' is not supported"));
                            return;
                        }
                    }

                    JSV returnValue = NewObject(ctx);
                    SetSymbolName(ctx, returnValue, "CryptoKey");
                    SetAttribute(ctx, returnValue, "type", pkd.isPrivate ? "private" : "public", 0);
                    SetAttribute(ctx, returnValue, "algorithm", js_algorithm, 0);
                    SetAttribute(ctx, returnValue, "extractable", js_extractable, 0);
                    SetAttribute(ctx, returnValue, "usages", js_keyUsages, 0);

                    JSV privateObject = NewObject(ctx);
                    JSV data = NewUint8Array(ctx, keyBinary);
                    SetAttribute(ctx, privateObject, "data", data, 0);
                    SetAttribute(ctx, privateObject, "_isPrivate", NewBool(ctx, true), 0);
                    SetAttribute(ctx, returnValue, "internal", privateObject, 0);

                    promise.Resolve(ctx, returnValue);

                }
                else {

                    if (a_name == "HMAC") {
                        JSV js_a_hash = {};
                        JSV js_hash_name = {};
                        std::string a_hash_name = "";
                        if (!ReadObjectProperty(ctx, js_algorithm, "hash", js_a_hash) || !ReadObjectProperty(ctx, js_a_hash, "name", js_hash_name) || !ReadJSValueAsString(ctx, js_hash_name, a_hash_name)) {
                            if (!js_a_hash.isValid()) promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The algorithm must have a 'hash' object"));
                            else if (!js_hash_name.isValid()) promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The hash must have a 'name' string"));
                            else promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The hash does not match the key"));
                            return;
                        }
                        if (!IsHMACMatched(&keyBinary, a_hash_name)) {
                            promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The hash does not match the key"));
                            return;
                        }
                        if (keyBinary.size() * 8 < 8 || keyBinary.size() * 8 > 4096 || keyBinary.size() * 8 % 8 != 0) {
                            promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] HMAC key length must be 8-4096 bits and multiple of 8"));
                            return;
                        }
                    }
                    else if (a_name == "HKDF") {
                        JSV js_a_hash = {};
                        JSV js_hash_name = {};
                        std::string a_hash_name = "";
                        if (!ReadObjectProperty(ctx, js_algorithm, "hash", js_a_hash) || !ReadObjectProperty(ctx, js_a_hash, "name", js_hash_name) || !ReadJSValueAsString(ctx, js_hash_name, a_hash_name)) {
                            if (!js_a_hash.isValid()) promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The algorithm must have a 'hash' object"));
                            else if (!js_hash_name.isValid()) promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The hash must have a 'name' string"));
                            else promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The hash does not match the key"));
                            return;
                        }
                        if (keyBinary.empty() || keyBinary.size() * 8 % 8 != 0) {
                            promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] HKDF key length must be a non-empty multiple of 8 bits"));
                            return;
                        }
                    }
                    else if (a_name == "PBKDF2") {
                        JSV js_a_hash = {};
                        JSV js_hash_name = {};
                        std::string a_hash_name = "";
                        if (ReadObjectProperty(ctx, js_algorithm, "hash", js_a_hash) && js_a_hash.isValid()) {
                            if (!ReadObjectProperty(ctx, js_a_hash, "name", js_hash_name) || !ReadJSValueAsString(ctx, js_hash_name, a_hash_name)) {
                                if (!js_hash_name.isValid()) promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The hash must have a 'name' string"));
                                else promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The hash does not match the key"));
                                return;
                            }
                        }

                        JSV js_salt = {};
                        BYTEBUFFER a_salt;
                        if (ReadObjectProperty(ctx, js_algorithm, "salt", js_salt) && js_salt.isValid()) {
                            if (!ReadJSValueAsArrayBuffer(ctx, js_salt, a_salt)) {
                                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] PBKDF2 salt must be a binary value (ArrayBuffer/Uint8Array)"));
                                return;
                            }
                        }

                        JSV js_iterations = {};
                        uint64_t a_iterations = 0;
                        if (ReadObjectProperty(ctx, js_algorithm, "iterations", js_iterations) && js_iterations.isValid()) {
                            if (!ReadJSValueAsUint64(ctx, js_iterations, a_iterations) || a_iterations == 0) {
                                if (a_iterations == 0) promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] PBKDF2 iterations must be greater than 0"));
                                else promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] PBKDF2 iterations must be a positive integer"));
                                return;
                            }
                        }

                        JSV js_length = {};
                        uint64_t a_length = 0;
                        bool has_length = ReadObjectProperty(ctx, js_algorithm, "length", js_length);
                        if (has_length) {
                            if (!ReadJSValueAsUint64(ctx, js_length, a_length) || a_length == 0 || a_length % 8 != 0) {
                                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] PBKDF2 length must be a positive multiple of 8 bits"));
                                return;
                            }
                        }

                        if (keyBinary.empty() || keyBinary.size() * 8 % 8 != 0) {
                            promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] PBKDF2 key length must be a non-empty multiple of 8 bits"));
                            return;
                        }
                    }
                    else if (a_name.find("AES") != std::string::npos) {
                        JSV js_a_length = {};
                        uint64_t a_length = 0;
                        bool hasLength = ReadObjectProperty(ctx, js_algorithm, "length", js_a_length) && ReadJSValueAsUint64(ctx, js_a_length, a_length);

                        if (hasLength) {
                            if (a_length < 128 || a_length > 512 || a_length % 8 != 0) {
                                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] AES key length must be 128-512 bits and multiple of 8"));
                                return;
                            }
                            if (!IsAESMatched(&keyBinary, a_length)) {
                                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The length does not match the key"));
                                return;
                            }
                        }
                        else {
                            a_length = keyBinary.size() * 8;
                            SetAttribute(ctx, js_algorithm, "length", NewUint64(ctx, a_length), 0);
                        }
                    }
                    else if (a_name == "ChaCha20-Poly1305") {
                        if (keyBinary.size() * 8 < 128 || keyBinary.size() * 8 > 256 || keyBinary.size() * 8 % 8 != 0) {
                            promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] ChaCha20-Poly1305 key length must be 128-256 bits and multiple of 8"));
                            return;
                        }
                    }
                    else {
                        promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The algorithm does not match the key"));
                        return;
                    }

                    JSV returnValue = NewObject(ctx);
                    SetSymbolName(ctx, returnValue, "CryptoKey");
                    SetAttribute(ctx, returnValue, "type", "secret", 0);
                    SetAttribute(ctx, returnValue, "algorithm", js_algorithm, 0);
                    SetAttribute(ctx, returnValue, "extractable", js_extractable, 0);
                    SetAttribute(ctx, returnValue, "usages", js_keyUsages, 0);

                    JSV privateObject = NewObject(ctx);
                    JSV data = NewUint8Array(ctx, keyBinary);
                    SetAttribute(ctx, privateObject, "data", data, 0);
                    SetAttribute(ctx, privateObject, "_isPrivate", NewBool(ctx, true), 0);
                    SetAttribute(ctx, returnValue, "internal", privateObject, 0);

                    promise.Resolve(ctx, returnValue);

                }

                return;
                });
            Thread td = std::move(t);
            td.detach();
            jsmdPtr->threadList.push_back(td);
            update(ctx);

            return promise.promise.get(1);
        }
        static JSValue crypto_subtle_generateKey(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            Promise promise = NewPromise(ctx);

            if (argumentCount != 3) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.generateKey] Only 3 arguments are supported: (algorithm, extractable, keyUsages)"));
                return promise.promise.get(1);
            }

            JSValue jsAlgorithm = argumentValues[0];
            JSV uAlgorithm = JSV(ctx, &jsAlgorithm).cget(1).cset(1);
            if (!JS_IsObject(jsAlgorithm)) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.generateKey] The first argument must be a object"));
                return promise.promise.get(1);
            }

            JSValue jsExtractable = argumentValues[1];
            JSV uExtractable = JSV(ctx, &jsExtractable).cget(1).cset(1);
            if (!JS_IsBool(jsExtractable)) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.generateKey] The second argument must be a boolean"));
                return promise.promise.get(1);
            }

            JSValue jsKeyUsages = argumentValues[2];
            JSV uKeyUsages = JSV(ctx, &jsKeyUsages).cget(1).cset(1);

            std::vector<JSV> jkeyUsages = {};
            if (!JS_IsArray(jsKeyUsages) || !ReadJSValueAsArray(ctx, uKeyUsages, jkeyUsages)) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.generateKey] The third argument must be an array"));
                return promise.promise.get(1);
            }

            JSV js_a_name;
            std::string a_name = "";
            if (!ReadObjectProperty(ctx, uAlgorithm, "name", js_a_name) || !ReadJSValueAsString(ctx, js_a_name, a_name)) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.generateKey] The algorithm must have the 'name' property"));
                return promise.promise.get(1);
            }

            if (!allowedKeyUsagesList.count(a_name)) {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.generateKey] The algorithm name is not supported"));
                return promise.promise.get(1);
            }

            std::vector<std::string> invalidAlgorithmList = {};
            ForEach(ctx, uAlgorithm, [&](JSV& key, JSV& value) {
                std::string cKey = "";
                if (!ReadJSValueAsString(ctx, key, cKey)) return;
                if (!allowedGenerateAlgorithm[a_name].count(cKey)) {
                    invalidAlgorithmList.push_back(cKey);
                }
                });
            for (std::string key : invalidAlgorithmList) {
                RemoveAttribute(ctx, jsAlgorithm, key);
            }

            std::vector<std::string> keyUsages = {};
            for (JSV& jsv : jkeyUsages) {
                std::string usage = "";
                if (!JS_IsString(jsv.get()) || !ReadJSValueAsString(ctx, jsv, usage)) {
                    promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.generateKey] The third argument must be all items of string array type"));
                    return promise.promise.get(1);
                }
                if (!allowedKeyUsagesList[a_name].count(usage)) {
                    promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.generateKey] Invalid keyUsages argument '" + usage + "'"));
                    return promise.promise.get(1);
                }
                keyUsages.push_back(usage);
            }

            if (keyUsages.empty()) {
                promise.Reject(ctx, NewSyntaxError(ctx, "[crypto.subtle.generateKey] Usages cannot be empty when creating a key"));
                return promise.promise.get(1);
            }

            JSMData* jsmdPtr = nullptr;
            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                return JS_EXCEPTION;
            }

            if (a_name == "HMAC") {

                std::unordered_map<std::string, std::string>& allowedThisKeyUsagesList = allowedKeyUsagesList[a_name];
                for (std::string usage : keyUsages) {
                    if (!allowedThisKeyUsagesList.count(usage)) {
                        promise.Reject(ctx, NewString(ctx, "[crypto.subtle.generateKey] The keyUsage '" + usage + "' is not supported in this algorithm"));
                        return promise.promise.get(1);
                    }
                }

                JSV js_a_hash = {};
                if (!ReadObjectProperty(ctx, uAlgorithm, "hash", js_a_hash) || !JS_IsObject(js_a_hash.get())) {
                    promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.generateKey] HMAC algorithm must have a 'hash' object property"));
                    return promise.promise.get(1);
                }

                JSV js_hash_name = {};
                std::string hash_name = "";
                if (!ReadObjectProperty(ctx, js_a_hash, "name", js_hash_name) || !ReadJSValueAsString(ctx, js_hash_name, hash_name)) {
                    promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.generateKey] HMAC hash must have a 'name' string property"));
                    return promise.promise.get(1);
                }

                if (hash_name != "SHA-1" && hash_name != "SHA-224" && hash_name != "SHA-256" && hash_name != "SHA-384" && hash_name != "SHA-512" && hash_name != "SHA-3-224" && hash_name != "SHA-3-256" && hash_name != "SHA-3-384" && hash_name != "SHA-3-512" && hash_name != "SHA-512/224" && hash_name != "SHA-512/256") {
                    promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.generateKey] Unsupported HMAC hash algorithm : " + hash_name));
                    return promise.promise.get(1);
                }

                JSV js_a_length = {};
                uint64_t a_length = 0;
                if (ReadObjectProperty(ctx, uAlgorithm, "length", js_a_length)) {
                    uint64_t a_length_temp = 0;
                    if (!ReadJSValueAsUint64(ctx, js_a_length, a_length_temp) || a_length_temp == 0) {
                        promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.generateKey] The key length must be an positive integer"));
                        return promise.promise.get(1);
                    }
                    if (a_length_temp % 8 != 0 || a_length_temp < 8 || a_length_temp > 4096) {
                        promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.generateKey] HMAC key length must be a multiple of 8 bits and between 8 and 4096 bits"));
                        return promise.promise.get(1);
                    }
                    a_length = a_length_temp / 8;
                }

                if (a_length == 0) {
                    if (hash_name == "SHA-1") a_length = 20;
                    else if (hash_name == "SHA-224") a_length = 28;
                    else if (hash_name == "SHA-256") a_length = 32U;
                    else if (hash_name == "SHA-384") a_length = 48;
                    else if (hash_name == "SHA-512") a_length = 32U;
                    else if (hash_name == "SHA-3-224") a_length = 28U;
                    else if (hash_name == "SHA-3-256") a_length = 32U;
                    else if (hash_name == "SHA-3-384") a_length = 48U;
                    else if (hash_name == "SHA-3-512") a_length = 64U;
                    else if (hash_name == "SHA-512/224") a_length = 28U;
                    else if (hash_name == "SHA-512/256") a_length = 32U;
                }

                std::thread t([=]() {

                    BYTEBUFFER keyBinary = {};
                    if (!crypto_subtle_generateKey_HMAC(hash_name, a_length * 8, &keyBinary)) {
                        promise.Reject(ctx, NewInternalError(ctx, "[crypto.subtle.generateKey] Failed to generate key"));
                        return;
                    }

                    JSV returnValue = NewObject(ctx);
                    SetSymbolName(ctx, returnValue, "CryptoKey");
                    SetAttribute(ctx, returnValue, "type", "secret", 0);
                    SetAttribute(ctx, returnValue, "algorithm", uAlgorithm, 0);
                    SetAttribute(ctx, returnValue, "extractable", uExtractable, 0);
                    SetAttribute(ctx, returnValue, "usages", uKeyUsages, 0);

                    JSV privateObject = NewObject(ctx);
                    JSV data = NewUint8Array(ctx, keyBinary);
                    SetAttribute(ctx, privateObject, "data", data, 0);
                    SetAttribute(ctx, privateObject, "_isPrivate", NewBool(ctx, true), 0);
                    SetAttribute(ctx, returnValue, "internal", privateObject, 0);

                    promise.Resolve(ctx, returnValue);

                    });
                Thread td = std::move(t);
                td.detach();
                jsmdPtr->threadList.push_back(td);
                update(ctx);

            }
            else if (a_name == "AES-GCM" || a_name == "AES-CBC" || a_name == "AES-CTR" || a_name == "AES-KW") {

                JSV js_a_length = {};
                uint64_t a_length = 0;
                if (!ReadObjectProperty(ctx, uAlgorithm, "length", js_a_length) || !ReadJSValueAsUint64(ctx, js_a_length, a_length)) {
                    promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.generateKey] The key length must be an positive integer"));
                    return promise.promise.get(1);
                }

                if (a_length % 8 != 0 || a_length < 128 || a_length > 512) {
                    promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.generateKey] AES key length must be a multiple of 8 bits and between 128 and 512 bits"));
                    return promise.promise.get(1);
                }

                std::thread t([=]() {

                    BYTEBUFFER keyBinary = {};
                    if (!crypto_subtle_generateKey_AES(a_length, a_name.substr(4), &keyBinary)) {
                        promise.Reject(ctx, NewInternalError(ctx, "[crypto.subtle.generateKey] Failed to generate key"));
                        return;
                    }


                    JSV returnValue = NewObject(ctx);
                    SetSymbolName(ctx, returnValue, "CryptoKey");
                    SetAttribute(ctx, returnValue, "type", "secret", 0);
                    SetAttribute(ctx, returnValue, "algorithm", uAlgorithm, 0);
                    SetAttribute(ctx, returnValue, "extractable", uExtractable, 0);
                    SetAttribute(ctx, returnValue, "usages", uKeyUsages, 0);

                    JSV privateObject = NewObject(ctx);
                    JSV data = NewUint8Array(ctx, keyBinary);
                    SetAttribute(ctx, privateObject, "data", data, 0);
                    SetAttribute(ctx, privateObject, "_isPrivate", NewBool(ctx, true), 0);
                    SetAttribute(ctx, returnValue, "internal", privateObject, 0);

                    promise.Resolve(ctx, returnValue);

                    });
                Thread td = std::move(t);
                td.detach();
                jsmdPtr->threadList.push_back(td);
                update(ctx);

            }
            else if (a_name == "ChaCha20-Poly1305") {

                JSV js_a_length = {};
                uint64_t a_length = 256;
                if (ReadObjectProperty(ctx, uAlgorithm, "length", js_a_length)) {
                    if (!ReadJSValueAsUint64(ctx, js_a_length, a_length) || a_length % 8 != 0 || a_length < 128 || a_length > 256) {
                        promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.generateKey] ChaCha20-Poly1305 key length must be a multiple of 8 bits and between 128 and 256 bits"));
                        return promise.promise.get(1);
                    }
                }

                std::thread t([=]() {

                    BYTEBUFFER keyBinary = {};
                    if (!crypto_subtle_generateKey_ChaCha20Poly1305(&keyBinary)) {
                        promise.Reject(ctx, NewInternalError(ctx, "[crypto.subtle.generateKey] Failed to generate key"));
                        return;
                    }

                    JSV returnValue = NewObject(ctx);
                    SetSymbolName(ctx, returnValue, "CryptoKey");
                    SetAttribute(ctx, returnValue, "type", "secret", 0);
                    SetAttribute(ctx, returnValue, "algorithm", uAlgorithm, 0);
                    SetAttribute(ctx, returnValue, "extractable", uExtractable, 0);
                    SetAttribute(ctx, returnValue, "usages", uKeyUsages, 0);

                    JSV privateObject = NewObject(ctx);
                    JSV data = NewUint8Array(ctx, keyBinary);
                    SetAttribute(ctx, privateObject, "data", data, 0);
                    SetAttribute(ctx, privateObject, "_isPrivate", NewBool(ctx, true), 0);
                    SetAttribute(ctx, returnValue, "internal", privateObject, 0);

                    promise.Resolve(ctx, returnValue);

                    });
                Thread td = std::move(t);
                td.detach();
                jsmdPtr->threadList.push_back(td);
                update(ctx);
            }
            else if (a_name == "RSA-PSS" || a_name == "RSA-OAEP" || a_name == "RSASSA-PKCS1-v1_5") {

                JSV js_a_modulusLength = {};
                uint64_t a_modulusLength = 0;
                if (!ReadObjectProperty(ctx, uAlgorithm, "modulusLength", js_a_modulusLength) || !ReadJSValueAsUint64(ctx, js_a_modulusLength, a_modulusLength)) {
                    if (!js_a_modulusLength.isValid())
                        promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.generateKey] RSA algorithm must have 'modulusLength' property"));
                    if (js_a_modulusLength.isValid())
                        promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.generateKey] RSA modulus length must be an positive integer"));
                    return promise.promise.get(1);
                }
                if (a_modulusLength % 8 != 0 || a_modulusLength < 1024 || a_modulusLength > 16384) {
                    promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.generateKey] RSA modulus length must be a multiple of 8 bits and between 1024 and 16384 bits"));
                    return promise.promise.get(1);
                }

                JSV js_a_publicExponent = {};
                BYTEBUFFER a_publicExponentBinary = {};
                if (!ReadObjectProperty(ctx, uAlgorithm, "publicExponent", js_a_publicExponent) || !ReadJSValueAsUint8Array(ctx, js_a_publicExponent, a_publicExponentBinary)) {
                    promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.generateKey] RSA public exponent must be a Uint8Array"));
                    return promise.promise.get(1);
                }
                if (a_publicExponentBinary.empty()) {
                    promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.generateKey] RSA public exponent cannot be empty"));
                    return promise.promise.get(1);
                }

                uint64_t a_publicExponent = 0;
                for (unsigned char byte : a_publicExponentBinary) {
                    if (a_publicExponent > (UINT64_MAX >> 8)) {
                        promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.generateKey] RSA public exponent is too large (exceeds 64 bits)"));
                        return promise.promise.get(1);
                    }
                    a_publicExponent = (a_publicExponent << 8) | byte;
                }
                if (a_publicExponent <= 1 || (a_publicExponent % 2) == 0) {
                    promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.generateKey] RSA public exponent must be odd and >1"));
                    return promise.promise.get(1);
                }

                JSV js_a_hash = {};
                JSV js_hash_name = {};
                std::string a_hash_name = "";
                if (!ReadObjectProperty(ctx, uAlgorithm, "hash", js_a_hash) || !ReadObjectProperty(ctx, js_a_hash, "name", js_hash_name) || !ReadJSValueAsString(ctx, js_hash_name, a_hash_name)) {
                    if (!js_a_hash.isValid())
                        promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.generateKey] RSA algorithm must have 'hash' property"));
                    else if (!js_hash_name.isValid())
                        promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.generateKey] RSA hash must have 'name' property"));
                    else if (a_hash_name == "")
                        promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.generateKey] RSA hash must have a valid 'name' property"));
                    return promise.promise.get(1);
                }
                if (!allowedShaName.count(a_hash_name)) {
                    promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.generateKey] The hash '" + a_hash_name + "' is not supported"));
                    return promise.promise.get(1);
                }

                std::thread t([=]() {

                    BYTEBUFFER publicKeyBinary = {};
                    BYTEBUFFER privateKeyBinary = {};
                    std::string paddingMode = "";
                    if (a_name == "RSA-PSS") paddingMode = "PSS";
                    else if (a_name == "RSA-OAEP") paddingMode = "OAEP";
                    else if (a_name == "RSASSA-PKCS1-v1_5") paddingMode = "PKCS1";

                    if (!crypto_subtle_generateKey_RSA(a_modulusLength, a_publicExponent, paddingMode, a_hash_name, &publicKeyBinary, &privateKeyBinary)) {
                        promise.Reject(ctx, NewInternalError(ctx, "[crypto.subtle.generateKey] Failed to generate key"));
                        return;
                    }

                    JSV returnValue = NewObject(ctx);
                    JSV publicKey = NewObject(ctx);
                    JSV privateKey = NewObject(ctx);

                    SetSymbolName(ctx, publicKey, "CryptoKey");
                    SetSymbolName(ctx, privateKey, "CryptoKey");

                    SetAttribute(ctx, returnValue, "publicKey", publicKey);
                    SetAttribute(ctx, returnValue, "privateKey", privateKey);

                    SetAttribute(ctx, publicKey, "type", "public", 0);
                    SetAttribute(ctx, publicKey, "algorithm", uAlgorithm, 0);
                    SetAttribute(ctx, publicKey, "extractable", uExtractable, 0);

                    SetAttribute(ctx, privateKey, "type", "private", 0);
                    SetAttribute(ctx, privateKey, "algorithm", uAlgorithm, 0);
                    SetAttribute(ctx, privateKey, "extractable", uExtractable, 0);

                    std::vector<JSV> publicKeyUsages = {};
                    std::vector<JSV> privateKeyUsages = {};
                    for (const std::string& usage : keyUsages) {
                        if (a_name == "RSA-OAEP") {
                            if (usage == "encrypt" || usage == "wrapKey") {
                                publicKeyUsages.push_back(NewString(ctx, usage));
                            }
                            else if (usage == "decrypt" || usage == "unwrapKey") {
                                privateKeyUsages.push_back(NewString(ctx, usage));
                            }
                        }
                        else if (a_name == "RSA-PSS" || a_name == "RSASSA-PKCS1-v1_5") {
                            if (usage == "verify") {
                                publicKeyUsages.push_back(NewString(ctx, usage));
                            }
                            else if (usage == "sign") {
                                privateKeyUsages.push_back(NewString(ctx, usage));
                            }
                        }
                    }

                    JSV uPublicKeyUsages = NewArray(ctx, publicKeyUsages);
                    JSV uPrivateKeyUsages = NewArray(ctx, privateKeyUsages);

                    SetAttribute(ctx, publicKey, "usages", uPublicKeyUsages, 0);
                    SetAttribute(ctx, privateKey, "usages", uPrivateKeyUsages, 0);

                    JSV publicKeyPrivateObject = NewObject(ctx);
                    JSV publicData = NewUint8Array(ctx, publicKeyBinary);
                    SetAttribute(ctx, publicKeyPrivateObject, "data", publicData, 0);
                    SetAttribute(ctx, publicKeyPrivateObject, "_isPrivate", NewBool(ctx, true), 0);
                    SetAttribute(ctx, publicKey, "internal", publicKeyPrivateObject, 0);

                    JSV privateKeyPrivateObject = NewObject(ctx);
                    JSV privateData = NewUint8Array(ctx, privateKeyBinary);
                    SetAttribute(ctx, privateKeyPrivateObject, "data", privateData, 0);
                    SetAttribute(ctx, privateKeyPrivateObject, "_isPrivate", NewBool(ctx, true), 0);
                    SetAttribute(ctx, privateKey, "internal", privateKeyPrivateObject, 0);

                    promise.Resolve(ctx, returnValue);

                    });
                Thread td = std::move(t);
                td.detach();
                jsmdPtr->threadList.push_back(td);
                update(ctx);

            }
            else if (a_name == "ECDSA" || a_name == "ECDH") {

                JSV js_a_namedCurve = {};
                std::string a_namedCurve = "";
                if (!ReadObjectProperty(ctx, uAlgorithm, "namedCurve", js_a_namedCurve) || !ReadJSValueAsString(ctx, js_a_namedCurve, a_namedCurve)) {
                    if (!js_a_namedCurve.isValid())
                        promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.generateKey] EC algorithm must have 'namedCurve' property"));
                    if (js_a_namedCurve.isValid())
                        promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.generateKey] EC modulus name curve must be an valid string"));
                    return promise.promise.get(1);
                }
                if (!allowedCurveName.count(a_namedCurve)) {
                    promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.generateKey] The namedCurve '" + a_namedCurve + "' is not supported"));
                    return promise.promise.get(1);
                }

                std::string a_hash_name = "SHA-256";
                if (a_name == "ECDSA") {
                    JSV js_a_hash = {};
                    if (ReadObjectProperty(ctx, uAlgorithm, "hash", js_a_hash)) {
                        JSV js_hash_name = {};
                        if (!ReadObjectProperty(ctx, js_a_hash, "name", js_hash_name) || !ReadJSValueAsString(ctx, js_hash_name, a_hash_name)) {
                            promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.generateKey] ECDSA hash must have a valid 'name' string property"));
                            return promise.promise.get(1);
                        }
                        if (!allowedShaName.count(a_hash_name)) {
                            promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.generateKey] The hash '" + a_hash_name + "' is not supported"));
                            return promise.promise.get(1);
                        }
                    }
                }

                std::thread t([=]() {

                    BYTEBUFFER publicKeyBinary = {};
                    BYTEBUFFER privateKeyBinary = {};
                    if (!crypto_subtle_generateKey_EC(a_name, a_namedCurve, a_hash_name, &publicKeyBinary, &privateKeyBinary)) {
                        promise.Reject(ctx, NewInternalError(ctx, "[crypto.subtle.generateKey] Failed to generate key"));
                        return;
                    }

                    JSV returnValue = NewObject(ctx);
                    JSV publicKey = NewObject(ctx);
                    JSV privateKey = NewObject(ctx);

                    SetSymbolName(ctx, publicKey, "CryptoKey");
                    SetSymbolName(ctx, privateKey, "CryptoKey");

                    SetAttribute(ctx, returnValue, "publicKey", publicKey);
                    SetAttribute(ctx, returnValue, "privateKey", privateKey);

                    SetAttribute(ctx, publicKey, "type", "public", 0);
                    SetAttribute(ctx, publicKey, "algorithm", uAlgorithm, 0);
                    SetAttribute(ctx, publicKey, "extractable", uExtractable, 0);

                    SetAttribute(ctx, privateKey, "type", "private", 0);
                    SetAttribute(ctx, privateKey, "algorithm", uAlgorithm, 0);
                    SetAttribute(ctx, privateKey, "extractable", uExtractable, 0);

                    std::vector<JSV> publicKeyUsages = {};
                    std::vector<JSV> privateKeyUsages = {};
                    for (const std::string& usage : keyUsages) {
                        if (a_name == "ECDH") {
                            privateKeyUsages.push_back(NewString(ctx, usage));
                        }
                        else if (a_name == "ECDSA") {
                            if (usage == "verify") {
                                publicKeyUsages.push_back(NewString(ctx, usage));
                            }
                            else if (usage == "sign") {
                                privateKeyUsages.push_back(NewString(ctx, usage));
                            }
                        }
                    }

                    JSV uPublicKeyUsages = NewArray(ctx, publicKeyUsages);
                    JSV uPrivateKeyUsages = NewArray(ctx, privateKeyUsages);

                    SetAttribute(ctx, publicKey, "usages", uPublicKeyUsages, 0);
                    SetAttribute(ctx, privateKey, "usages", uPrivateKeyUsages, 0);

                    JSV publicKeyPrivateObject = NewObject(ctx);
                    JSV publicData = NewUint8Array(ctx, publicKeyBinary);
                    SetAttribute(ctx, publicKeyPrivateObject, "data", publicData, 0);
                    SetAttribute(ctx, publicKeyPrivateObject, "_isPrivate", NewBool(ctx, true), 0);
                    SetAttribute(ctx, publicKey, "internal", publicKeyPrivateObject, 0);

                    JSV privateKeyPrivateObject = NewObject(ctx);
                    JSV privateData = NewUint8Array(ctx, privateKeyBinary);
                    SetAttribute(ctx, privateKeyPrivateObject, "data", privateData, 0);
                    SetAttribute(ctx, privateKeyPrivateObject, "_isPrivate", NewBool(ctx, true), 0);
                    SetAttribute(ctx, privateKey, "internal", privateKeyPrivateObject, 0);

                    promise.Resolve(ctx, returnValue);

                    });
                Thread td = std::move(t);
                td.detach();
                jsmdPtr->threadList.push_back(td);
                update(ctx);

            }
            else if (a_name == "Ed25519") {

                std::thread t([=]() {

                    BYTEBUFFER publicKeyBinary = {};
                    BYTEBUFFER privateKeyBinary = {};
                    if (!crypto_subtle_generateKey_Ed25519(&publicKeyBinary, &privateKeyBinary)) {
                        promise.Reject(ctx, NewInternalError(ctx, "[crypto.subtle.generateKey] Failed to generate key"));
                        return;
                    }

                    JSV returnValue = NewObject(ctx);
                    JSV publicKey = NewObject(ctx);
                    JSV privateKey = NewObject(ctx);

                    SetSymbolName(ctx, publicKey, "CryptoKey");
                    SetSymbolName(ctx, privateKey, "CryptoKey");

                    SetAttribute(ctx, returnValue, "publicKey", publicKey);
                    SetAttribute(ctx, returnValue, "privateKey", privateKey);

                    SetAttribute(ctx, publicKey, "type", "public", 0);
                    SetAttribute(ctx, publicKey, "algorithm", uAlgorithm, 0);
                    SetAttribute(ctx, publicKey, "extractable", uExtractable, 0);

                    SetAttribute(ctx, privateKey, "type", "private", 0);
                    SetAttribute(ctx, privateKey, "algorithm", uAlgorithm, 0);
                    SetAttribute(ctx, privateKey, "extractable", uExtractable, 0);

                    std::vector<JSV> publicKeyUsages = {};
                    std::vector<JSV> privateKeyUsages = {};
                    for (const std::string& usage : keyUsages) {
                        if (usage == "verify") {
                            publicKeyUsages.push_back(NewString(ctx, usage));
                        }
                        else if (usage == "sign") {
                            privateKeyUsages.push_back(NewString(ctx, usage));
                        }
                    }

                    JSV uPublicKeyUsages = NewArray(ctx, publicKeyUsages);
                    JSV uPrivateKeyUsages = NewArray(ctx, privateKeyUsages);

                    SetAttribute(ctx, publicKey, "usages", uPublicKeyUsages, 0);
                    SetAttribute(ctx, privateKey, "usages", uPrivateKeyUsages, 0);

                    JSV publicKeyPrivateObject = NewObject(ctx);
                    JSV publicData = NewUint8Array(ctx, publicKeyBinary);
                    SetAttribute(ctx, publicKeyPrivateObject, "data", publicData, 0);
                    SetAttribute(ctx, publicKeyPrivateObject, "_isPrivate", NewBool(ctx, true), 0);
                    SetAttribute(ctx, publicKey, "internal", publicKeyPrivateObject, 0);

                    JSV privateKeyPrivateObject = NewObject(ctx);
                    JSV privateData = NewUint8Array(ctx, privateKeyBinary);
                    SetAttribute(ctx, privateKeyPrivateObject, "data", privateData, 0);
                    SetAttribute(ctx, privateKeyPrivateObject, "_isPrivate", NewBool(ctx, true), 0);
                    SetAttribute(ctx, privateKey, "internal", privateKeyPrivateObject, 0);

                    promise.Resolve(ctx, returnValue);

                    });
                Thread td = std::move(t);
                td.detach();
                jsmdPtr->threadList.push_back(td);
                update(ctx);

            }
            else if (a_name == "X25519") {

                std::thread t([=]() {

                    BYTEBUFFER publicKeyBinary = {};
                    BYTEBUFFER privateKeyBinary = {};
                    if (!crypto_subtle_generateKey_X25519(&publicKeyBinary, &privateKeyBinary)) {
                        promise.Reject(ctx, NewInternalError(ctx, "[crypto.subtle.generateKey] Failed to generate key"));
                        return;
                    }

                    JSV returnValue = NewObject(ctx);
                    JSV publicKey = NewObject(ctx);
                    JSV privateKey = NewObject(ctx);

                    SetSymbolName(ctx, publicKey, "CryptoKey");
                    SetSymbolName(ctx, privateKey, "CryptoKey");

                    SetAttribute(ctx, returnValue, "publicKey", publicKey);
                    SetAttribute(ctx, returnValue, "privateKey", privateKey);

                    SetAttribute(ctx, publicKey, "type", "public", 0);
                    SetAttribute(ctx, publicKey, "algorithm", uAlgorithm, 0);
                    SetAttribute(ctx, publicKey, "extractable", uExtractable, 0);

                    SetAttribute(ctx, privateKey, "type", "private", 0);
                    SetAttribute(ctx, privateKey, "algorithm", uAlgorithm, 0);
                    SetAttribute(ctx, privateKey, "extractable", uExtractable, 0);

                    SetAttribute(ctx, publicKey, "usages", NewArray(ctx, {}), 0);
                    SetAttribute(ctx, privateKey, "usages", uKeyUsages, 0);

                    JSV publicKeyPrivateObject = NewObject(ctx);
                    JSV publicData = NewUint8Array(ctx, publicKeyBinary);
                    SetAttribute(ctx, publicKeyPrivateObject, "data", publicData, 0);
                    SetAttribute(ctx, publicKeyPrivateObject, "_isPrivate", NewBool(ctx, true), 0);
                    SetAttribute(ctx, publicKey, "internal", publicKeyPrivateObject, 0);

                    JSV privateKeyPrivateObject = NewObject(ctx);
                    JSV privateData = NewUint8Array(ctx, privateKeyBinary);
                    SetAttribute(ctx, privateKeyPrivateObject, "data", privateData, 0);
                    SetAttribute(ctx, privateKeyPrivateObject, "_isPrivate", NewBool(ctx, true), 0);
                    SetAttribute(ctx, privateKey, "internal", privateKeyPrivateObject, 0);

                    promise.Resolve(ctx, returnValue);

                    });
                Thread td = std::move(t);
                td.detach();
                jsmdPtr->threadList.push_back(td);
                update(ctx);

            }
            else {
                promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.generateKey] The algorithm name '" + a_name + "' is not supported"));
                return promise.promise.get(1);
            }
            return promise.promise.get(1);
        }

        static JSValue console_restore(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            JSV js_title = (argumentCount >= 1) ? JSV(ctx, argumentValues[0]) : NewString(ctx, wstringToString(L"CGI.JS - r" + AY_CJS_CPP_VW + L""));
            std::string title = "";
            ReadJSValueAsString(ctx, js_title, title);
            if (mode == "file" && console == NULL) CreateConsole(stringToWstring(title));
            return JS_UNDEFINED;
        }
        static JSValue console_kill(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            if (mode == "file") CloseConsole();
            return JS_UNDEFINED;
        }
        static JSValue console_hide(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            if (console != NULL) {
                SetWindowLongPtrW(console, GWL_EXSTYLE, GetWindowLongPtrW(console, GWL_EXSTYLE) | WS_EX_TOOLWINDOW);
                ShowWindow(console, SW_HIDE);
                UpdateWindow(console);
            }
            return JS_UNDEFINED;
        }
        static JSValue console_show(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            if (console != NULL) {
                SetWindowLongPtrW(console, GWL_EXSTYLE, GetWindowLongPtrW(console, GWL_EXSTYLE) & ~WS_EX_TOOLWINDOW);
                ShowWindow(console, SW_RESTORE);
                UpdateWindow(console);
                SetForegroundWindow(console);
            }
            return JS_UNDEFINED;
        }
        static JSValue console_pause(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            isPaused = true;
            return JS_UNDEFINED;
        }
        static JSValue console_resume(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            isPaused = false;
            return JS_UNDEFINED;
        }
        static JSValue console_log(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            const uint32_t JS_GPN_ALL = JS_GPN_STRING_MASK | JS_GPN_SYMBOL_MASK | JS_GPN_SET_ENUM;
            std::unordered_set<uint64_t> visited_objs;

            JSAtom atom_toStringTag = JS_NewAtom(ctx, "Symbol.toStringTag");
            JSAtom atom_name = JS_NewAtom(ctx, "name");
            JSAtom atom_toString = JS_NewAtom(ctx, "toString");
            JSAtom atom_length = JS_NewAtom(ctx, "length");
            JSAtom atom_buffer = JS_NewAtom(ctx, "buffer");
            JSAtom atom_byteOffset = JS_NewAtom(ctx, "byteOffset");
            JSAtom atom_state = JS_NewAtom(ctx, "state");
            JSAtom atom__isPrivate = JS_NewAtom(ctx, "_isPrivate");
            JSAtom atom_byteLength = JS_NewAtom(ctx, "byteLength");
            JSAtom atom_toLocaleString = JS_NewAtom(ctx, "toLocaleString");
            JSAtom atom_constructor = JS_NewAtom(ctx, "constructor");
            JSAtom atom_prototype = JS_NewAtom(ctx, "prototype");
            JSAtom atom_internal = JS_NewAtom(ctx, "internal");
            JSAtom atom_id = JS_NewAtom(ctx, "id");

            auto get_color_value = [&](const std::wstring& color_key) -> const std::wstring& {
                auto it = TextLightColorValue.find(color_key);
                if (it != TextLightColorValue.end()) return it->second;
                static std::wstring default_color = TextLightColorValue[L"Default"];
                return default_color;
                };

            auto js_val_to_string = [&](JSValueConst val) -> std::string {
                if (JS_IsUndefined(val) || JS_IsNull(val) || JS_IsException(val)) return "";
                JSValue str_val = JS_ToString(ctx, val);
                if (JS_IsException(str_val)) {
                    JS_FreeValue(ctx, str_val);
                    return "";
                }
                std::string result;
                const char* cstr = JS_ToCString(ctx, str_val);
                if (cstr) {
                    result = cstr;
                    JS_FreeCString(ctx, cstr);
                }
                JS_FreeValue(ctx, str_val);
                return result;
                };

            auto get_to_string_tag = [&](JSValueConst val) -> std::string {
                if (atom_toStringTag != JS_ATOM_NULL) {
                    JSValue tag_val = JS_GetProperty(ctx, val, atom_toStringTag);
                    if (!JS_IsUndefined(tag_val) && !JS_IsNull(tag_val) && !JS_IsException(tag_val)) {
                        std::string tag_str = js_val_to_string(tag_val);
                        if (!tag_str.empty()) {
                            JS_FreeValue(ctx, tag_val);
                            return tag_str;
                        }
                    }
                    JS_FreeValue(ctx, tag_val);
                }

                if (JS_IsObject(val)) {
                    JSValue length_val = JS_GetProperty(ctx, val, atom_length);
                    bool has_valid_length = !JS_IsUndefined(length_val) && !JS_IsNull(length_val) && !JS_IsException(length_val);
                    JS_FreeValue(ctx, length_val);

                    if (has_valid_length) {
                        JSValue constructor_val = JS_GetProperty(ctx, val, atom_constructor);
                        if (!JS_IsUndefined(constructor_val) && !JS_IsNull(constructor_val) && !JS_IsException(constructor_val)) {
                            JSValue name_val = JS_GetProperty(ctx, constructor_val, atom_name);
                            std::string constructor_name = js_val_to_string(name_val);
                            if (constructor_name == "Array") {
                                JS_FreeValue(ctx, name_val);
                                JS_FreeValue(ctx, constructor_val);
                                return constructor_name;
                            }
                            JS_FreeValue(ctx, name_val);
                        }
                        JS_FreeValue(ctx, constructor_val);

                        JSValue array_js_str = JS_NewString(ctx, "Array");
                        if (!JS_IsException(array_js_str)) {
                            std::string array_cstr = js_val_to_string(array_js_str);
                            if (!array_cstr.empty()) {
                                JSValue proto_val = JS_GetProperty(ctx, val, atom_prototype);
                                JSValue proto_name_val = JS_GetProperty(ctx, proto_val, atom_name);
                                std::string proto_name = js_val_to_string(proto_name_val);
                                bool is_real_array = (proto_name == "Array");
                                JS_FreeValue(ctx, proto_name_val);
                                JS_FreeValue(ctx, proto_val);
                                if (is_real_array) return array_cstr;
                            }
                            JS_FreeValue(ctx, array_js_str);
                        }
                    }

                    JSValue buffer_val = JS_GetProperty(ctx, val, atom_buffer);
                    JSValue byteOffset_val = JS_GetProperty(ctx, val, atom_byteOffset);
                    JSValue byteLength_val = JS_GetProperty(ctx, val, atom_byteLength);
                    bool is_typed_array = !JS_IsUndefined(buffer_val) && !JS_IsNull(buffer_val)
                        && !JS_IsUndefined(byteOffset_val) && !JS_IsNull(byteOffset_val)
                        && !JS_IsUndefined(byteLength_val) && !JS_IsNull(byteLength_val);
                    JS_FreeValue(ctx, buffer_val);
                    JS_FreeValue(ctx, byteOffset_val);
                    JS_FreeValue(ctx, byteLength_val);

                    if (is_typed_array) {
                        JSValue constructor_val = JS_GetProperty(ctx, val, atom_constructor);
                        if (!JS_IsUndefined(constructor_val) && !JS_IsNull(constructor_val) && !JS_IsException(constructor_val)) {
                            JSValue name_val = JS_GetProperty(ctx, constructor_val, atom_name);
                            std::string constructor_name = js_val_to_string(name_val);
                            if (!constructor_name.empty()) {
                                JS_FreeValue(ctx, name_val);
                                JS_FreeValue(ctx, constructor_val);
                                return constructor_name;
                            }
                            JS_FreeValue(ctx, name_val);
                        }
                        JS_FreeValue(ctx, constructor_val);
                    }
                }

                return GetSymbolName(ctx, val);
                };

            auto get_function_type = [&](JSValueConst val) -> std::wstring {
                if (!JS_IsFunction(ctx, val)) return L"";
                bool is_class = false;
                JSValue name_val = JS_GetProperty(ctx, val, atom_name);
                std::string func_name = js_val_to_string(name_val);
                if (func_name.find("class ") != std::string::npos) is_class = true;
                JS_FreeValue(ctx, name_val);

                if (!is_class) {
                    JSValue to_str_fun = JS_GetProperty(ctx, val, atom_toString);
                    if (!JS_IsUndefined(to_str_fun) && !JS_IsNull(to_str_fun) && !JS_IsException(to_str_fun)) {
                        JSValue str_val = JS_Call(ctx, to_str_fun, val, 0, nullptr);
                        JS_FreeValue(ctx, to_str_fun);
                        if (!JS_IsException(str_val)) {
                            std::string fn_to_str = js_val_to_string(str_val);
                            if (fn_to_str.find("class ") != std::string::npos) is_class = true;
                        }
                        JS_FreeValue(ctx, str_val);
                    }
                    else JS_FreeValue(ctx, to_str_fun);
                }

                if (is_class) return L"Class";
                JSValue to_str_fun = JS_GetProperty(ctx, val, atom_toString);
                std::wstring func_type = L"Function";
                if (!JS_IsUndefined(to_str_fun) && !JS_IsNull(to_str_fun) && !JS_IsException(to_str_fun)) {
                    JSValue str_val = JS_Call(ctx, to_str_fun, val, 0, nullptr);
                    JS_FreeValue(ctx, to_str_fun);
                    if (!JS_IsException(str_val)) {
                        std::string fn_to_str = js_val_to_string(str_val);
                        if (fn_to_str.find("[native code]") != std::string::npos) func_type = L"BuiltInFunction";
                    }
                    JS_FreeValue(ctx, str_val);
                }
                else JS_FreeValue(ctx, to_str_fun);

                JSValue name_val2 = JS_GetProperty(ctx, val, atom_name);
                std::string func_name2 = js_val_to_string(name_val2);
                if (func_name2.find('.') != std::string::npos) func_type = L"Method";
                JS_FreeValue(ctx, name_val2);
                return func_type;
                };

            auto get_indent_str = [&](int indent) -> std::wstring {
                static std::unordered_map<int, std::wstring> indent_cache;
                if (indent <= 0) return L"";
                if (indent_cache.count(indent)) return indent_cache[indent];
                std::wstring indent_str(indent * 2, L' ');
                indent_cache[indent] = indent_str;
                return indent_str;
                };

            auto is_continuous_number_keys = [&](JSPropertyEnum* props, uint32_t prop_cnt) -> bool {
                if (prop_cnt == 0) return false;
                uint32_t max_key = 0;
                std::unordered_set<uint32_t> key_set;
                for (uint32_t i = 0; i < prop_cnt; i++) {
                    std::string prop_name = js_val_to_string(JS_AtomToString(ctx, props[i].atom));
                    if (prop_name.empty()) return false;
                    char* endptr = nullptr;
                    uint32_t num_key = strtoul(prop_name.c_str(), &endptr, 10);
                    if (*endptr != '\0') return false;
                    key_set.insert(num_key);
                    if (num_key > max_key) max_key = num_key;
                }
                return (max_key + 1 == prop_cnt) && (key_set.size() == prop_cnt);
                };

            auto is_private_value = [&](JSValueConst val) -> bool {
                if (!JS_IsObject(val)) return false;
                JSValue private_val = JS_GetProperty(ctx, val, atom__isPrivate);
                bool is_private = false;
                if (!JS_IsException(private_val) && !JS_IsUndefined(private_val) && !JS_IsNull(private_val)) {
                    is_private = JS_ToBool(ctx, private_val);
                }
                JS_FreeValue(ctx, private_val);
                return is_private;
                };

            std::function<void(JSValueConst, int)> print_js_value = [&](JSValueConst val, int indent) -> void {
                if (is_private_value(val)) return;
                std::wstring indent_str = get_indent_str(indent);

                if (JS_IsFunction(ctx, val)) {
                    std::wstring func_type = get_function_type(val);
                    JSValue name_val = JS_GetProperty(ctx, val, atom_name);
                    std::string fn_name = js_val_to_string(name_val);
                    JS_FreeValue(ctx, name_val);

                    JSValue to_str_fun = JS_GetProperty(ctx, val, atom_toString);
                    std::string fn_to_str;
                    if (!JS_IsUndefined(to_str_fun) && !JS_IsNull(to_str_fun) && !JS_IsException(to_str_fun)) {
                        JSValue str_val = JS_Call(ctx, to_str_fun, val, 0, nullptr);
                        JS_FreeValue(ctx, to_str_fun);
                        if (!JS_IsException(str_val)) fn_to_str = js_val_to_string(str_val);
                        JS_FreeValue(ctx, str_val);
                    }
                    else JS_FreeValue(ctx, to_str_fun);

                    std::wstring func_str;
                    if (!fn_to_str.empty()) {
                        func_str = stringToWstring(fn_to_str);
                        std::wstring line_indent = get_indent_str(indent);
                        size_t pos = 0;
                        while ((pos = func_str.find(L'\n', pos)) != std::wstring::npos) {
                            func_str.insert(pos + 1, line_indent);
                            pos += line_indent.length() + 1;
                        }
                    }
                    else {
                        if (func_type == L"Class") func_str = fn_name.empty() ? L"class { [native code] }"
                            : L"class " + stringToWstring(fn_name) + L" { [native code] }";
                        else func_str = fn_name.empty() ? L"function() { [native code] }"
                            : L"function " + stringToWstring(fn_name) + L"() { [native code] }";
                    }
                    CreateOutput(func_str, get_color_value(func_type));
                    return;
                }

                if (JS_IsObject(val) || JS_IsArray(val)) {
                    std::string tag_str = get_to_string_tag(val);
                    std::wstring obj_color_key = L"Object";

                    if (tag_str == "ArrayBuffer") {
                        obj_color_key = L"Array";
                        JSValue byteLength_val = JS_GetProperty(ctx, val, atom_byteLength);
                        uint32_t byte_length = 0;
                        JS_ToUint32(ctx, &byte_length, byteLength_val);
                        JS_FreeValue(ctx, byteLength_val);
                        CreateOutput(L"ArrayBuffer (" + std::to_wstring(byte_length) + L")", get_color_value(obj_color_key));
                        return;
                    }

                    if (tag_str == "Promise") {
                        obj_color_key = L"Promise";
                        CreateOutput(L"Promise {", get_color_value(obj_color_key));
                        CreateOutput(L"\n", get_color_value(obj_color_key));

                        JSMData* jsmdPtr = nullptr;
                        std::wstring state_str = L"pending";
                        std::wstring state_color = get_color_value(L"Info");
                        bool isNeedFree = false;
                        JSValue result_val = JS_UNDEFINED;
                        JSPromiseStateEnum state = JS_PromiseState(ctx, val);
                        if (state == JS_PROMISE_FULFILLED) {
                            state_str = L"fulfilled";
                            state_color = get_color_value(L"Success");
                            result_val = JS_PromiseResult(ctx, val);
                            isNeedFree = true;
                        }
                        else if (state == JS_PROMISE_REJECTED) {
                            state_str = L"rejected";
                            state_color = get_color_value(L"Error");
                            result_val = JS_PromiseResult(ctx, val);
                            isNeedFree = true;
                        }

                        CreateOutput(get_indent_str(indent + 1), get_color_value(obj_color_key));
                        CreateOutput(L"[[PromiseState]]: <", get_color_value(L"Property"));
                        CreateOutput(state_str, state_color);
                        CreateOutput(L">", get_color_value(L"Property"));
                        CreateOutput(L"\n", get_color_value(obj_color_key));

                        CreateOutput(get_indent_str(indent + 1), get_color_value(obj_color_key));
                        CreateOutput(L"[[PromiseResult]]: ", get_color_value(L"Property"));
                        if (!is_private_value(result_val) && !JS_IsException(result_val)) print_js_value(result_val, indent + 1);
                        else if (!is_private_value(result_val)) CreateOutput(L"[invalid]", get_color_value(L"Comment"));

                        CreateOutput(L"\n", get_color_value(obj_color_key));
                        CreateOutput(get_indent_str(indent) + L"}", get_color_value(obj_color_key));

                        if (isNeedFree) JS_FreeValue(ctx, result_val);
                        return;
                    }

                    if (tag_str == "Date") {
                        obj_color_key = L"Date";
                        std::wstring date_str = L"Date ";
                        JSValue locale_str_val = JS_GetProperty(ctx, val, atom_toLocaleString);
                        if (!JS_IsException(locale_str_val) && !JS_IsUndefined(locale_str_val)) {
                            JSValue str_val = JS_Call(ctx, locale_str_val, val, 0, nullptr);
                            JS_FreeValue(ctx, locale_str_val);
                            std::string date_cstr = js_val_to_string(str_val);
                            if (!date_cstr.empty()) date_str += L"[" + stringToWstring(date_cstr) + L"]";
                            else date_str += L"[Invalid Date]";
                            JS_FreeValue(ctx, str_val);
                        }
                        else {
                            JS_FreeValue(ctx, locale_str_val);
                            date_str += L"[Invalid Date]";
                        }
                        CreateOutput(date_str, get_color_value(obj_color_key));
                        return;
                    }

                    if (tag_str == "RegExp") {
                        obj_color_key = L"RegExp";
                        std::string regex_str = js_val_to_string(val);
                        std::wstring regex_wstr = regex_str.empty() ? L"RegExp [invalid]" : stringToWstring(regex_str);
                        CreateOutput(regex_wstr, get_color_value(obj_color_key));
                        return;
                    }

                    if (tag_str == "Array" ||
                        tag_str == "Uint8Array" || tag_str == "Uint16Array" || tag_str == "Uint32Array" ||
                        tag_str == "Int8Array" || tag_str == "Int16Array" || tag_str == "Int32Array" ||
                        tag_str == "Float32Array" || tag_str == "Float64Array") {
                        obj_color_key = L"Array";
                        JSValue length_val = JS_GetProperty(ctx, val, atom_length);
                        uint32_t arr_length = 0;
                        JS_ToUint32(ctx, &arr_length, length_val);
                        JS_FreeValue(ctx, length_val);

                        CreateOutput(stringToWstring(tag_str) + L" [", get_color_value(obj_color_key));
                        for (uint32_t i = 0; i < arr_length; ++i) {
                            JSValue elem_val = JS_GetPropertyUint32(ctx, val, i);
                            if (i > 0) CreateOutput(L", ", get_color_value(obj_color_key));
                            if (!is_private_value(elem_val) && !JS_IsException(elem_val)) print_js_value(elem_val, indent + 1);
                            else if (!is_private_value(elem_val)) CreateOutput(L"[invalid]", get_color_value(L"Comment"));
                            JS_FreeValue(ctx, elem_val);
                        }
                        CreateOutput(L"]", get_color_value(obj_color_key));
                        return;
                    }

                    if (tag_str == "Module") {
                        obj_color_key = L"Module";
                        CreateOutput(indent_str + L"Module { ... }", get_color_value(obj_color_key));
                        return;
                    }
                }

                if (JS_IsString(val)) {
                    std::string str_val = js_val_to_string(val);
                    CreateOutput(L"\"" + stringToWstring(str_val) + L"\"", get_color_value(L"String"));
                }
                else if (JS_IsNumber(val)) {
                    double num = 0.0;
                    if (JS_ToFloat64(ctx, &num, val) == 0) CreateOutput(RemoveSpaceAfterNumber(std::to_wstring(num)), get_color_value(L"Number"));
                    else CreateOutput(L"[invalid number]", get_color_value(L"Comment"));
                }
                else if (JS_IsBigInt(val)) {
                    int64_t bnum_signed = 0;
                    uint64_t bnum_unsigned = 0;
                    if (JS_ToBigInt64(ctx, &bnum_signed, val) == 0) CreateOutput(std::to_wstring(bnum_signed), get_color_value(L"Number"));
                    else if (JS_ToBigUint64(ctx, &bnum_unsigned, val) == 0) CreateOutput(std::to_wstring(bnum_unsigned), get_color_value(L"Number"));
                    else CreateOutput(L"[invalid bigint]", get_color_value(L"Comment"));
                }
                else if (JS_IsBool(val)) {
                    bool b = JS_ToBool(ctx, val);
                    CreateOutput(b ? L"true" : L"false", get_color_value(L"Boolean"));
                }
                else if (JS_IsNull(val)) CreateOutput(L"null", get_color_value(L"NullUndefined"));
                else if (JS_IsUndefined(val)) CreateOutput(L"undefined", get_color_value(L"NullUndefined"));
                else if (JS_IsSymbol(val)) {
                    std::string symbol_str = js_val_to_string(val);
                    CreateOutput(L"Symbol(" + stringToWstring(symbol_str) + L")", get_color_value(L"Symbol"));
                }
                else if (JS_IsObject(val)) {
                    uint64_t obj_id = (uint64_t)JS_VALUE_GET_PTR(val);
                    if (visited_objs.count(obj_id)) {
                        CreateOutput(L"[Circular]", get_color_value(L"Comment"));
                        return;
                    }
                    visited_objs.insert(obj_id);

                    JSValue val_copy = JS_DupValue(ctx, val);
                    std::string proto_name_str = GetPrototypeName(ctx, val_copy);
                    JS_FreeValue(ctx, val_copy);
                    std::wstring obj_type_name = stringToWstring(proto_name_str);

                    std::wstring proto_color_key = L"Type";
                    if (!obj_type_name.empty() && TextLightColorValue.count(obj_type_name)) proto_color_key = obj_type_name;

                    if (!obj_type_name.empty() && obj_type_name != L"Object") CreateOutput(obj_type_name + L" ", get_color_value(proto_color_key));
                    CreateOutput(L"{\n", get_color_value(L"Object"));

                    JSPropertyEnum* props = nullptr;
                    uint32_t prop_cnt = 0;
                    std::vector<JSPropertyEnum> final_valid_props;
                    if (JS_GetOwnPropertyNames(ctx, &props, &prop_cnt, val, JS_GPN_ALL) == 0) {
                        for (uint32_t i = 0; i < prop_cnt; i++) {
                            std::string prop_name = js_val_to_string(JS_AtomToString(ctx, props[i].atom));
                            bool is_private_prop = (prop_name == "_isPrivate");
                            JSValue prop_val = JS_GetProperty(ctx, val, props[i].atom);
                            bool is_private_val = is_private_value(prop_val);
                            if (!is_private_prop && !is_private_val) final_valid_props.push_back(props[i]);
                            JS_FreeValue(ctx, prop_val);
                        }
                        JS_FreePropertyEnum(ctx, props, prop_cnt);
                    }

                    size_t final_prop_size = final_valid_props.size();
                    for (size_t i = 0; i < final_prop_size; i++) {
                        JSAtom prop_atom = final_valid_props[i].atom;
                        std::string prop_name = js_val_to_string(JS_AtomToString(ctx, prop_atom));
                        if (!prop_name.empty()) {
                            CreateOutput(get_indent_str(indent + 1), get_color_value(L"Object"));
                            CreateOutput(stringToWstring(prop_name) + L": ", get_color_value(L"Property"));
                            JSValue prop_val = JS_GetProperty(ctx, val, prop_atom);
                            if (!JS_IsException(prop_val)) print_js_value(prop_val, indent + 1);
                            else CreateOutput(L"[invalid value]", get_color_value(L"Comment"));
                            JS_FreeValue(ctx, prop_val);
                            if (i < final_prop_size - 1) CreateOutput(L",", get_color_value(L"Object"));
                        }
                        CreateOutput(L"\n", get_color_value(L"Object"));
                    }

                    CreateOutput(get_indent_str(indent) + L"}", get_color_value(L"Object"));
                    visited_objs.erase(obj_id);
                }
                else CreateOutput(L"[unknown type]", get_color_value(L"Comment"));
                };

            for (int i = 0; i < argumentCount; i++) {
                if (JS_IsException(argumentValues[i])) CreateOutput(L"[exception]", get_color_value(L"Comment"));
                else print_js_value(argumentValues[i], 0);
                if (i < argumentCount - 1) CreateOutput(L" ", get_color_value(L"Object"));
            }
            CreateOutput(L"\n", get_color_value(L"Object"));

            JS_FreeAtom(ctx, atom_toStringTag);
            JS_FreeAtom(ctx, atom_name);
            JS_FreeAtom(ctx, atom_toString);
            JS_FreeAtom(ctx, atom_length);
            JS_FreeAtom(ctx, atom_buffer);
            JS_FreeAtom(ctx, atom_byteOffset);
            JS_FreeAtom(ctx, atom_state);
            JS_FreeAtom(ctx, atom__isPrivate);
            JS_FreeAtom(ctx, atom_byteLength);
            JS_FreeAtom(ctx, atom_toLocaleString);
            JS_FreeAtom(ctx, atom_constructor);
            JS_FreeAtom(ctx, atom_prototype);
            JS_FreeAtom(ctx, atom_internal);
            JS_FreeAtom(ctx, atom_id);

            return JS_UNDEFINED;
        }

        static JSValue filesystem_count(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            if (argumentCount != 1) {
                JS_ThrowTypeError(ctx, "[filesystem.count] Only 1 argument is supported: (path)");
                return JS_EXCEPTION;
            }
            JSV vPath = JSV(&argumentValues[0]);
            std::string path = "";
            if (!JS_IsString(vPath.get(0)) || !ReadJSValueAsString(ctx, vPath, path)) {
                JS_ThrowTypeError(ctx, "[filesystem.count] The first argument must be a string");
                return JS_EXCEPTION;
            }
            FileController fc = FileController(stringToWstring(path), stringToWstring(GetCurrentWorkDirectory(ctx)));
            if (!fc.isDir()) {
                JS_ThrowTypeError(ctx, "[filesystem.count] The path must be a directory");
                return JS_EXCEPTION;
            }
            return JS_NewBigUint64(ctx, fc.count());
        }
        static JSValue filesystem_remove(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            if (argumentCount != 1) {
                JS_ThrowTypeError(ctx, "[filesystem.remove] Only 1 argument is supported: (path)");
                return JS_EXCEPTION;
            }
            JSV vPath = JSV(&argumentValues[0]);
            std::string path = "";
            if (!JS_IsString(vPath.get(0)) || !ReadJSValueAsString(ctx, vPath, path)) {
                JS_ThrowTypeError(ctx, "[filesystem.remove] The first argument must be a string");
                return JS_EXCEPTION;
            }
            FileController fc = FileController(stringToWstring(path), stringToWstring(GetCurrentWorkDirectory(ctx)));
            return JS_NewBigUint64(ctx, fc.remove());
        }
        static JSValue filesystem_exists(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            if (argumentCount != 1) {
                JS_ThrowTypeError(ctx, "[filesystem.exists] Only 1 argument is supported: (path)");
                return JS_EXCEPTION;
            }
            JSV vPath = JSV(&argumentValues[0]);
            std::string path = "";
            if (!JS_IsString(vPath.get(0)) || !ReadJSValueAsString(ctx, vPath, path)) {
                JS_ThrowTypeError(ctx, "[filesystem.exists] The first argument must be a string");
                return JS_EXCEPTION;
            }
            FileController fc = FileController(stringToWstring(path), stringToWstring(GetCurrentWorkDirectory(ctx)));
            return JS_NewBool(ctx, fc.exists());
        }
        static JSValue filesystem_open(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            if (argumentCount <= 0 || argumentCount > 2) {
                JS_ThrowTypeError(ctx, "[filesystem.open] Only 1 or 2 arguments are supported: (path, mode?)");
                return JS_EXCEPTION;
            }

            JSValue jsPath = argumentValues[0];
            JSV vPath = JSV(&jsPath);

            std::string path = "";
            if (!JS_IsString(jsPath) || !ReadJSValueAsString(ctx, vPath, path) || path == "") {
                JS_ThrowTypeError(ctx, "[filesystem.open] The first argument must be a valid string type");
                return JS_EXCEPTION;
            }

            JSMData* jsmdPtr = nullptr;
            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                return JS_EXCEPTION;
            }

            std::string mode = "r";
            if (argumentCount > 1) {
                JSValueConst jsMode = argumentValues[1];
                if (!JS_IsString(jsMode)) {
                    JS_ThrowTypeError(ctx, "[filesystem.open] The second argument must be a string type");
                    return JS_EXCEPTION;
                }
                const char* cMode = JS_ToCString(ctx, jsMode);
                mode = cMode;
                JS_FreeCString(ctx, cMode);

            }

            int modeInt = GetFileControllerMode(mode);
            if (mode == "" && modeInt == filesystem_open_mode::FILE_MODE_NONE) {
                modeInt = filesystem_open_mode::FILE_MODE_READ;
                mode = "r";
            }
            else if (mode != "" && modeInt == filesystem_open_mode::FILE_MODE_NONE) {
                JS_ThrowTypeError(ctx, "[filesystem.open] The mode is invalid");
                return JS_EXCEPTION;
            }


            FileController* fc = new FileController(stringToWstring(path), stringToWstring(GetCurrentWorkDirectory(ctx)));
            if (modeInt & filesystem_open_mode::FILE_MODE_READ) {
                if (!fc->exists()) {
                    delete fc;
                    JS_ThrowTypeError(ctx, "[filesystem.open] The file does not exist");
                    return JS_EXCEPTION;
                }
            }
            else if ((modeInt & filesystem_open_mode::FILE_MODE_WRITE) && !(modeInt & filesystem_open_mode::FILE_MODE_APPEND)) {
                fc->clear();
            }

            JSV fileControllerObject = NewObject(ctx);
            ULL id = GetNewFileControllerId(ctx);
            std::string stringId = std::to_string(id);

            jsmdPtr->fileControllerList[id] = fc;

            SetAttribute(ctx, fileControllerObject, "id", stringId, 0);
            SetAttribute(ctx, fileControllerObject, "mode", mode, 0);
            SetAttribute(ctx, fileControllerObject, "name", path, 0);

            JSV jsClosed = NewBool(ctx, false);
            SetAttribute(ctx, fileControllerObject, "closed", jsClosed, -1);

            JSV jsSeek = NewUint64(ctx, 0);

            SetAttribute(ctx, fileControllerObject, "seekPtr", jsSeek, -1);

            if (modeInt & filesystem_open_mode::FILE_MODE_READ || modeInt & filesystem_open_mode::FILE_MODE_RDWR) {
                AppendMethod(ctx, fileControllerObject, "read", [](JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) ->JSValue {
                    if (argumentCount > 1) {
                        JS_ThrowTypeError(ctx, "[filesystem.open->read] Only 1 argument is supported: (?size)");
                        return JS_EXCEPTION;
                    }

                    int64_t nsize = -1;
                    if (argumentCount == 1) {
                        JSValue jsSize = argumentValues[0];
                        if (!JS_IsNumber(jsSize)) {
                            JS_ThrowTypeError(ctx, "[filesystem.open->read] The first argument must be a number type");
                            return JS_EXCEPTION;
                        }
                        int result = JS_ToInt64(ctx, &nsize, jsSize);
                        if (result != 0 || nsize < -1) {
                            JS_ThrowRangeError(ctx, "[filesystem.open->read] The value of first argument is invalid");
                            return JS_EXCEPTION;
                        }
                    }

                    ULL size = 0;
                    if (nsize == -1) {
                        size = ULLONG_MAX;
                    }
                    else {
                        size = static_cast<ULL>(nsize);
                    }

                    JSMData* jsmdPtr = nullptr;
                    if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                        JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                        return JS_EXCEPTION;
                    }

                    JSV vThisVal = JSV(&thisVal);

                    JSV jsMode = GetProperty(ctx, vThisVal, "mode");
                    std::string mode = "";
                    if (!ReadJSValueAsString(ctx, jsMode, mode)) {
                        JS_ThrowTypeError(ctx, "[filesystem.open->read] This instance object is invalid");
                        return JS_EXCEPTION;
                    }

                    int modeInt = GetFileControllerMode(mode);
                    if (!((modeInt & filesystem_open_mode::FILE_MODE_READ) || (modeInt & filesystem_open_mode::FILE_MODE_RDWR))) {
                        JS_ThrowTypeError(ctx, "[filesystem.open->read] This instance object is invalid");
                        return JS_EXCEPTION;
                    }

                    JSV jsId = GetProperty(ctx, vThisVal, "id");
                    std::string sid = "";
                    if (!ReadJSValueAsString(ctx, jsId, sid)) {
                    ErrorProcess:;
                        JS_ThrowTypeError(ctx, "[filesystem.open->read] This instance object is invalid");
                        return JS_EXCEPTION;
                    }
                    ULL id = stoullSafely(stringToWstring(sid));
                    if (!jsmdPtr->fileControllerList.count(id)) goto ErrorProcess;
                    FileController* fc = jsmdPtr->fileControllerList[id];

                    JSV jsSeek = GetProperty(ctx, vThisVal, "seekPtr");
                    uint64_t uSeek = 0;
                    if (!ReadJSValueAsUint64(ctx, jsSeek, uSeek)) {
                        JS_ThrowTypeError(ctx, "[filesystem.open->read] This instance object is invalid");
                        return JS_EXCEPTION;
                    }
                    ULL seek = static_cast<ULL>(uSeek);

                    BYTEBUFFER fileData = {};
                    fc->read(seek, size, &fileData);

                    JSV uint8Array = NewUint8Array(ctx, fileData);
                    SetAttribute(ctx, vThisVal, "buffer", uint8Array);

                    ULL newSeek = seek + fileData.size();
                    JSV newSeekVal = NewUint64(ctx, newSeek);
                    SetAttribute(ctx, vThisVal, "seekPtr", newSeekVal);

                    if (modeInt & filesystem_open_mode::FILE_MODE_BIN) {
                        return uint8Array.get(1);
                    }
                    else {
                        std::string text = GetTextFromBinary(&fileData);
                        JSV jsString = NewString(ctx, text);
                        return jsString.get(1);
                    }

                    return JS_UNDEFINED;
                    }, -1, 0);
            }
            if (modeInt & filesystem_open_mode::FILE_MODE_WRITE || modeInt & filesystem_open_mode::FILE_MODE_RDWR || modeInt & filesystem_open_mode::FILE_MODE_APPEND) {
                AppendMethod(ctx, fileControllerObject, "write", [](JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) ->JSValue {
                    if (argumentCount != 1) {
                        JS_ThrowTypeError(ctx, "[filesystem.open->write] Only 1 argument is supported: (data)");
                        return JS_EXCEPTION;
                    }

                    JSMData* jsmdPtr = nullptr;
                    if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                        JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                        return JS_EXCEPTION;
                    }

                    JSV vThisVal = JSV(&thisVal);

                    JSV jsMode = GetProperty(ctx, vThisVal, "mode");
                    std::string mode = "";
                    if (!ReadJSValueAsString(ctx, jsMode, mode)) {
                        JS_ThrowTypeError(ctx, "[filesystem.open->write] This instance object is invalid");
                        return JS_EXCEPTION;
                    }

                    int modeInt = GetFileControllerMode(mode);
                    if (!((modeInt & filesystem_open_mode::FILE_MODE_WRITE) || (modeInt & filesystem_open_mode::FILE_MODE_RDWR) || (modeInt & filesystem_open_mode::FILE_MODE_APPEND))) {
                        JS_ThrowTypeError(ctx, "[filesystem.open->write] This instance object is invalid");
                        return JS_EXCEPTION;
                    }

                    BYTEBUFFER writeData = {};
                    JSValue jsData = argumentValues[0];
                    JSV vData = JSV(&jsData);
                    if (!(modeInt & filesystem_open_mode::FILE_MODE_BIN)) {
                        std::string str = "";
                        if (!JS_IsString(jsData) || !ReadJSValueAsString(ctx, vData, str)) {
                            JS_ThrowTypeError(ctx, "[filesystem.open->write] The first argument must be a string type");
                            return JS_EXCEPTION;
                        }
                        writeData = ToBinary(str);
                    }
                    else if (modeInt & filesystem_open_mode::FILE_MODE_BIN) {
                        if (!ReadJSValueAsUint8Array(ctx, vData, writeData)) {
                            JS_ThrowTypeError(ctx, "[filesystem.open->write] The first argument must be a uint8Array type");
                            return JS_EXCEPTION;
                        }
                    }

                    JSV jsId = GetProperty(ctx, vThisVal, "id");
                    std::string sid = "";
                    if (!ReadJSValueAsString(ctx, jsId, sid)) {
                    ErrorProcess:;
                        JS_ThrowTypeError(ctx, "[filesystem.open->write] This instance object is invalid");
                        return JS_EXCEPTION;
                    }
                    ULL id = stoullSafely(stringToWstring(sid));
                    if (!jsmdPtr->fileControllerList.count(id)) goto ErrorProcess;
                    FileController* fc = jsmdPtr->fileControllerList[id];

                    JSV jsSeek = GetProperty(ctx, vThisVal, "seekPtr");
                    uint64_t uSeek = 0;
                    if (!ReadJSValueAsUint64(ctx, jsSeek, uSeek)) {
                        JS_ThrowTypeError(ctx, "[filesystem.open->write] This instance object is invalid");
                        return JS_EXCEPTION;
                    }
                    ULL seek = static_cast<ULL>(uSeek);

                    ULL writeSize = 0;
                    if (!(modeInt & filesystem_open_mode::FILE_MODE_APPEND)) {
                        writeSize = fc->write(&writeData, seek, false);
                    }
                    else if (modeInt & filesystem_open_mode::FILE_MODE_APPEND) {
                        writeSize = fc->write(&writeData, ULLONG_MAX, true);
                    }

                    ULL newSeek = 0;
                    if (modeInt & filesystem_open_mode::FILE_MODE_APPEND) {
                        newSeek = fc->size();
                    }
                    else {
                        newSeek = seek + writeSize;
                    }
                    JSV newSeekVal = NewUint64(ctx, newSeek);
                    SetAttribute(ctx, vThisVal, "seekPtr", newSeekVal, -1);

                    JSV returnSize = NewUint64(ctx, writeSize);
                    return returnSize.get(1);
                    }, -1, 0);
            }
            AppendMethod(ctx, fileControllerObject, "close", [](JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) ->JSValue {
                if (argumentCount > 0) {
                    JS_ThrowTypeError(ctx, "[filesystem.open->close] No arguments are supported");
                    return JS_EXCEPTION;
                }

                JSMData* jsmdPtr = nullptr;
                if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                    JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                    return JS_EXCEPTION;
                }

                JSV vThisVal = JSV(&thisVal);

                JSV jsClosedTemp = GetProperty(ctx, vThisVal, "closed");
                bool isClosed = false;
                ReadJSValueAsBool(ctx, jsClosedTemp, isClosed);
                if (isClosed) {
                    JS_ThrowTypeError(ctx, "[filesystem.open->close] File has been closed already, cannot call close repeatedly");
                    return JS_EXCEPTION;
                }

                JSV jsId = GetProperty(ctx, vThisVal, "id");
                std::string sid = "";
                if (!ReadJSValueAsString(ctx, jsId, sid)) {
                ErrorProcess:;
                    JS_ThrowTypeError(ctx, "[filesystem.open->read] This instance object is invalid");
                    return JS_EXCEPTION;
                }
                ULL id = stoullSafely(stringToWstring(sid));
                if (!jsmdPtr->fileControllerList.count(id)) goto ErrorProcess;

                delete jsmdPtr->fileControllerList[id];
                jsmdPtr->fileControllerList.erase(id);

                JSV jsClosed = NewBool(ctx, true);
                SetAttribute(ctx, vThisVal, "closed", jsClosed, 0);
                return JS_UNDEFINED;
                }, -1, 0);
            AppendMethod(ctx, fileControllerObject, "tell", [](JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) ->JSValue {
                if (argumentCount > 0) {
                    JS_ThrowTypeError(ctx, "[filesystem.open->tell] No arguments are supported");
                    return JS_EXCEPTION;
                }

                JSMData* jsmdPtr = nullptr;
                if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                    JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                    return JS_EXCEPTION;
                }

                JSV vThisVal = JSV(&thisVal);

                JSV jsId = GetProperty(ctx, vThisVal, "id");
                std::string sid = "";
                if (!ReadJSValueAsString(ctx, jsId, sid)) {
                ErrorProcess:;
                    JS_ThrowTypeError(ctx, "[filesystem.open->tell] This instance object is invalid");
                    return JS_EXCEPTION;
                }
                ULL id = stoullSafely(stringToWstring(sid));
                if (!jsmdPtr->fileControllerList.count(id)) goto ErrorProcess;

                JSV jsSeek = GetProperty(ctx, vThisVal, "seekPtr");
                return jsSeek.get(1);
                }, -1, 0);
            AppendMethod(ctx, fileControllerObject, "size", [](JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues)  ->JSValue {
                if (argumentCount > 0) {
                    JS_ThrowTypeError(ctx, "[filesystem.open->size] No arguments are supported");
                    return JS_EXCEPTION;
                }

                JSMData* jsmdPtr = nullptr;
                if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                    JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                    return JS_EXCEPTION;
                }

                JSV vThisVal = JSV(&thisVal);

                JSV jsId = GetProperty(ctx, vThisVal, "id");
                std::string sid = "";
                if (!ReadJSValueAsString(ctx, jsId, sid)) {
                ErrorProcess:;
                    JS_ThrowTypeError(ctx, "[filesystem.open->size] This instance object is invalid");
                    return JS_EXCEPTION;
                }
                ULL id = stoullSafely(stringToWstring(sid));
                if (!jsmdPtr->fileControllerList.count(id)) goto ErrorProcess;
                FileController* fc = jsmdPtr->fileControllerList[id];

                ULL size = fc->size();

                JSV returnSize = NewUint64(ctx, static_cast<uint64_t>(size));
                return returnSize.get(1);
                }, -1, 0);
            AppendMethod(ctx, fileControllerObject, "seek", [](JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) ->JSValue {
                if (argumentCount > 2 || argumentCount < 1) {
                    JS_ThrowTypeError(ctx, "[filesystem.open->seek] Only 1 or 2 arguments are supported: (offset, ?whence)");
                    return JS_EXCEPTION;
                }

                JSV vThisVal = JSV(&thisVal);

                JSValue jsOffset = argumentValues[0];
                JSV vOffset = JSV(ctx, &jsOffset);
                int64_t offset = 0;
                if (!ReadJSValueAsInt64(ctx, vOffset, offset)) {
                    JS_ThrowTypeError(ctx, "[filesystem.open->seek] The first argument must be an integer type");
                    return JS_EXCEPTION;
                }

                int64_t whence = 0;
                if (argumentCount >= 2) {
                    JSValue jsWhence = argumentValues[1];
                    JSV uWhence = JSV(ctx, &jsWhence);
                    if (!ReadJSValueAsInt64(ctx, uWhence, whence)) {
                        JS_ThrowTypeError(ctx, "[filesystem.open->seek] The second argument must be an integer type (0/1/2)");
                        return JS_EXCEPTION;
                    }
                    if (whence != 0 && whence != 1 && whence != 2) {
                        JS_ThrowRangeError(ctx, "[filesystem.open->seek] The second argument must be 0, 1 or 2");
                        return JS_EXCEPTION;
                    }
                }

                JSMData* jsmdPtr = nullptr;
                if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                    JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                    return JS_EXCEPTION;
                }

                JSV jsId = GetProperty(ctx, vThisVal, "id");
                std::string sid = "";
                if (!ReadJSValueAsString(ctx, jsId, sid)) {
                ErrorProcess:;
                    JS_ThrowTypeError(ctx, "[filesystem.open->seek] This instance object is invalid");
                    return JS_EXCEPTION;
                }
                ULL id = stoullSafely(stringToWstring(sid));
                if (!jsmdPtr->fileControllerList.count(id)) goto ErrorProcess;
                FileController* fc = jsmdPtr->fileControllerList[id];

                JSV jsSeek = GetProperty(ctx, vThisVal, "seekPtr");
                uint64_t uSeek = 0;
                if (!ReadJSValueAsUint64(ctx, jsSeek, uSeek)) {
                    JS_ThrowTypeError(ctx, "[filesystem.open->seek] This instance object is invalid");
                    return JS_EXCEPTION;
                }
                int64_t seek = static_cast<int64_t>(uSeek);

                JSV jsMode = GetProperty(ctx, vThisVal, "mode");
                std::string mode = "";
                if (!ReadJSValueAsString(ctx, jsMode, mode)) {
                    JS_ThrowTypeError(ctx, "[filesystem.open->seek] Failed to get file mode");
                    return JS_EXCEPTION;
                }
                int modeInt = GetFileControllerMode(mode);
                bool is_bin_mode = (modeInt & filesystem_open_mode::FILE_MODE_BIN);

                int64_t new_seek = 0;
                if (whence == 0) {
                    if (offset < 0) {
                        JS_ThrowRangeError(ctx, "[filesystem.open->seek] negative seek position %lld", offset);
                        return JS_EXCEPTION;
                    }
                    new_seek = offset;
                }
                else if (whence == 1) {
                    if (!is_bin_mode) {
                        JS_ThrowTypeError(ctx, "[filesystem.open->seek] can't do cur-relative seeks in text mode");
                        return JS_EXCEPTION;
                    }
                    new_seek = seek + offset;
                    if (new_seek < 0) {
                        JS_ThrowRangeError(ctx, "[filesystem.open->seek] seek position is negative");
                        return JS_EXCEPTION;
                    }
                }
                else if (whence == 2) {
                    if (!is_bin_mode && offset != 0) {
                        JS_ThrowTypeError(ctx, "[filesystem.open->seek] can't do end-relative seeks in text mode");
                        return JS_EXCEPTION;
                    }
                    new_seek = static_cast<int64_t>(fc->size()) + offset;
                    if (new_seek < 0) {
                        JS_ThrowRangeError(ctx, "[filesystem.open->seek] seek position is negative");
                        return JS_EXCEPTION;
                    }
                }

                JSV newSeekVal = NewUint64(ctx, static_cast<uint64_t>(new_seek));
                SetAttribute(ctx, vThisVal, "seekPtr", newSeekVal, -1);

                return JS_UNDEFINED;
                }, -1, 0);

            return fileControllerObject.get(1);
        }

        //////////////////////////////////////////////////////

        static bool ArrayInsert(JSContext* ctx, JSV array, uint64_t insert_idx, JSV value) {
            if (!JS_IsArray(array.get(0))) return false;
            int64_t len_int64 = ArrayGetLength(ctx, array);
            if (len_int64 < 0 || insert_idx > static_cast<uint32_t>(len_int64)) return false;
            uint32_t len = static_cast<uint32_t>(len_int64);
            for (uint32_t i = len; i > insert_idx; --i) {
                JSValue prev_val = JS_GetPropertyUint32(ctx, array.get(0), i - 1);
                if (JS_IsException(prev_val)) { JS_FreeValue(ctx, prev_val); return false; }
                if (JS_SetPropertyUint32(ctx, array.get(0), i, prev_val) != 1) return false;
            }
            return JS_SetPropertyUint32(ctx, array.get(0), static_cast<uint32_t>(insert_idx), value.get(1)) == 1;
        }
        static bool ArrayPushBack(JSContext* ctx, JSV array, JSV value) {
            if (!JS_IsArray(array.get(0))) return false;
            uint32_t len = static_cast<uint32_t>(ArrayGetLength(ctx, array));
            return JS_SetPropertyUint32(ctx, array.get(0), len, value.get(1)) == 1;
        }
        static bool ArrayPopBack(JSContext* ctx, JSV array) {
            if (!JS_IsArray(array.get(0))) return false;
            int64_t len_int64 = ArrayGetLength(ctx, array);
            if (len_int64 <= 0) return false;
            JSValue new_len_val = JS_NewInt32(ctx, static_cast<int32_t>(len_int64 - 1));
            bool ret = JS_SetPropertyStr(ctx, array.get(0), "length", new_len_val) == 1;
            JS_FreeValue(ctx, new_len_val);
            return ret;
        }
        static bool ArrayErase(JSContext* ctx, JSV array, uint64_t erase_idx) {
            if (!JS_IsArray(array.get(0))) return false;
            int64_t len_int64 = ArrayGetLength(ctx, array);
            if (len_int64 <= 0 || erase_idx >= static_cast<uint32_t>(len_int64)) return false;
            uint32_t len = static_cast<uint32_t>(len_int64);
            for (uint32_t i = static_cast<uint32_t>(erase_idx); i < len - 1; ++i) {
                JSValue next_val = JS_GetPropertyUint32(ctx, array.get(0), i + 1);
                if (JS_IsException(next_val)) { JS_FreeValue(ctx, next_val); return false; }
                if (JS_SetPropertyUint32(ctx, array.get(0), i, next_val) != 1) return false;
            }
            return ArrayPopBack(ctx, array);
        }
        static bool ArrayClear(JSContext* ctx, JSV array) {
            if (!JS_IsArray(array.get(0))) return false;
            JSValue zero_val = JS_NewInt32(ctx, 0);
            bool ret = JS_SetPropertyStr(ctx, array.get(0), "length", zero_val) == 1;
            JS_FreeValue(ctx, zero_val);
            return ret;
        }
        static bool ArrayResize(JSContext* ctx, JSV array, uint64_t new_size) {
            if (!JS_IsArray(array.get(0))) return false;
            int64_t len_int64 = ArrayGetLength(ctx, array);
            if (len_int64 < 0) return false;
            uint32_t old_len = static_cast<uint32_t>(len_int64);
            if (new_size < old_len) {
                JSValue new_len_val = JS_NewInt32(ctx, static_cast<int32_t>(new_size));
                bool ret = JS_SetPropertyStr(ctx, array.get(0), "length", new_len_val) == 1;
                JS_FreeValue(ctx, new_len_val);
                return ret;
            }
            JSValue undefined_val = JS_UNDEFINED;
            for (uint32_t i = old_len; i < new_size; ++i) {
                if (JS_SetPropertyUint32(ctx, array.get(0), i, undefined_val) != 1) return false;
            }
            return true;
        }
        static JSValue ArrayAt(JSContext* ctx, JSV array, uint64_t idx) {
            if (!JS_IsArray(array.get(0))) return JS_EXCEPTION;
            int64_t len_int64 = ArrayGetLength(ctx, array);
            if (len_int64 <= 0 || idx >= static_cast<uint32_t>(len_int64)) return JS_EXCEPTION;
            return JS_GetPropertyUint32(ctx, array.get(0), static_cast<uint32_t>(idx));
        }
        static bool ArrayAssign(JSContext* ctx, JSV array, uint64_t count, JSV val) {
            if (!JS_IsArray(array.get(0))) return false;
            if (!ArrayClear(ctx, array)) return false;
            for (uint32_t i = 0; i < count; ++i) {
                if (JS_SetPropertyUint32(ctx, array.get(0), i, val.get(1)) != 1) return false;
            }
            return true;
        }
        static bool ForEach(JSContext* ctx, JSV object, std::function<void(JSV& key, JSV& value)> callback) {
            const uint32_t JS_GPN_ALL = JS_GPN_STRING_MASK | JS_GPN_SYMBOL_MASK | JS_GPN_SET_ENUM;
            JSPropertyEnum* prop_tab = NULL;
            uint32_t prop_len = 0;
            if (JS_GetOwnPropertyNames(ctx, &prop_tab, &prop_len, object.get(0), JS_GPN_ALL) == 0) {
                for (uint32_t i = 0; i < prop_len; i++) {
                    JSPropertyEnum* prop = &prop_tab[i];
                    JSValue jsKey = JS_AtomToValue(ctx, prop->atom);
                    JSValue jsValue = JS_GetProperty(ctx, object.get(0), prop->atom);
                    JSV key = JSV(ctx, &jsKey).cset(1);
                    JSV value = JSV(ctx, &jsValue).cset(1);
                    if (callback) callback(key, value);
                    if (value.getCtx() == ctx) JS_SetProperty(ctx, object.get(0), prop->atom, value.get(1));
                }
                js_free(ctx, prop_tab);
                return true;
            }
            return false;
        }
        static bool ForEach(JSContext* ctx, JSV object, std::function<void(JSV& item)> callback) {

            if (!JS_IsArray(object.get(0))) {
                return false;
            }

            JSV js_length = GetProperty(ctx, object, "length");
            uint64_t length64 = 0;
            ReadJSValueAsUint64(ctx, js_length, length64);
            uint32_t length = static_cast<uint32_t>(length64);

            for (uint32_t i = 0; i < length; i++) {

                JSV item = GetProperty(ctx, object, NewUint64(ctx, i));

                if (callback) {
                    callback(item);
                }

                if (item.getCtx() == ctx) SetAttribute(ctx, object, NewUint64(ctx, i), item);

            }

            return true;
        }
        static uint64_t ArrayGetLength(JSContext* ctx, JSV object) {
            JSV js_length = GetProperty(ctx, object, "length");
            uint64_t length = 0;
            ReadJSValueAsUint64(ctx, js_length, length);
            return length;
        }

        static std::string GetCurrentWorkDirectory(JSContext* ctx) {
            JSV global = NewGlobalObject(ctx);
            JSV jsWorkDirectory = GetProperty(ctx, global, {
                {"system"},
                {"workDirectory"},
                });
            std::string workDirectory = "";
            if (JS_IsString(jsWorkDirectory.get(0))) ReadJSValueAsString(ctx, jsWorkDirectory, workDirectory);
            if (workDirectory == "") workDirectory = wstringToString(apppath(0));
            return workDirectory;
        }

        static JSV GetPrototype(JSContext* ctx, JSV targetObject) {
            JSValue ptt = JS_GetPrototype(ctx, targetObject.get(0));
            return JSV(ctx, &ptt).cset(1);
        }
        static JSV GetProperty(JSContext* ctx, JSV targetObject, std::vector<std::string> propChain) {
            if (propChain.empty()) {
                return JSV(JS_EXCEPTION);
            }
            JSV currentObject = targetObject;
            for (const auto& prop : propChain) {
                JSV nextObject = GetProperty(ctx, currentObject, prop);
                JSValue jsVal = nextObject.get(0);
                if (JS_IsUndefined(jsVal) || JS_IsNull(jsVal) || JS_IsException(jsVal)) {
                    return JSV().cset(1);
                }
                currentObject = nextObject;
            }
            return currentObject;
        }
        static JSV GetProperty(JSContext* ctx, JSV targetObject, std::string prop) {
            if (!targetObject.isValid()) return JSV(JS_EXCEPTION);
            return JSV(ctx, JS_GetPropertyStr(ctx, targetObject.get(0), prop.c_str())).cset(1);
        }
        static JSV GetProperty(JSContext* ctx, JSV targetObject, JSAtom atom) {
            if (!targetObject.isValid()) return JSV(JS_EXCEPTION);
            return JSV(ctx, JS_GetProperty(ctx, targetObject.get(0), atom)).cset(1);
        }
        static JSV GetProperty(JSContext* ctx, JSV targetObject, JSV key) {
            if (!targetObject.isValid()) return JSV(JS_EXCEPTION);
            JSAtom atom = JS_ValueToAtom(ctx, key.get(0));
            JSValue ppt = JS_GetProperty(ctx, targetObject.get(0), atom);
            JS_FreeAtom(ctx, atom);
            return JSV(ctx, &ppt).cset(1);
        }

        static bool ClearObject(JSContext* ctx, JSValue& jsv) {

            if (!JS_IsObject(jsv)) {
                return false;
            }

            const uint32_t JS_GPN_ALL = JS_GPN_STRING_MASK | JS_GPN_SYMBOL_MASK | JS_GPN_SET_ENUM;
            JSPropertyEnum* prop_tab = nullptr;
            uint32_t prop_len = 0;

            int get_prop_ret = JS_GetOwnPropertyNames(ctx, &prop_tab, &prop_len, jsv, JS_GPN_ALL);
            if (get_prop_ret < 0 || prop_tab == nullptr) {
                return false;
            }

            for (uint32_t i = 0; i < prop_len; ++i) {
                JSPropertyEnum& prop = prop_tab[i];
                JSAtom prop_atom = prop.atom;

                if (prop_atom == JS_ATOM_NULL) {
                    continue;
                }

                // 尝试重新定义属性为可配置/可写/可枚举，然后删除
                int define_flags = JS_PROP_CONFIGURABLE | JS_PROP_WRITABLE | JS_PROP_ENUMERABLE;
                (void)JS_DefineProperty(ctx, jsv, prop_atom, JS_UNDEFINED, JS_UNDEFINED, JS_UNDEFINED, define_flags);

                // 尝试删除属性
                int delete_result = JS_DeleteProperty(ctx, jsv, prop_atom, 0);

                // 删除失败则覆盖值为undefined
                if (delete_result <= 0) {
                    (void)JS_SetProperty(ctx, jsv, prop_atom, JS_UNDEFINED);
                }

                // 释放原子对象（quickjs-ng要求必须释放获取到的atom）
                JS_FreeAtom(ctx, prop_atom);
            }

            js_free(ctx, prop_tab);
            prop_tab = nullptr;
            prop_len = 0;

            JSPropertyEnum* check_tab = nullptr;
            uint32_t check_len = 0;
            int check_get_ret = JS_GetOwnPropertyNames(ctx, &check_tab, &check_len, jsv, JS_GPN_ALL);

            if (check_get_ret >= 0 && check_tab != nullptr) {
                // 仅对最终残留的属性（引擎保护的）覆盖值
                for (uint32_t i = 0; i < check_len; ++i) {
                    JSAtom prop_atom = check_tab[i].atom;
                    if (prop_atom != JS_ATOM_NULL) {
                        (void)JS_SetProperty(ctx, jsv, prop_atom, JS_UNDEFINED);
                        JS_FreeAtom(ctx, prop_atom);
                    }
                }
                // 释放二次检查的属性枚举数组（关键修复：原代码遗漏）
                js_free(ctx, check_tab);
            }

            return true;
        }
        static JSV NewGlobalObject(JSContext* ctx) {
            return JSV(ctx, JS_GetGlobalObject(ctx)).cset(1);
        }
        static JSV NewObject(JSContext* ctx) {
            JSValue object = JS_NewObject(ctx);
            return JSV(ctx, &object).cset(1);
        }
        static JSV NewObject(JSContext* ctx, JSV parentObject, std::string name) {
            JSValue object = JS_NewObject(ctx);
            JSV obj = JSV(ctx, &object);
            obj.set(1);
            JS_SetPropertyStr(ctx, parentObject.get(0), name.c_str(), obj.get(1));
            return obj;
        }
        static JSV GetObjectStruct(JSContext* ctx, const OBJECTStruct& value) {
            if (value.isString()) {
                return NewString(ctx, wstringToString(value.get<std::wstring>()));
            }
            else if (value.isBool()) {
                return NewBool(ctx, value.get<bool>());
            }
            else if (value.isDouble()) {
                return NewDouble(ctx, value.get<double>());
            }
            else if (value.isNull()) {
                return JSV(JS_NULL);
            }
            else if (value.isInt()) {
                return NewInt64(ctx, static_cast<int64_t>(value.get<int>()));
            }
            else if (value.isLong()) {
                return NewInt64(ctx, static_cast<int64_t>(value.get<long>()));
            }
            else if (value.isLongLong()) {
                return NewInt64(ctx, static_cast<int64_t>(value.get<long long>()));
            }
            else if (value.isUInt()) {
                return NewUint64(ctx, static_cast<uint64_t>(value.get<unsigned int>()));
            }
            else if (value.isULong()) {
                return NewUint64(ctx, static_cast<uint64_t>(value.get<unsigned long>()));
            }
            else if (value.isULongLong()) {
                return NewUint64(ctx, static_cast<uint64_t>(value.get<unsigned long long>()));
            }
            else if (value.isObject()) {
                OBJECT nextObject = value.get<OBJECT>();
                return NewObject(ctx, nextObject);
            }
            else if (value.isArray()) {
                std::vector<JSV> array = {};
                ARRAY nextArray = value.get<ARRAY>();
                for (OBJECTStruct objs : nextArray) {
                    array.push_back(GetObjectStruct(ctx, objs));
                }
                return NewArray(ctx, array);
            }
            else {
                return JSV(JS_UNDEFINED);
            }

        }
        static JSV NewObject(JSContext* ctx, OBJECT& object) {

            JSV returnObject = NewObject(ctx);

            for (const auto& [key, value] : object) {
                SetAttribute(ctx, returnObject, wstringToString(key), GetObjectStruct(ctx, value));
            }

            return returnObject;
        }
        static JSV NewArray(JSContext* ctx, std::vector<JSV> uArray) {
            JSValue array = JS_NewArray(ctx);
            for (uint32_t i = 0; i < static_cast<uint32_t>(uArray.size()); ++i) {
                JS_SetPropertyUint32(ctx, array, i, uArray[i].get(1));
            }
            return JSV(ctx, &array).cset(1);
        }

        static bool FreeObject(JSContext* ctx, JSV targetObject) {
            if (!JS_IsObject(targetObject.get(0))) return false;
            JS_FreeValue(ctx, targetObject.get(0));
            targetObject.set(-1);
            return true;
        }

        static bool AppendMethod(JSContext* ctx, JSV targetObject, std::string name, JSV func, int64_t flags = -1) {
            if (ctx == nullptr) return false;
            if (!JS_IsFunction(ctx, func.get(0))) {
                return false;
            }
            if (flags != -1 && flags >= 0) {
                return JS_DefinePropertyValueStr(ctx, targetObject.get(0), name.c_str(), func.get(1), static_cast<unsigned int>(flags)) == 1;
            }
            return JS_SetPropertyStr(ctx, targetObject.get(0), name.c_str(), func.get(1)) == 1;
        }
        template<typename Func>
        static bool AppendMethod(JSContext* ctx, JSV targetObject, std::string name, Func func, int argLength = -1, int64_t flags = -1) {
            if (ctx == nullptr) return false;
            if (!JS_IsObject(targetObject.get())) return false;
            JSValue jsFunc = JS_NewCFunction(ctx, func, name.c_str(), argLength);
            JSV jfc = JSV(ctx, jsFunc);
            jfc.set(1);
            bool result = AppendMethod(ctx, targetObject, name, jfc, flags);
            //AppendRelease(ctx, jfc);
            return result;
        }

        static std::string GetSymbolName(JSContext* ctx, JSV targetObject) {
            std::string result = "";

            if (ctx == nullptr) return result;
            if (!JS_IsObject(targetObject.get(0))) return result;

            JSV global = NewGlobalObject(ctx);
            if (JS_IsException(global.get(0))) return result;

            JSV symbol = GetProperty(ctx, global, "Symbol");
            if (JS_IsException(symbol.get(0)) || !JS_IsObject(symbol.get(0))) return result;

            JSV toStringTagSymbol = GetProperty(ctx, symbol, "toStringTag");
            if (JS_IsException(toStringTagSymbol.get(0)) || !JS_IsSymbol(toStringTagSymbol.get(0))) return result;

            JSAtom toStringTagAtom = JS_ValueToAtom(ctx, toStringTagSymbol.get(0));
            if (toStringTagAtom == JS_ATOM_NULL) {
                return result;
            }

            JSV jsName = JSV(ctx, JS_GetProperty(ctx, targetObject.get(0), toStringTagAtom)).cset(1);
            JS_FreeAtom(ctx, toStringTagAtom);

            if (JS_IsException(jsName.get(0))) return result;
            if (JS_IsString(jsName.get(0))) {
                size_t len = 0;
                const char* str = JS_ToCStringLen(ctx, &len, jsName.get(0));
                if (str != nullptr) {
                    result = std::string(str, len);
                    JS_FreeCString(ctx, str);
                }
            }

            return result;
        }
        static bool SetSymbolName(JSContext* ctx, JSV targetObject, std::string name) {

            if (ctx == nullptr) return false;
            if (!JS_IsObject(targetObject.get(0))) return false;

            JSV global = NewGlobalObject(ctx);
            if (JS_IsException(global.get(0))) return false;

            JSV symbol = GetProperty(ctx, global, "Symbol");
            if (JS_IsException(symbol.get(0)) || !JS_IsObject(symbol.get(0))) return false;

            JSV toStringTagSymbol = GetProperty(ctx, symbol, "toStringTag");
            if (JS_IsException(toStringTagSymbol.get(0)) || !JS_IsSymbol(toStringTagSymbol.get(0))) return false;

            JSV jsName = NewString(ctx, name);
            if (JS_IsException(jsName.get(0))) return false;

            JSV newProto = NewObject(ctx);
            if (JS_IsException(newProto.get(0))) return false;

            JSV originalProto = GetPrototype(ctx, targetObject);
            if (JS_IsException(originalProto.get(0))) return false;

            if (!JS_IsNull(originalProto.get(0)) && !JS_IsUndefined(originalProto.get(0))) {
                if (JS_SetPrototype(ctx, newProto.get(0), originalProto.get(0)) != 1) return false;
            }

            JSAtom toStringTagAtom = JS_ValueToAtom(ctx, toStringTagSymbol.get(0));
            if (toStringTagAtom == JS_ATOM_NULL) return false;

            int ret = SetAttribute(ctx, newProto, toStringTagAtom, jsName);
            JS_FreeAtom(ctx, toStringTagAtom);
            if (ret == -1 || ret == 0) return false;
            if (JS_SetPrototype(ctx, targetObject.get(0), newProto.get(0)) != 1) return false;
            return true;
        }
        static bool SetAttribute(JSContext* ctx, JSV targetObject, std::string key, JSV value, int64_t flags = -1) {
            if (ctx == nullptr) return false;
            int ret = 0;
            if (flags != -1 && flags >= 0) {
                return (JS_DefinePropertyValueStr(ctx, targetObject.get(0), key.c_str(), value.get(1), static_cast<unsigned int>(flags))) == 1;
            }
            return (JS_SetPropertyStr(ctx, targetObject.get(0), key.c_str(), value.get(1))) == 1;
        }
        static bool SetAttribute(JSContext* ctx, JSV targetObject, std::string key, std::string value, int64_t flags = -1) {
            if (ctx == nullptr) return false;
            JSValue jsVal = JS_NewString(ctx, value.c_str());
            if (JS_IsException(jsVal)) {
                return false;
            }
            int ret = 0;
            if (flags != -1 && flags >= 0) {
                ret = JS_DefinePropertyValueStr(ctx, targetObject.get(0), key.c_str(), jsVal, static_cast<unsigned int>(flags));
            }
            else {
                ret = JS_SetPropertyStr(ctx, targetObject.get(0), key.c_str(), jsVal);
            }
            return ret == 1;
        }
        static bool SetAttribute(JSContext* ctx, JSV targetObject, JSV key, JSV value, int64_t flags = -1) {
            if (ctx == nullptr) return false;
            int ret = 0;
            if (flags != -1 && flags >= 0) {
                return (JS_DefinePropertyValue(ctx, targetObject.get(0), JS_ValueToAtom(ctx, key.get(0)), value.get(1), static_cast<unsigned int>(flags))) == 1;
            }
            return (JS_SetProperty(ctx, targetObject.get(0), JS_ValueToAtom(ctx, key.get(0)), value.get(1))) == 1;
        }
        static bool SetAttribute(JSContext* ctx, JSV targetObject, JSAtom key, JSV value, int64_t flags = -1) {
            if (ctx == nullptr) return false;
            int ret = 0;
            if (flags != -1 && flags >= 0) {
                return (JS_DefinePropertyValue(ctx, targetObject.get(0), key, value.get(1), static_cast<unsigned int>(flags))) == 1;
            }
            return (JS_SetProperty(ctx, targetObject.get(0), key, value.get(1))) == 1;
        }
        static bool RemoveAttribute(JSContext* ctx, JSV targetObject, std::string key) {
            JSValue keyValue = JS_NewString(ctx, key.c_str());
            JSAtom atom = JS_ValueToAtom(ctx, keyValue);
            bool ret = JS_DeleteProperty(ctx, targetObject.get(0), atom, 0) == 1;
            JS_FreeAtom(ctx, atom);
            JS_FreeValue(ctx, keyValue);
            return ret;
        }
        static bool SetPrototype(JSContext* ctx, JSV targetObject, JSV value) {
            if (ctx == nullptr) return false;
            return (JS_SetPrototype(ctx, targetObject.get(0), value.get(1))) == 1;
        }

        static bool RemoveAttribute(JSContext* ctx, JSV targetObject, JSV key) {
            JSAtom atom = JS_ValueToAtom(ctx, key.get(0));
            bool ret = JS_DeleteProperty(ctx, targetObject.get(0), atom, 0) == 1;
            JS_FreeAtom(ctx, atom);
            return ret;
        }

        static bool ReadJSValueAsBool(JSContext* ctx, JSV jsVal, bool& outBool) {
            if (ctx == nullptr) return false;
            if (!JS_IsBool(jsVal.get(0))) {
                return false;
            }
            int nBool = JS_ToBool(ctx, jsVal.get(0));
            outBool = static_cast<bool>(nBool);
            return true;
        }
        static bool ReadJSValueAsString(JSContext* ctx, JSV jsVal, std::string& outString, bool isStrict = true) {
            if (ctx == nullptr) return false;
            if (!JS_IsString(jsVal.get(0)) && isStrict) {
                return false;
            }
            const char* cString = JS_ToCString(ctx, jsVal.get(0));
            if (cString == nullptr) {
                return false;
            }
            outString.assign(cString);
            JS_FreeCString(ctx, cString);
            return true;
        }
        static bool ReadJSValueAsInt32(JSContext* ctx, JSV jsVal, int32_t& outInt32) {
            if (ctx == nullptr) return false;
            if (!JS_IsNumber(jsVal.get(0)) && !JS_IsBigInt(jsVal.get(0))) {
                return false;
            }

            int32_t result = 0;
            int ret = -1;

            if (JS_IsNumber(jsVal.get(0))) {
                ret = JS_ToInt32(ctx, &result, jsVal.get(0));
            }

            if (ret != 0 && JS_IsBigInt(jsVal.get(0))) {
                int64_t bigResult = 0;
                ret = JS_ToInt64(ctx, &bigResult, jsVal.get(0));
                if (ret == 0) {
                    if (bigResult >= INT32_MIN && bigResult <= INT32_MAX) {
                        result = static_cast<int32_t>(bigResult);
                        ret = 0;
                    }
                    else {
                        ret = -1;
                    }
                }
            }

            if (ret != 0) {
                return false;
            }

            outInt32 = result;
            return true;
        }
        static bool ReadJSValueAsInt64(JSContext* ctx, JSV jsVal, int64_t& outInt64) {
            if (ctx == nullptr) return false;
            if (!JS_IsNumber(jsVal.get(0)) && !JS_IsBigInt(jsVal.get(0))) {
                return false;
            }

            int64_t result = 0;
            int ret = -1;

            if (JS_IsNumber(jsVal.get(0))) {
                ret = JS_ToInt64(ctx, &result, jsVal.get(0));
            }

            if (ret != 0 && JS_IsBigInt(jsVal.get(0))) {
                ret = JS_ToInt64(ctx, &result, jsVal.get(0));
            }

            if (ret != 0) {
                return false;
            }

            outInt64 = result;
            return true;
        }
        static bool ReadJSValueAsUint64(JSContext* ctx, JSV jsVal, uint64_t& outUint64) {
            if (ctx == nullptr) return false;
            if (!JS_IsNumber(jsVal.get(0)) && !JS_IsBigInt(jsVal.get(0))) {
                return false;
            }

            uint64_t result = 0;
            int ret = -1;

            if (JS_IsNumber(jsVal.get(0))) {
                double numVal = 0.0;
                ret = JS_ToFloat64(ctx, &numVal, jsVal.get(0));
                if (ret == 0) {
                    if (numVal >= 0 && numVal == floor(numVal) && numVal <= UINT64_MAX) {
                        result = static_cast<uint64_t>(numVal);
                        ret = 0;
                    }
                    else {
                        ret = -1;
                    }
                }
            }

            if (ret != 0 && JS_IsBigInt(jsVal.get(0))) {
                ret = JS_ToBigUint64(ctx, &result, jsVal.get(0));
            }

            if (ret != 0) {
                return false;
            }

            outUint64 = result;
            return true;
        }
        static bool ReadJSValueAsDouble(JSContext* ctx, JSV jsVal, double& outDouble) {
            if (ctx == nullptr) return false;
            if (!JS_IsNumber(jsVal.get(0)) && !JS_IsBigInt(jsVal.get(0))) {
                return false;
            }
            double result = 0.0;
            int ret = -1;
            if (JS_IsNumber(jsVal.get(0))) {
                ret = JS_ToFloat64(ctx, &result, jsVal.get(0));
            }
            if (ret != 0 && JS_IsBigInt(jsVal.get(0))) {
                int64_t bigResult = 0;
                ret = JS_ToInt64(ctx, &bigResult, jsVal.get(0));
                if (ret == 0) {
                    result = static_cast<double>(bigResult);
                    ret = 0;
                }
            }

            if (ret != 0) {
                return false;
            }

            outDouble = result;
            return true;
        }
        static bool ReadJSValueAsArray(JSContext* ctx, JSV jsVal, std::vector<JSV>& outArray) {
            if (ctx == nullptr) return false;
            if (!JS_IsArray(jsVal.get(0))) {
                return false;
            }

            outArray.clear();

            JSValue lenVal = JS_GetPropertyStr(ctx, jsVal.get(0), "length");
            if (JS_IsException(lenVal) || !JS_IsNumber(lenVal)) {
                JS_FreeValue(ctx, lenVal);
                return false;
            }

            uint32_t arrLen = 0;
            int ret = JS_ToUint32(ctx, &arrLen, lenVal);
            JS_FreeValue(ctx, lenVal);
            if (ret != 0) {
                return false;
            }

            for (uint32_t i = 0; i < arrLen; ++i) {
                JSValue elem = JS_GetPropertyUint32(ctx, jsVal.get(0), i);
                if (JS_IsException(elem)) {
                    outArray.clear();
                    JS_FreeValue(ctx, elem);
                    return false;
                }
                outArray.push_back(JSV(ctx, &elem).cset(1));
            }

            return true;
        }
        static bool ReadJSValueAsObjectStruct(JSContext* ctx, JSValue propVal, OBJECTStruct& structVal) {
            if (JS_IsNull(propVal)) {
                structVal.data = nullptr_t{};
            }
            else if (JS_IsBool(propVal)) {
                structVal.data = (JS_ToBool(ctx, propVal) == 1);
            }
            else if (JS_IsBigInt(propVal)) {
                int64_t bigIntVal;
                if (JS_ToBigInt64(ctx, &bigIntVal, propVal) == 0) {
                    structVal.data = bigIntVal;
                }
                else {
                    uint64_t bigUintVal;
                    if (JS_ToBigUint64(ctx, &bigUintVal, propVal) == 0) {
                        structVal.data = bigUintVal;
                    }
                    else {
                        std::string protoName = GetFullPrototypeName(ctx, propVal);
                        structVal.data = stringToWstring(protoName);
                        return false;
                    }
                }
            }
            else if (JS_IsNumber(propVal)) {
                double dVal;
                if (JS_ToFloat64(ctx, &dVal, propVal) == 0) {
                    int32_t i32 = static_cast<int32_t>(dVal);
                    if (static_cast<double>(i32) == dVal) {
                        structVal.data = static_cast<int>(i32);
                    }
                    else {
                        uint32_t u32 = static_cast<uint32_t>(dVal);
                        if (static_cast<double>(u32) == dVal) {
                            structVal.data = static_cast<unsigned int>(u32);
                        }
                        else {
                            int64_t i64 = static_cast<int64_t>(dVal);
                            if (static_cast<double>(i64) == dVal) {
                                structVal.data = static_cast<long long>(i64);
                            }
                            else {
                                uint64_t u64 = static_cast<uint64_t>(dVal);
                                if (static_cast<double>(u64) == dVal) {
                                    structVal.data = static_cast<unsigned long long>(u64);
                                }
                                else {
                                    structVal.data = dVal;
                                }
                            }
                        }
                    }
                }
                else {
                    std::string protoName = GetFullPrototypeName(ctx, propVal);
                    structVal.data = stringToWstring(protoName);
                    return false;
                }
            }
            else if (JS_IsString(propVal)) {
                size_t valStrLen = 0;
                const char* valCStr = JS_ToCStringLen(ctx, &valStrLen, propVal);
                if (valCStr) {
                    structVal.data = stringToWstring(valCStr);
                    JS_FreeCString(ctx, valCStr);
                }
                else {
                    std::string protoName = GetFullPrototypeName(ctx, propVal);
                    structVal.data = stringToWstring(protoName);
                    return false;
                }
            }
            else if (JS_IsObject(propVal) && !JS_IsArray(propVal)) {
                OBJECT nestedObj;
                if (!ReadJSValueAsObject(ctx, JSV(ctx, &propVal), nestedObj)) return false;
                structVal.data = nestedObj;
            }
            else if (JS_IsArray(propVal)) {
                std::vector<JSV> array = {};
                if (!ReadJSValueAsArray(ctx, propVal, array)) return false;
                ARRAY nestedArray;
                for (JSV& jsv : array) {
                    OBJECTStruct nestedObjStruct;
                    if (!ReadJSValueAsObjectStruct(ctx, jsv.get(0), nestedObjStruct)) return false;
                    nestedArray.push_back(nestedObjStruct);
                }
                structVal.data = nestedArray;
            }
            else if (JS_IsUndefined(propVal)) {
                structVal.data = nullptr_t{};
            }
            else {
                std::string protoName = GetFullPrototypeName(ctx, propVal);
                structVal.data = stringToWstring(protoName);
                return false;
            }
            return true;
        }

        static bool ReadJSValueAsObject(JSContext* ctx, JSV jsVal, OBJECT& outObject) {
            if (ctx == nullptr) return false;
            JSValue jsObj = jsVal.get(0);
            if (!JS_IsObject(jsObj) || JS_IsArray(jsObj)) {
                return false;
            }
            outObject.clear();
            JSPropertyEnum* propTab = nullptr;
            uint32_t propCount = 0;
            const int flags = JS_GPN_STRING_MASK | JS_GPN_ENUM_ONLY;
            bool bSuccess = true;
            int ret = JS_GetOwnPropertyNames(ctx, &propTab, &propCount, jsObj, flags);
            if (ret < 0 || propTab == nullptr || propCount == 0) {
                if (propTab != nullptr) {
                    js_free(ctx, propTab);
                }
                return false;
            }
            for (uint32_t i = 0; i < propCount; ++i) {
                JSPropertyEnum& propEnum = propTab[i];
                std::wstring propName;
                OBJECTStruct structVal;
                const char* cStr = JS_AtomToCString(ctx, propEnum.atom);
                if (cStr == nullptr) {
                    bSuccess = false;
                    continue;
                }
                propName = stringToWstring(cStr);
                JS_FreeCString(ctx, cStr);
                JSValue propVal = JS_GetProperty(ctx, jsObj, propEnum.atom);
                if (JS_IsException(propVal)) {
                    JS_FreeValue(ctx, propVal);
                    bSuccess = false;
                    continue;
                }

                if (!ReadJSValueAsObjectStruct(ctx, propVal, structVal)) {
                    bSuccess = false;
                }

                outObject[propName] = structVal;
                JS_FreeValue(ctx, propVal);
            }
            if (propTab != nullptr) {
                for (uint32_t i = 0; i < propCount; ++i) {
                    JS_FreeAtom(ctx, propTab[i].atom);
                }
                js_free(ctx, propTab);
            }
            return bSuccess;
        }
        static bool ReadObjectProperty(JSContext* ctx, JSV jsVal, std::string name, JSV& property) {
            if (ctx == nullptr) return false;
            if (!JS_IsObject(jsVal.get(0)) || JS_IsArray(jsVal.get(0)) || JS_IsNull(jsVal.get(0)) || JS_IsUndefined(jsVal.get(0))) {
                return false;
            }
            JSValue propVal = JS_GetPropertyStr(ctx, jsVal.get(0), name.c_str());
            if (JS_IsUndefined(propVal) || JS_IsNull(propVal) || JS_IsException(propVal)) {
                JS_FreeValue(ctx, propVal);
                return false;
            }
            property = JSV(ctx, propVal).cset(1);
            return true;
        }
        static bool ReadObjectPropertyValue(JSContext* ctx, JSV jsVal, JSV propName, JSV& property) {
            if (ctx == nullptr) return false;
            if (!JS_IsObject(jsVal.get(0)) || JS_IsArray(jsVal.get(0)) || JS_IsNull(jsVal.get(0)) || JS_IsUndefined(jsVal.get(0))) {
                return false;
            }
            JSAtom atom = JS_ValueToAtom(ctx, propName.get(0));
            JSValue propVal = JS_GetProperty(ctx, jsVal.get(0), atom);
            JS_FreeAtom(ctx, atom);
            if (JS_IsUndefined(propVal) || JS_IsNull(propVal) || JS_IsException(propVal)) {
                JS_FreeValue(ctx, propVal);
                return false;
            }
            property = JSV(ctx, propVal).cset(1);
            return true;
        }
        static bool ReadBinaryAsFormData(JSContext* ctx, BYTEBUFFER_PTR binary, FORMDATA& formData) {
            if (!binary || binary->empty())
                return false;

            const uint8_t* data = binary->data();
            size_t len = binary->size();
            if (len < 32)
                return false;

            formData.clear();

            // -------------------------------------------------------------------------
            // 【核心】自动从请求体开头提取 boundary
            // 规则：
            // 1. 以 -- 开头
            // 2. 后面是任意非换行字符
            // 3. 到 \r 或 \n 结束
            // -------------------------------------------------------------------------
            size_t pos = 0;

            while (pos + 1 < len && !(data[pos] == '-' && data[pos + 1] == '-'))
                pos++;
            if (pos + 2 >= len)
                return false;

            size_t boundaryStart = pos;
            pos += 2;

            while (pos < len && data[pos] != '\r' && data[pos] != '\n')
                pos++;
            if (pos >= len)
                return false;

            std::string boundary((const char*)data + boundaryStart, pos - boundaryStart);
            std::string endBoundary = boundary + "--";

            // -------------------------------------------------------------------------
            // 跳过第一个 boundary 和换行
            // -------------------------------------------------------------------------
            pos = boundaryStart + boundary.size();
            while (pos < len && (data[pos] == '\r' || data[pos] == '\n'))
                pos++;

            // -------------------------------------------------------------------------
            // 循环解析每一段
            // -------------------------------------------------------------------------
            while (pos < len) {
                if (pos + endBoundary.size() <= len) {
                    if (memcmp(data + pos, endBoundary.data(), endBoundary.size()) == 0)
                        break;
                }

                size_t headerEnd = std::string::npos;
                for (size_t i = pos; i + 3 < len; ++i) {
                    if (data[i] == '\r' && data[i + 1] == '\n' && data[i + 2] == '\r' && data[i + 3] == '\n') {
                        headerEnd = i;
                        break;
                    }
                }
                if (headerEnd == std::string::npos) {
                    for (size_t i = pos; i + 1 < len; ++i) {
                        if (data[i] == '\n' && data[i + 1] == '\n') {
                            headerEnd = i;
                            break;
                        }
                    }
                }
                if (headerEnd == std::string::npos)
                    break;

                size_t bodyStart = headerEnd;
                if (bodyStart + 4 <= len && data[bodyStart] == '\r' && data[bodyStart + 1] == '\n'
                    && data[bodyStart + 2] == '\r' && data[bodyStart + 3] == '\n')
                    bodyStart += 4;
                else if (bodyStart + 2 <= len && data[bodyStart] == '\n' && data[bodyStart + 1] == '\n')
                    bodyStart += 2;
                else
                    break;

                // ---------------------------------------------------------------------
                // 解析 name、filename、Content-Type
                // ---------------------------------------------------------------------
                FORMDATAITEM file;

                const char* nameKey = "name=\"";
                size_t nameKeyLen = strlen(nameKey);
                size_t namePos = std::string::npos;
                for (size_t i = pos; i + nameKeyLen <= headerEnd; ++i) {
                    if (memcmp(data + i, nameKey, nameKeyLen) == 0) {
                        namePos = i + nameKeyLen;
                        break;
                    }
                }
                if (namePos == std::string::npos) {
                    pos = bodyStart;
                    continue;
                }

                size_t nameEnd = namePos;
                while (nameEnd < headerEnd && data[nameEnd] != '"')
                    nameEnd++;
                if (nameEnd >= headerEnd) {
                    pos = bodyStart;
                    continue;
                }
                file.name = std::string((const char*)data + namePos, nameEnd - namePos);

                const char* fnKey = "filename=\"";
                size_t fnKeyLen = strlen(fnKey);
                size_t fnPos = std::string::npos;
                for (size_t i = pos; i + fnKeyLen <= headerEnd; ++i) {
                    if (memcmp(data + i, fnKey, fnKeyLen) == 0) {
                        fnPos = i + fnKeyLen;
                        break;
                    }
                }
                if (fnPos != std::string::npos && fnPos < headerEnd) {
                    size_t fnEnd = fnPos;
                    while (fnEnd < headerEnd && data[fnEnd] != '"')
                        fnEnd++;
                    if (fnEnd < headerEnd)
                        file.fileName = std::string((const char*)data + fnPos, fnEnd - fnPos);
                }

                const char* ctKey = "Content-Type: ";
                size_t ctKeyLen = strlen(ctKey);
                size_t ctPos = std::string::npos;
                for (size_t i = pos; i + ctKeyLen <= headerEnd; ++i) {
                    if (memcmp(data + i, ctKey, ctKeyLen) == 0) {
                        ctPos = i + ctKeyLen;
                        break;
                    }
                }
                if (ctPos != std::string::npos && ctPos < headerEnd) {
                    size_t ctEnd = ctPos;
                    while (ctEnd < headerEnd && data[ctEnd] != '\r' && data[ctEnd] != '\n')
                        ctEnd++;
                    file.contentType = std::string((const char*)data + ctPos, ctEnd - ctPos);
                }

                size_t bodyEnd = bodyStart;
                bool found = false;
                while (bodyEnd + boundary.size() <= len) {
                    if (memcmp(data + bodyEnd, boundary.data(), boundary.size()) == 0) {
                        found = true;
                        break;
                    }
                    bodyEnd++;
                }
                if (!found)
                    bodyEnd = len;

                size_t bodyLen = bodyEnd - bodyStart;
                if (bodyLen >= 2 && data[bodyEnd - 2] == '\r' && data[bodyEnd - 1] == '\n')
                    bodyLen -= 2;
                else if (bodyLen >= 1 && data[bodyEnd - 1] == '\n')
                    bodyLen -= 1;

                if (bodyLen > 0) {
                    file.binary.assign(data + bodyStart, data + bodyStart + bodyLen);
                }

                file.key = NewString(ctx, file.name);
                file.value = NewUint8Array(ctx, file.binary);
                formData[file.name] = std::move(file);
                pos = bodyEnd;
            }

            return !formData.empty();
        }

        template<typename Func>
        static JSV NewIterator(JSContext* ctx, JSV targetObject, std::string name, Func next, int64_t flags = -1) {
            JSV iterator = NewObject(ctx);
            if (!iterator.isValid()) return {};

            SetSymbolName(ctx, iterator, name);
            AppendMethod(ctx, iterator, "next", next, -1, flags);

            JSV global = NewGlobalObject(ctx);
            if (!global.isValid()) return {};
            JSV symbolIterator = GetProperty(ctx, global, { {"Symbol"}, {"iterator"} });
            if (!symbolIterator.isValid()) return {};

            JSV iteratorFunc = NewFunction(ctx, "Symbol.iterator", [](JSContext* ctx, JSValueConst thisVal, int argc, JSValueConst* argv) -> JSValue {
                return JS_DupValue(ctx, thisVal);
                }, -1);
            if (!iteratorFunc.isValid()) return {};

            SetAttribute(ctx, iterator, symbolIterator, iteratorFunc, flags);
            SetAttribute(ctx, targetObject, symbolIterator, iterator, flags);

            return iterator;
        }
        template<typename Func>
        static JSV NewConstructor(JSContext* ctx, std::string name, Func func, int argLength = -1) {
            JSValue jsFunc = JS_NewCFunction2(ctx, func, name.c_str(), argLength, JS_CFUNC_constructor, 0);
            return JSV(ctx, jsFunc).cset(1);
        }
        template<typename Func>
        static JSV NewFunction(JSContext* ctx, std::string name, Func func, int argLength = -1) {
            JSValue jsFunc = JS_NewCFunction(ctx, func, name.c_str(), argLength);
            return JSV(ctx, jsFunc).cset(1);
        }
        static JSV NewNumber(JSContext* ctx, double num) {
            JSValue jsVal = JS_NewNumber(ctx, num);
            return JSV(ctx, &jsVal).cset(1);
        }
        static JSV NewBool(JSContext* ctx, bool bVal) {
            JSValue jsVal = JS_NewBool(ctx, bVal);
            return JSV(ctx, &jsVal).cset(1);
        }
        static JSV NewInt64(JSContext* ctx, int64_t i64Val) {
            JSValue jsVal = JS_NewBigInt64(ctx, i64Val);
            return JSV(ctx, &jsVal).cset(1);
        }
        static JSV NewUint64(JSContext* ctx, uint64_t u64Val) {
            JSValue jsVal = JS_NewBigUint64(ctx, u64Val);
            return JSV(ctx, &jsVal).cset(1);
        }
        static JSV NewDouble(JSContext* ctx, double dVal) {
            JSValue jsVal = JS_NewFloat64(ctx, dVal);
            return JSV(ctx, &jsVal).cset(1);
        }
        static JSV NewString(JSContext* ctx, const std::string& str) {
            JSValue jsVal = JS_NewString(ctx, str.c_str());
            return JSV(ctx, &jsVal).cset(1);
        }
        static JSV NewArrayBuffer(JSContext* ctx, const BYTEBUFFER& vec) {
            if (vec.empty()) {
                JSValue emptyBuffer = JS_NewArrayBuffer(ctx, nullptr, 0, nullptr, nullptr, false);
                return JSV(ctx, &emptyBuffer).cset(1);
            }

            size_t dataLen = vec.size();
            uint8_t* buf = (uint8_t*)malloc(dataLen);
            if (buf == nullptr) {
                return JSV(JS_EXCEPTION);
            }

            memcpy(buf, vec.data(), dataLen);

            JSValue buffer = JS_NewArrayBuffer(
                ctx,
                buf,
                dataLen,
                [](JSRuntime* rt, void* opaque, void* data) {
                    if (data != nullptr) {
                        free(data);
                    }
                },
                nullptr,
                false
            );

            if (JS_IsException(buffer)) {
                free(buf);
                return JSV(JS_EXCEPTION);
            }

            JSV vbuffer = JSV(ctx, &buffer);
            vbuffer.set(1);
            //AppendRelease(ctx, vbuffer);
            return vbuffer;
        }

        static JSV NewError(JSContext* ctx) {
            JSValue jsVal = JS_NewError(ctx);
            return JSV(ctx, &jsVal).cset(1);
        }
        static JSV NewReferenceError(JSContext* ctx, std::string msg) {
            JSValue jsVal = JS_NewReferenceError(ctx, msg.c_str());
            return JSV(ctx, &jsVal).cset(1);
        }
        static JSV NewTypeError(JSContext* ctx, std::string msg) {
            JSValue jsVal = JS_NewTypeError(ctx, msg.c_str());
            return JSV(ctx, &jsVal).cset(1);
        }
        static JSV NewRangeError(JSContext* ctx, std::string msg) {
            JSValue jsVal = JS_NewRangeError(ctx, msg.c_str());
            return JSV(ctx, &jsVal).cset(1);
        }
        static JSV NewSyntaxError(JSContext* ctx, std::string msg) {
            JSValue jsVal = JS_NewSyntaxError(ctx, msg.c_str());
            return JSV(ctx, &jsVal).cset(1);
        }
        static JSV NewInternalError(JSContext* ctx, std::string msg) {
            JSValue jsVal = JS_NewInternalError(ctx, msg.c_str());
            return JSV(ctx, &jsVal).cset(1);
        }
        static JSV NewPlainError(JSContext* ctx, std::string msg) {
            JSValue jsVal = JS_NewPlainError(ctx, msg.c_str());
            return JSV(ctx, &jsVal).cset(1);
        }

        static bool ReadJSValueAsArrayBufferView(JSContext* ctx, JSV jsVal, const std::string& expectedTypeName, BYTEBUFFER& outBinary) {
            outBinary.clear();

            if (!JS_IsObject(jsVal.get(0))) {
                return false;
            }

            JSValue constructor = JS_GetPropertyStr(ctx, jsVal.get(0), "constructor");

            if (JS_IsException(constructor)) {
                JS_FreeValue(ctx, constructor);
                return false;
            }

            JSValue constructorName = JS_GetPropertyStr(ctx, constructor, "name");
            if (JS_IsException(constructorName)) {
                JS_FreeValue(ctx, constructor);
                JS_FreeValue(ctx, constructorName);
                return false;
            }



            const char* name = JS_ToCString(ctx, constructorName);
            if (!name || strcmp(name, expectedTypeName.c_str()) != 0) {
                if (name) JS_FreeCString(ctx, name);
                JS_FreeValue(ctx, constructor);
                JS_FreeValue(ctx, constructorName);
                return false;
            }
            JS_FreeCString(ctx, name);
            JS_FreeValue(ctx, constructor);
            JS_FreeValue(ctx, constructorName);

            JSValue buffer = JS_GetPropertyStr(ctx, jsVal.get(0), "buffer");
            if (JS_IsException(buffer)) {
                JS_FreeValue(ctx, buffer);
                return false;
            }

            if (!JS_IsArrayBuffer(buffer)) {
                JS_FreeValue(ctx, buffer);
                return false;
            }

            JSValue byteLengthVal = JS_GetPropertyStr(ctx, jsVal.get(0), "byteLength");
            if (JS_IsException(byteLengthVal)) {
                JS_FreeValue(ctx, buffer);
                JS_FreeValue(ctx, byteLengthVal);
                return false;
            }

            JSValue byteOffsetVal = JS_GetPropertyStr(ctx, jsVal.get(0), "byteOffset");
            if (JS_IsException(byteOffsetVal)) {
                JS_FreeValue(ctx, buffer);
                JS_FreeValue(ctx, byteLengthVal);
                JS_FreeValue(ctx, byteOffsetVal);
                return false;
            }

            int64_t byteLength = 0;
            int64_t byteOffset = 0;

            if (JS_ToInt64(ctx, &byteLength, byteLengthVal) != 0) {
                JS_FreeValue(ctx, buffer);
                JS_FreeValue(ctx, byteLengthVal);
                JS_FreeValue(ctx, byteOffsetVal);
                return false;
            }

            if (JS_ToInt64(ctx, &byteOffset, byteOffsetVal) != 0) {
                JS_FreeValue(ctx, buffer);
                JS_FreeValue(ctx, byteLengthVal);
                JS_FreeValue(ctx, byteOffsetVal);
                return false;
            }

            if (byteLength < 0 || byteOffset < 0) {
                JS_FreeValue(ctx, buffer);
                JS_FreeValue(ctx, byteLengthVal);
                JS_FreeValue(ctx, byteOffsetVal);
                return false;
            }

            size_t bufLen = 0;
            uint8_t* bufData = JS_GetArrayBuffer(ctx, &bufLen, buffer);
            if (bufData == nullptr) {
                JS_FreeValue(ctx, buffer);
                JS_FreeValue(ctx, byteLengthVal);
                JS_FreeValue(ctx, byteOffsetVal);
                return true;
            }

            if ((size_t)byteOffset + (size_t)byteLength > bufLen) {
                JS_FreeValue(ctx, buffer);
                JS_FreeValue(ctx, byteLengthVal);
                JS_FreeValue(ctx, byteOffsetVal);
                return false;
            }

            if (byteLength > 0) {
                outBinary.resize((size_t)byteLength);
                memcpy(outBinary.data(), bufData + byteOffset, (size_t)byteLength);
            }

            JS_FreeValue(ctx, buffer);
            JS_FreeValue(ctx, byteLengthVal);
            JS_FreeValue(ctx, byteOffsetVal);

            return true;
        }
        static JSV CreateTypedArrayFromBuffer(JSContext* ctx, JSV buffer, const std::string& typeName) {
            if (JS_IsException(buffer.get(0))) {
                return JSV(JS_EXCEPTION);
            }

            JSValue global = JS_GetGlobalObject(ctx);
            JSValue constructor = JS_GetPropertyStr(ctx, global, typeName.c_str());
            if (JS_IsException(constructor)) {
                return JSV(ctx, JS_EXCEPTION);
            }
            JSValue bg = buffer.get();
            JSValue typedArr = JS_CallConstructor(ctx, constructor, 1, &bg);
            JS_FreeValue(ctx, constructor);
            JS_FreeValue(ctx, global);
            if (JS_IsException(typedArr)) {
                return JSV(ctx, JS_EXCEPTION);
            }

            JSV vTypeArr = JSV(ctx, &typedArr);
            vTypeArr.set(1);
            //AppendRelease(ctx, vTypeArr);
            return vTypeArr;
        }

        static bool ReadJSValueAsUint8Array(JSContext* ctx, JSV jsVal, BYTEBUFFER& outBinary) {
            return ReadJSValueAsArrayBufferView(ctx, jsVal, "Uint8Array", outBinary);
        }
        static bool ReadJSValueAsUint16Array(JSContext* ctx, JSV jsVal, BYTEBUFFER& outBinary) {
            return ReadJSValueAsArrayBufferView(ctx, jsVal, "Uint16Array", outBinary);
        }
        static bool ReadJSValueAsUint32Array(JSContext* ctx, JSV jsVal, BYTEBUFFER& outBinary) {
            return ReadJSValueAsArrayBufferView(ctx, jsVal, "Uint32Array", outBinary);
        }
        static bool ReadJSValueAsInt8Array(JSContext* ctx, JSV jsVal, BYTEBUFFER& outBinary) {
            return ReadJSValueAsArrayBufferView(ctx, jsVal, "Int8Array", outBinary);
        }
        static bool ReadJSValueAsInt16Array(JSContext* ctx, JSV jsVal, BYTEBUFFER& outBinary) {
            return ReadJSValueAsArrayBufferView(ctx, jsVal, "Int16Array", outBinary);
        }
        static bool ReadJSValueAsInt32Array(JSContext* ctx, JSV jsVal, BYTEBUFFER& outBinary) {
            return ReadJSValueAsArrayBufferView(ctx, jsVal, "Int32Array", outBinary);
        }

        static bool ReadJSValueAsArrayBuffer(JSContext* ctx, JSV jsVal, BYTEBUFFER& outBinary) {
            outBinary.clear();

            if (!JS_IsObject(jsVal.get(0))) {
                return false;
            }

            JSValue constructor = JS_GetPropertyStr(ctx, jsVal.get(0), "constructor");
            if (JS_IsException(constructor)) {
                JS_FreeValue(ctx, constructor);
                return false;
            }

            JSValue constructorName = JS_GetPropertyStr(ctx, constructor, "name");
            if (JS_IsException(constructorName)) {
                JS_FreeValue(ctx, constructor);
                JS_FreeValue(ctx, constructorName);
                return false;
            }

            const char* name = JS_ToCString(ctx, constructorName);
            if (!name || strcmp(name, "ArrayBuffer") != 0) {
                if (name) JS_FreeCString(ctx, name);
                JS_FreeValue(ctx, constructor);
                JS_FreeValue(ctx, constructorName);
                return false;
            }
            JS_FreeCString(ctx, name);
            JS_FreeValue(ctx, constructor);
            JS_FreeValue(ctx, constructorName);

            JSValue arrayBuffer = jsVal.get(0);
            if (!JS_IsArrayBuffer(arrayBuffer)) {
                return false;
            }

            JSValue byteLengthVal = JS_GetPropertyStr(ctx, arrayBuffer, "byteLength");
            if (JS_IsException(byteLengthVal)) {
                JS_FreeValue(ctx, byteLengthVal);
                return false;
            }

            int64_t byteLength = 0;
            if (JS_ToInt64(ctx, &byteLength, byteLengthVal) != 0) {
                JS_FreeValue(ctx, byteLengthVal);
                return false;
            }

            if (byteLength < 0) {
                JS_FreeValue(ctx, byteLengthVal);
                return false;
            }

            size_t bufLen = 0;
            uint8_t* bufData = JS_GetArrayBuffer(ctx, &bufLen, arrayBuffer);
            if (bufData == nullptr) {
                JS_FreeValue(ctx, byteLengthVal);
                return true;
            }

            if ((size_t)byteLength > bufLen) {
                JS_FreeValue(ctx, byteLengthVal);
                return false;
            }

            if (byteLength > 0) {
                outBinary.resize((size_t)byteLength);
                memcpy(outBinary.data(), bufData, (size_t)byteLength);
            }

            JS_FreeValue(ctx, byteLengthVal);

            return true;
        }

        static bool ReadJSValueAsArrayBufferView(JSContext* ctx, JSV jsVal, BYTEBUFFER& outBinary) {
            if (ReadJSValueAsArrayBuffer(ctx, jsVal, outBinary) || ReadJSValueAsUint8Array(ctx, jsVal, outBinary) || ReadJSValueAsUint16Array(ctx, jsVal, outBinary) || ReadJSValueAsUint32Array(ctx, jsVal, outBinary)
                || ReadJSValueAsInt8Array(ctx, jsVal, outBinary) || ReadJSValueAsInt16Array(ctx, jsVal, outBinary) || ReadJSValueAsInt32Array(ctx, jsVal, outBinary)) return true;
            return false;
        }

        static JSV NewUint8Array(JSContext* ctx, const BYTEBUFFER& vec) {
            if (vec.empty()) {
                return JSV(ctx, JS_NewUint8Array(ctx, nullptr, 0, nullptr, nullptr, false)).cset(1);
            }

            size_t dataLen = vec.size();
            uint8_t* buf = (uint8_t*)malloc(dataLen);
            if (buf == nullptr) {
                return JSV(JS_EXCEPTION);
            }

            memcpy(buf, vec.data(), dataLen);

            JSValue uint8Arr = JS_NewUint8Array(
                ctx,
                buf,
                dataLen,
                [](JSRuntime* rt, void* opaque, void* data) {
                    if (data != nullptr) {
                        free(data);
                    }
                },
                nullptr,
                false
            );

            if (JS_IsException(uint8Arr)) {
                free(buf);
                return JSV(JS_EXCEPTION);
            }

            return JSV(ctx, uint8Arr).cset(1);
        }
        static JSV NewUint16Array(JSContext* ctx, const BYTEBUFFER& vec) {
            JSV buffer = NewArrayBuffer(ctx, vec);
            return CreateTypedArrayFromBuffer(ctx, buffer, "Uint16Array");
        }
        static JSV NewUint32Array(JSContext* ctx, const BYTEBUFFER& vec) {
            JSV buffer = NewArrayBuffer(ctx, vec);
            return CreateTypedArrayFromBuffer(ctx, buffer, "Uint32Array");
        }
        static JSV NewInt8Array(JSContext* ctx, const BYTEBUFFER& vec) {
            JSV buffer = NewArrayBuffer(ctx, vec);
            return CreateTypedArrayFromBuffer(ctx, buffer, "Int8Array");
        }
        static JSV NewInt16Array(JSContext* ctx, const BYTEBUFFER& vec) {
            JSV buffer = NewArrayBuffer(ctx, vec);
            return CreateTypedArrayFromBuffer(ctx, buffer, "Int16Array");
        }
        static JSV NewInt32Array(JSContext* ctx, const BYTEBUFFER& vec) {
            JSV buffer = NewArrayBuffer(ctx, vec);
            return CreateTypedArrayFromBuffer(ctx, buffer, "Int32Array");
        }

        static Promise NewPromise_deleted(JSContext* ctx) {
            JSMData* jsmdPtr = nullptr;
            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                return {};
            }

            JSV promise = NewObject(ctx);
            SetSymbolName(ctx, promise, "Promise");

            ULL id = GetNewPromiseId(ctx);

            JSV internal = NewObject(ctx, promise, "internal");
            SetAttribute(ctx, internal, "_isPrivate", NewBool(ctx, true), 0);
            SetAttribute(ctx, internal, "id", NewUint64(ctx, id), 0);

            JSV thenFunc = NewFunction(ctx, "then", [](JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) ->JSValue {
                JSV js_resolver;
                if (argumentCount >= 1 && JS_IsFunction(ctx, argumentValues[0])) {
                    js_resolver = JSV(ctx, argumentValues[0]).cget(1).cset(1);
                }
                JSV js_rejecter;
                if (argumentCount >= 2 && JS_IsFunction(ctx, argumentValues[1])) {
                    js_rejecter = JSV(ctx, argumentValues[1]).cget(1).cset(1);
                }

                JSV js_id = GetProperty(ctx, thisVal, { {"internal"}, {"id"} });
                ULL id = 0;
                ReadJSValueAsUint64(ctx, js_id, id);
                JSMData* jsmdPtr = nullptr;
                if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr || !jsmdPtr->promiseList.count(id)) {
                    JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                    return JS_EXCEPTION;
                }

                Promise newPromise = NewPromise(ctx);
                jsmdPtr->promiseList[id].callbacks.push_back({ js_resolver, js_rejecter, JSV(), newPromise, false });

                if (jsmdPtr->promiseList[id].state != PromiseState::PENDING) {
                    std::thread t([=]() {
                        if (!jsmdPtr->promiseList[id].callbacks.empty()) {
                            auto& callback = jsmdPtr->promiseList[id].callbacks.back();
                            if (jsmdPtr->promiseList[id].state == PromiseState::FULFILLED) {
                                if (callback.onFulfilled.isValid()) {
                                    std::vector<JSV> callArgs;
                                    if (!jsmdPtr->promiseList[id].result.empty()) {
                                        callArgs = jsmdPtr->promiseList[id].result;
                                    }
                                    JSV r = CallFunction(ctx, callback.onFulfilled, thisVal, callArgs);
                                    if (!jsmdPtr->promiseList[id].callbacks.empty()) {
                                        if (!JS_IsException(r.get(0))) {
                                            callback.returnPromise.Resolve(ctx, r);
                                        }
                                        else {
                                            callback.returnPromise.Reject(ctx, r);
                                        }
                                    }
                                }
                                else if (!jsmdPtr->promiseList[id].callbacks.empty()) {
                                    JSV resolveVal = JS_UNDEFINED;
                                    if (!jsmdPtr->promiseList[id].result.empty()) {
                                        resolveVal = jsmdPtr->promiseList[id].result[0];
                                    }
                                    callback.returnPromise.Resolve(ctx, resolveVal);
                                }
                            }
                            else if (jsmdPtr->promiseList[id].state == PromiseState::REJECTED) {
                                if (callback.onRejected.isValid()) {
                                    std::vector<JSV> callArgs;
                                    if (!jsmdPtr->promiseList[id].error.empty()) {
                                        callArgs = jsmdPtr->promiseList[id].error;
                                    }
                                    JSV r = CallFunction(ctx, callback.onRejected, thisVal, callArgs);
                                    if (!jsmdPtr->promiseList[id].callbacks.empty()) {
                                        if (!JS_IsException(r.get(0))) {
                                            callback.returnPromise.Resolve(ctx, r);
                                        }
                                        else {
                                            callback.returnPromise.Reject(ctx, r);
                                        }
                                    }
                                }
                                else if (!jsmdPtr->promiseList[id].callbacks.empty()) {
                                    JSV rejectVal = JS_UNDEFINED;
                                    if (!jsmdPtr->promiseList[id].error.empty()) {
                                        rejectVal = jsmdPtr->promiseList[id].error[0];
                                    }
                                    callback.returnPromise.Reject(ctx, rejectVal);
                                }
                            }
                        }
                        });
                    Thread td = std::move(t);
                    td.detach();
                    jsmdPtr->threadList.push_back(td);
                    update(ctx);
                }
                return newPromise.promise.get(1);
                });

            JSV catchFunc = NewFunction(ctx, "catch", [](JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) ->JSValue {
                JSV js_then = GetProperty(ctx, thisVal, "then");
                if (!JS_IsFunction(ctx, js_then.get(0))) {
                    JS_ThrowTypeError(ctx, "then is not a function");
                    return JS_EXCEPTION;
                }
                JSValueConst callArgs[] = { JS_UNDEFINED, argumentCount >= 1 && JS_IsFunction(ctx, argumentValues[0]) ? argumentValues[0] : JS_UNDEFINED };
                int argc = argumentCount >= 1 && JS_IsFunction(ctx, argumentValues[0]) ? 2 : 1;
                JSV ret = CallFunction(ctx, js_then, thisVal, argc, callArgs);
                return ret.get(1);
                });

            JSV finallyFunc = NewFunction(ctx, "finally", [](JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) ->JSValue {
                JSV js_callback;
                if (argumentCount >= 1 && JS_IsFunction(ctx, argumentValues[0])) {
                    js_callback = JSV(ctx, argumentValues[0]).cget(1).cset(1);
                }
                JSV js_id = GetProperty(ctx, thisVal, { {"internal"}, {"id"} });
                ULL id = 0;
                ReadJSValueAsUint64(ctx, js_id, id);
                JSMData* jsmdPtr = nullptr;
                if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr || !jsmdPtr->promiseList.count(id)) {
                    JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                    return JS_EXCEPTION;
                }
                Promise newPromise = NewPromise(ctx);
                jsmdPtr->promiseList[id].callbacks.push_back({ JSV(), JSV(), js_callback, newPromise, true });

                if (jsmdPtr->promiseList[id].state != PromiseState::PENDING) {
                    if (!jsmdPtr->promiseList[id].callbacks.empty()) {
                        auto& callback = jsmdPtr->promiseList[id].callbacks.back();
                        if (!callback.isFinally) {
                            if (!jsmdPtr->promiseList[id].callbacks.empty()) {
                                JSV resolveVal = JS_UNDEFINED;
                                JSV rejectVal = JS_UNDEFINED;
                                if (!jsmdPtr->promiseList[id].result.empty()) resolveVal = jsmdPtr->promiseList[id].result[0];
                                if (!jsmdPtr->promiseList[id].error.empty()) rejectVal = jsmdPtr->promiseList[id].error[0];

                                jsmdPtr->promiseList[id].state == PromiseState::FULFILLED
                                    ? callback.returnPromise.Resolve(ctx, resolveVal)
                                    : callback.returnPromise.Reject(ctx, rejectVal);
                            }
                            return newPromise.promise.get(1);
                        }
                        if (!callback.onFinally.isValid()) {
                            if (!jsmdPtr->promiseList[id].callbacks.empty()) {
                                JSV resolveVal = JS_UNDEFINED;
                                JSV rejectVal = JS_UNDEFINED;
                                if (!jsmdPtr->promiseList[id].result.empty()) resolveVal = jsmdPtr->promiseList[id].result[0];
                                if (!jsmdPtr->promiseList[id].error.empty()) rejectVal = jsmdPtr->promiseList[id].error[0];

                                jsmdPtr->promiseList[id].state == PromiseState::FULFILLED
                                    ? callback.returnPromise.Resolve(ctx, resolveVal)
                                    : callback.returnPromise.Reject(ctx, rejectVal);
                            }
                            return newPromise.promise.get(1);
                        }
                        JSV fr = CallFunction(ctx, callback.onFinally, thisVal, 0, nullptr);
                        if (JS_IsException(fr.get(0))) {
                            if (!jsmdPtr->promiseList[id].callbacks.empty()) {
                                callback.returnPromise.Reject(ctx, fr);
                            }
                            return newPromise.promise.get(1);
                        }
                        JSV js_then = GetProperty(ctx, fr, "then");
                        if (!JS_IsFunction(ctx, js_then.get(0))) {
                            if (!jsmdPtr->promiseList[id].callbacks.empty()) {
                                JSV resolveVal = JS_UNDEFINED;
                                JSV rejectVal = JS_UNDEFINED;
                                if (!jsmdPtr->promiseList[id].result.empty()) resolveVal = jsmdPtr->promiseList[id].result[0];
                                if (!jsmdPtr->promiseList[id].error.empty()) rejectVal = jsmdPtr->promiseList[id].error[0];

                                jsmdPtr->promiseList[id].state == PromiseState::FULFILLED
                                    ? callback.returnPromise.Resolve(ctx, resolveVal)
                                    : callback.returnPromise.Reject(ctx, rejectVal);
                            }
                            return newPromise.promise.get(1);
                        }
                        JSV wrapFunc = NewFunction(ctx, "wrap", [](JSContext* ctx, JSValueConst thisVal, int, JSValueConst*)->JSValue {
                            JSV js_id = GetProperty(ctx, thisVal, { {"internal"}, {"id"} });
                            ULL id = 0;
                            ReadJSValueAsUint64(ctx, js_id, id);
                            JSMData* jsmdPtr = nullptr;
                            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr || !jsmdPtr->promiseList.count(id)) {
                                JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                                return JS_EXCEPTION;
                            }
                            if (!jsmdPtr->promiseList[id].callbacks.empty()) {
                                auto& callback = jsmdPtr->promiseList[id].callbacks.back();
                                JSV resolveVal = JS_UNDEFINED;
                                JSV rejectVal = JS_UNDEFINED;
                                if (!jsmdPtr->promiseList[id].result.empty()) resolveVal = jsmdPtr->promiseList[id].result[0];
                                if (!jsmdPtr->promiseList[id].error.empty()) rejectVal = jsmdPtr->promiseList[id].error[0];

                                jsmdPtr->promiseList[id].state == PromiseState::FULFILLED
                                    ? callback.returnPromise.Resolve(ctx, resolveVal)
                                    : callback.returnPromise.Reject(ctx, rejectVal);
                            }
                            return JS_UNDEFINED;
                            });
                        JSV errFunc = NewFunction(ctx, "err", [](JSContext* ctx, JSValueConst thisVal, int argc, JSValueConst* argv)->JSValue {
                            JSV js_id = GetProperty(ctx, thisVal, { {"internal"}, {"id"} });
                            ULL id = 0;
                            ReadJSValueAsUint64(ctx, js_id, id);
                            JSMData* jsmdPtr = nullptr;
                            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr || !jsmdPtr->promiseList.count(id)) {
                                JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                                return JS_EXCEPTION;
                            }
                            if (!jsmdPtr->promiseList[id].callbacks.empty()) {
                                JSV rejectVal = JS_UNDEFINED;
                                if (argv && argc > 0) {
                                    rejectVal = JSV(ctx, argv[0]);
                                }
                                jsmdPtr->promiseList[id].callbacks.back().returnPromise.Reject(ctx, rejectVal);
                            }
                            return JS_UNDEFINED;
                            });
                        std::vector<JSV> thenArgs = { wrapFunc , errFunc };
                        CallFunction(ctx, js_then, fr, thenArgs);
                    }
                }
                return newPromise.promise.get(1);
                });

            JSV resolve = NewFunction(ctx, "resolve", [](JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) ->JSValue {
                JSV js_id = GetProperty(ctx, thisVal, { {"internal"}, {"id"} });
                ULL id = 0;
                ReadJSValueAsUint64(ctx, js_id, id);
                JSMData* jsmdPtr = nullptr;
                if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr || !jsmdPtr->promiseList.count(id)) {
                    JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                    return JS_EXCEPTION;
                }
                if (jsmdPtr->promiseList[id].isChanged) return JS_UNDEFINED;

                JSV x = argumentCount > 0 ? JSV(ctx, argumentValues[0]).cget(1).cset(1) : JSV(JS_UNDEFINED);
                if (IsSameValue(ctx, x, JSV(ctx, thisVal).cget(1).cset(1))) {
                    jsmdPtr->promiseList[id].isChanged = true;
                    jsmdPtr->promiseList[id].state = PromiseState::REJECTED;
                    jsmdPtr->promiseList[id].error = { JSV(ctx, JS_ThrowTypeError(ctx, "[Promise] Chaining cycle detected for promise")) };
                    auto cbs = std::move(jsmdPtr->promiseList[id].callbacks);
                    jsmdPtr->promiseList[id].callbacks.clear();
                    for (auto& cb : cbs) {
                        if (cb.isFinally) {
                            JSV fr = CallFunction(ctx, cb.onFinally, thisVal, 0, nullptr);
                            JSV rejectVal = JS_UNDEFINED;
                            if (!jsmdPtr->promiseList[id].error.empty()) {
                                rejectVal = jsmdPtr->promiseList[id].error[0];
                            }
                            JS_IsException(fr.get(0)) ? cb.returnPromise.Reject(ctx, fr) : cb.returnPromise.Reject(ctx, rejectVal);
                        }
                        else {
                            JSV rejectVal = JS_UNDEFINED;
                            if (!jsmdPtr->promiseList[id].error.empty()) {
                                rejectVal = jsmdPtr->promiseList[id].error[0];
                            }
                            cb.returnPromise.Reject(ctx, rejectVal);
                        }
                    }
                    return JS_EXCEPTION;
                }

                JSV js_then = GetProperty(ctx, x, "then");
                if (!JS_IsFunction(ctx, js_then.get(0))) {
                    jsmdPtr->promiseList[id].isChanged = true;
                    jsmdPtr->promiseList[id].state = PromiseState::FULFILLED;
                    jsmdPtr->promiseList[id].result = { x };
                    auto cbs = std::move(jsmdPtr->promiseList[id].callbacks);
                    jsmdPtr->promiseList[id].callbacks.clear();
                    for (auto& cb : cbs) {
                        if (cb.isFinally) {
                            JSV fr = CallFunction(ctx, cb.onFinally, thisVal, 0, nullptr);
                            JSV resolveVal = JS_UNDEFINED;
                            if (!jsmdPtr->promiseList[id].result.empty()) {
                                resolveVal = jsmdPtr->promiseList[id].result[0];
                            }
                            if (JS_IsException(fr.get(0))) {
                                cb.returnPromise.Reject(ctx, fr);
                            }
                            else {
                                cb.returnPromise.Resolve(ctx, resolveVal);
                            }
                        }
                        else if (cb.onFulfilled.isValid()) {
                            std::vector<JSV> callArgs;
                            if (!jsmdPtr->promiseList[id].result.empty()) {
                                callArgs = jsmdPtr->promiseList[id].result;
                            }
                            JSV r = CallFunction(ctx, cb.onFulfilled, thisVal, callArgs);
                            if (!JS_IsException(r.get(0))) {
                                cb.returnPromise.Resolve(ctx, r);
                            }
                            else {
                                cb.returnPromise.Reject(ctx, r);
                            }
                        }
                        else {
                            JSV resolveVal = JS_UNDEFINED;
                            if (!jsmdPtr->promiseList[id].result.empty()) {
                                resolveVal = jsmdPtr->promiseList[id].result[0];
                            }
                            cb.returnPromise.Resolve(ctx, resolveVal);
                        }
                    }
                    return JS_UNDEFINED;
                }

                JSV r = CallFunction(ctx, js_then, x, {
                    NewFunction(ctx, "resolve", [](JSContext* ctx, JSValueConst thisVal, int argc, JSValueConst* argv)->JSValue {
                        JSV js_id = GetProperty(ctx, thisVal, { {"internal"}, {"id"} });
                        ULL id = 0;
                        ReadJSValueAsUint64(ctx, js_id, id);
                        JSMData* jsmdPtr = nullptr;
                        if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr || !jsmdPtr->promiseList.count(id)) {
                            JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                            return JS_EXCEPTION;
                        }
                        if (jsmdPtr->promiseList[id].isChanged) return JS_UNDEFINED;
                        return CallFunction(ctx, jsmdPtr->promiseList[id].resolve, thisVal, argc, argv).get(1);
                    }, 0),
                    NewFunction(ctx, "reject", [](JSContext* ctx, JSValueConst thisVal, int argc, JSValueConst* argv)->JSValue {
                        JSV js_id = GetProperty(ctx, thisVal, { {"internal"}, {"id"} });
                        ULL id = 0;
                        ReadJSValueAsUint64(ctx, js_id, id);
                        JSMData* jsmdPtr = nullptr;
                        if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr || !jsmdPtr->promiseList.count(id)) {
                            JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                            return JS_EXCEPTION;
                        }
                        if (jsmdPtr->promiseList[id].isChanged) return JS_UNDEFINED;
                        return CallFunction(ctx, jsmdPtr->promiseList[id].reject, thisVal, argc, argv).get(1);
                    }, 0),
                    });

                if (!jsmdPtr->promiseList[id].isChanged) {
                    auto cbs = std::move(jsmdPtr->promiseList[id].callbacks);
                    jsmdPtr->promiseList[id].callbacks.clear();
                    jsmdPtr->promiseList[id].isChanged = true;

                    if (JS_IsException(r.get(0))) {
                        for (auto& cb : cbs) {
                            if (cb.isFinally) {
                                JSV fr = CallFunction(ctx, cb.onFinally, thisVal, 0, nullptr);
                                JS_IsException(fr.get(0)) ? cb.returnPromise.Reject(ctx, fr) : cb.returnPromise.Reject(ctx, r);
                            }
                            else {
                                cb.returnPromise.Reject(ctx, r);
                            }
                        }
                    }
                    else {
                        for (auto& cb : cbs) {
                            if (cb.isFinally) {
                                JSV fr = CallFunction(ctx, cb.onFinally, thisVal, 0, nullptr);
                                if (JS_IsException(fr.get(0))) {
                                    cb.returnPromise.Reject(ctx, fr);
                                }
                                else {
                                    cb.returnPromise.Resolve(ctx, r);
                                }
                            }
                            else if (cb.onFulfilled.isValid()) {
                                std::vector<JSV> callArgs;
                                if (r.isValid()) {
                                    callArgs.push_back(r);
                                }
                                JSV cb_r = CallFunction(ctx, cb.onFulfilled, thisVal, callArgs);
                                if (!JS_IsException(cb_r.get(0))) {
                                    cb.returnPromise.Resolve(ctx, cb_r);
                                }
                                else {
                                    cb.returnPromise.Reject(ctx, cb_r);
                                }
                            }
                            else {
                                cb.returnPromise.Resolve(ctx, r);
                            }
                        }
                    }
                }

                return JS_UNDEFINED;
                });

            JSV reject = NewFunction(ctx, "reject", [](JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) ->JSValue {
                JSV js_id = GetProperty(ctx, thisVal, { {"internal"}, {"id"} });
                ULL id = 0;
                ReadJSValueAsUint64(ctx, js_id, id);
                JSMData* jsmdPtr = nullptr;
                if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr || !jsmdPtr->promiseList.count(id)) {
                    JS_ThrowInternalError(ctx, "[native code] This context is invalid");
                    return JS_EXCEPTION;
                }
                if (jsmdPtr->promiseList[id].isChanged) return JS_UNDEFINED;
                jsmdPtr->promiseList[id].isChanged = true;
                jsmdPtr->promiseList[id].state = PromiseState::REJECTED;

                vector_lock<JSV> tempArgs = {};
                if (argumentCount > 0) {
                    tempArgs.push_back(JSV(ctx, argumentValues[0]).cget(1).cset(1));
                }
                else {
                    tempArgs.push_back(JSV(ctx, JS_UNDEFINED));
                }
                jsmdPtr->promiseList[id].error = tempArgs;

                auto cbs = std::move(jsmdPtr->promiseList[id].callbacks);
                jsmdPtr->promiseList[id].callbacks.clear();
                for (auto& cb : cbs) {
                    if (cb.isFinally) {
                        JSV fr = CallFunction(ctx, cb.onFinally, thisVal, 0, nullptr);
                        JSV rejectVal = JS_UNDEFINED;
                        if (!jsmdPtr->promiseList[id].error.empty()) {
                            rejectVal = jsmdPtr->promiseList[id].error[0];
                        }
                        if (JS_IsException(fr.get(0))) {
                            cb.returnPromise.Reject(ctx, fr);
                        }
                        else {
                            cb.returnPromise.Reject(ctx, rejectVal);
                        }
                    }
                    else if (cb.onRejected.isValid()) {
                        std::vector<JSV> callArgs;
                        if (!jsmdPtr->promiseList[id].error.empty()) {
                            callArgs = jsmdPtr->promiseList[id].error;
                        }
                        JSV r = CallFunction(ctx, cb.onRejected, thisVal, callArgs);
                        if (!JS_IsException(r.get(0))) {
                            cb.returnPromise.Resolve(ctx, r);
                        }
                        else {
                            cb.returnPromise.Reject(ctx, r);
                        }
                    }
                    else {
                        JSV rejectVal = JS_UNDEFINED;
                        if (!jsmdPtr->promiseList[id].error.empty()) {
                            rejectVal = jsmdPtr->promiseList[id].error[0];
                        }
                        cb.returnPromise.Reject(ctx, rejectVal);
                    }
                }
                return JS_UNDEFINED;
                });

            AppendMethod(ctx, promise, "then", thenFunc);
            AppendMethod(ctx, promise, "catch", catchFunc);
            AppendMethod(ctx, promise, "finally", finallyFunc);

            PromiseData pd = {};
            pd.promise = promise;
            pd.resolve = resolve;
            pd.reject = reject;
            pd.isValid = true;
            pd.state = PromiseState::PENDING;
            jsmdPtr->promiseList[id] = pd;

            Promise rp = {};
            rp.promise = promise;
            rp.resolve = resolve;
            rp.reject = reject;
            //rp.callResolve = [=](JSContext* ctx, std::vector<JSV> args) -> JSV {
            //    JSV ret = CallFunction(ctx, rp.resolve, promise, args, true, false);
            //    ULL id = 0;
            //    ReadJSValueAsUint64(ctx, ret, id);
            //    jsmdPtr->promiseList[id].callbackId = id;
            //    return ret;
            //    };
            //rp.callReject = [=](JSContext* ctx, std::vector<JSV> args)-> JSV {
            //    JSV ret = CallFunction(ctx, rp.reject, promise, args, true, false);
            //    ULL id = 0;
            //    ReadJSValueAsUint64(ctx, ret, id);
            //    jsmdPtr->promiseList[id].callbackId = id;
            //    return ret;
            //    };
            rp.Resolve = [=](JSContext* ctx, JSV arg)-> JSV {
                JSV ret = CallFunction(ctx, rp.resolve, promise, { arg }, true, false);
                ULL id = 0;
                ReadJSValueAsUint64(ctx, ret, id);
                jsmdPtr->promiseList[id].callbackId = id;
                return ret;
                };
            rp.Reject = [=](JSContext* ctx, JSV arg)-> JSV {
                JSV ret = CallFunction(ctx, rp.reject, promise, { arg }, true, false);
                ULL id = 0;
                ReadJSValueAsUint64(ctx, ret, id);
                jsmdPtr->promiseList[id].callbackId = id;
                return ret;
                };
            return rp;
        }
        static Promise NewPromise(JSContext* ctx) {
            JSValue res_rej[2];
            JSValue js_promise = JS_NewPromiseCapability(ctx, res_rej);
            JSV promise = JSV(ctx, js_promise).cset(1);
            JSV resolve = JSV(ctx, res_rej[0]).cset(1);
            JSV reject = JSV(ctx, res_rej[1]).cset(1);
            Promise ret = {};
            ret.promise = promise;
            ret.resolve = resolve;
            ret.reject = reject;
            ret.Resolve = [=](JSContext* ctx, JSV arg)->void {
                CallFunction(ctx, resolve, promise, { arg }, true, false);
                };
            ret.Reject = [=](JSContext* ctx, JSV arg)->void {
                CallFunction(ctx, reject, promise, { arg }, true, false);
                };
            return ret;
        }

        static std::string ToString(JSContext* ctx, JSV vName) {
            std::string name = "";
            JSValue val = vName.get(0);

            if (JS_IsArray(val)) {
                std::vector<JSV> array;
                if (!ReadJSValueAsArray(ctx, vName, array)) {
                    return "";
                }
                if (array.empty()) {
                    return "";
                }
                for (size_t i = 0; i < array.size(); ++i) {
                    std::string itemStr = ToString(ctx, array[i]);
                    if (i > 0) {
                        name += ",";
                    }
                    name += itemStr;
                }
            }
            else if (JS_IsString(val)) {
                if (!ReadJSValueAsString(ctx, vName, name)) {
                    name = "";
                }
            }
            else if (JS_IsBool(val)) {
                bool boolVal = false;
                if (ReadJSValueAsBool(ctx, vName, boolVal)) {
                    name = boolVal ? "true" : "false";
                }
                else {
                    name = "";
                }
            }
            else if (JS_IsUndefined(val)) {
                name = "undefined";
            }
            else if (JS_IsNull(val)) {
                name = "null";
            }
            else if (JS_IsNumber(val) || JS_IsBigInt(val)) {
                uint64_t numVal = 0;
                double doubleVal = 0.0;
                bool retu = ReadJSValueAsUint64(ctx, vName, numVal);
                bool retd = ReadJSValueAsDouble(ctx, vName, doubleVal);

                if (!retu && !retd) {
                    name = "";
                }
                else {
                    if (!retd) {
                        doubleVal = static_cast<double>(numVal);
                    }

                    if (std::isnan(doubleVal)) {
                        name = "NaN";
                    }
                    else if (std::isinf(doubleVal)) {
                        name = doubleVal > 0 ? "Infinity" : "-Infinity";
                    }
                    else {
                        name = std::to_string(doubleVal);
                        if (name.find(".0") == name.length() - 2) {
                            name = name.substr(0, name.length() - 2);
                        }
                    }
                }
            }
            else {
                name = GetFullPrototypeName(ctx, val);
            }

            return name;
        }
        static BYTEBUFFER ToValue(JSContext* ctx, JSV vName) {
            BYTEBUFFER binary = {};
            JSValue val = vName.get(0);
            if (ReadJSValueAsArrayBufferView(ctx, vName, binary)) {
                return binary;
            }
            else if (GetSymbolName(ctx, vName) == "Blob") {
                JSV js_data = GetProperty(ctx, vName, { {"internal"}, {"data"} });
                if (js_data.isValid()) ReadJSValueAsArrayBuffer(ctx, js_data, binary);
            }
            else if (JS_IsArray(val)) {
                std::vector<JSV> array = {};
                if (ReadJSValueAsArray(ctx, vName, array)) {
                    std::string arrStr = "";
                    for (size_t i = 0; i < array.size(); ++i) {
                        std::string itemStr = ToString(ctx, array[i]);
                        if (i > 0) {
                            arrStr += ",";
                        }
                        arrStr += itemStr;
                    }
                    binary = ToBinary(arrStr);
                }
            }
            else if (JS_IsNumber(val) || JS_IsBigInt(val)) {
                std::string numStr = "";
                uint64_t numVal = 0;
                double doubleVal = 0.0;
                bool retu = ReadJSValueAsUint64(ctx, vName, numVal);
                bool retd = ReadJSValueAsDouble(ctx, vName, doubleVal);

                if (!retu && !retd) {
                    numStr = "";
                }
                else {
                    if (!retd) {
                        doubleVal = static_cast<double>(numVal);
                    }

                    if (std::isnan(doubleVal)) {
                        numStr = "NaN";
                    }
                    else if (std::isinf(doubleVal)) {
                        numStr = doubleVal > 0 ? "Infinity" : "-Infinity";
                    }
                    else {
                        numStr = std::to_string(doubleVal);
                        if (numStr.find(".0") == numStr.length() - 2) {
                            numStr = numStr.substr(0, numStr.length() - 2);
                        }
                    }
                }
                binary = ToBinary(numStr);
            }
            else if (JS_IsString(val)) {
                std::string strVal = "";
                if (ReadJSValueAsString(ctx, vName, strVal)) {
                    binary = ToBinary(strVal);
                }
            }
            else if (JS_IsBool(val)) {
                bool boolVal = false;
                if (ReadJSValueAsBool(ctx, vName, boolVal)) {
                    binary = ToBinary(boolVal ? "true" : "false");
                }
            }
            else if (JS_IsUndefined(val)) {
                binary = ToBinary("undefined");
            }
            else if (JS_IsNull(val)) {
                binary = ToBinary("null");
            }
            else {
                std::string protoName = GetFullPrototypeName(ctx, val);
                binary = ToBinary(protoName);
            }

            return binary;
        }
        static BYTEBUFFER ToAdvValue(JSContext* ctx, JSV vName) {
            BYTEBUFFER binary = {};
            JSValue val = vName.get(0);

            if (JS_IsObject(val)) {
                OBJECT obj = {};
                if (ReadJSValueAsObject(ctx, vName, obj)) {
                    try {
                        std::wstring jsonStr = JSON.stringify(obj);
                        binary = ToBinary(jsonStr);
                        return binary;
                    }
                    catch (...) {
                    }
                }
            }

            binary = ToValue(ctx, vName);
            return binary;
        }

        static JSV CallFunction(JSContext* ctx, JSV func, JSV thisVal, std::vector<JSV> args, bool isAsync = false, bool isWait = true) {
            std::vector<JSValue> jsArgs = {};
            jsArgs.reserve(args.size());
            for (const auto& jsv : args) jsArgs.push_back(jsv.get(0));
            JSV result = JSV();
            if (isAsync) {
                ULL id = AddTask(ctx, func, thisVal, args, thisVal);
                if (isWait) waitTask(ctx, id);
                if (isWait) result = queryTask(ctx, id).ret;
                if (isWait) deleteTask(ctx, id);
                if (!isWait) result = NewUint64(ctx, id);
            }
            else result = JSV(ctx, JS_Call(ctx, func.get(0), thisVal.get(0), static_cast<int>(jsArgs.size()), jsArgs.data())).cset(1);
            return result;
        }
        static JSV CallFunction(JSContext* ctx, JSV func, JSV thisVal, int argc, JSValueConst* argv, bool isAsync = false, bool isWait = true) {
            JSValue funcVal = func.get(0);
            if (JS_IsUndefined(funcVal) || JS_IsNull(funcVal) || !JS_IsFunction(ctx, funcVal)) {
                return JSV(JS_UNDEFINED);
            }
            JSV result = JSV();
            if (isAsync) {
                std::vector<JSV> args = {};
                for (int i = 0; i < argc; i++) {
                    args.push_back(JSV(ctx, argv[i]).cget(1).cset(1));
                }
                ULL id = AddTask(ctx, func, thisVal, args, thisVal);
                if (isWait) waitTask(ctx, id);
                if (isWait) result = queryTask(ctx, id).ret;
                if (isWait) deleteTask(ctx, id);
                if (!isWait) result = NewUint64(ctx, id);
            }
            else result = JSV(ctx, JS_Call(ctx, funcVal, thisVal.get(0), argc, argv)).cset(1);
            return result;
        }
        static JSV CallConstructor(JSContext* ctx, JSV func, std::vector<JSV> args) {
            std::vector<JSValue> jsArgs = {};
            jsArgs.reserve(args.size());
            for (const auto& jsv : args) jsArgs.push_back(jsv.get(0));
            return JSV(ctx, JS_CallConstructor(ctx, func.get(0), static_cast<int>(jsArgs.size()), jsArgs.data())).cset(1);
        }
        static JSV CallConstructor(JSContext* ctx, JSV func, int argc, JSValueConst* argv) {
            JSValue funcVal = func.get(0);
            if (JS_IsUndefined(funcVal) || JS_IsNull(funcVal) || !JS_IsFunction(ctx, funcVal)) {
                return JSV(JS_UNDEFINED);
            }
            return JSV(ctx, JS_CallConstructor(ctx, funcVal, argc, argv)).cset(1);
        }

        static bool CopyObject(JSContext* ctx, JSV originJsv, JSV targetJsv) {

            JSPropertyEnum* prop_tab = NULL;
            uint32_t prop_len = 0;
            const uint32_t JS_GPN_ALL = JS_GPN_STRING_MASK | JS_GPN_SYMBOL_MASK | JS_GPN_SET_ENUM;

            auto cleanup = [&]() {
                if (prop_tab) {
                    js_free(ctx, prop_tab);
                    prop_tab = NULL;
                }
                };

            if (JS_IsException(originJsv.get(0)) || JS_IsException(targetJsv.get(0))) {
                cleanup();
                return false;
            }
            if (!JS_IsObject(originJsv.get(0)) || JS_IsNull(originJsv.get(0)) ||
                !JS_IsObject(targetJsv.get(0)) || JS_IsNull(targetJsv.get(0))) {
                cleanup();
                return false;
            }

            if (JS_GetOwnPropertyNames(ctx, &prop_tab, &prop_len, targetJsv.get(0), JS_GPN_ALL) == 0) {
                for (uint32_t i = 0; i < prop_len; i++) {
                    JSPropertyEnum* prop = &prop_tab[i];
                    JS_DeleteProperty(ctx, targetJsv.get(0), prop->atom, 0);
                }
                js_free(ctx, prop_tab);
                prop_tab = NULL;
                prop_len = 0;
            }

            if (JS_IsArray(originJsv.get(0))) {
                JSV js_length = GetProperty(ctx, originJsv, "length");
                uint64_t length64 = 0;
                if (!ReadJSValueAsUint64(ctx, js_length, length64)) {
                    cleanup();
                    return false;
                }
                uint32_t length = static_cast<uint32_t>(length64);

                for (uint32_t i = 0; i < length; i++) {
                    JSV originItem = GetProperty(ctx, originJsv, NewUint64(ctx, i));
                    if (JS_IsException(originItem.get(0))) {
                        continue;
                    }

                    JSV newItem;
                    if (!JS_IsObject(originItem.get(0)) || JS_IsNull(originItem.get(0))) {
                        JSValue dupVal = JS_DupValue(ctx, originItem.get(0));
                        newItem = JSV(ctx, &dupVal).cset(1);
                    }
                    else {
                        JSValue newVal = JS_IsArray(originItem.get(0)) ? JS_NewArray(ctx) : JS_NewObject(ctx);
                        if (JS_IsException(newVal)) {
                            continue;
                        }
                        JSV tempTarget = JSV(ctx, &newVal).cset(1);
                        CopyObject(ctx, originItem, tempTarget);
                        newItem = tempTarget;
                    }
                    SetAttribute(ctx, targetJsv, NewUint64(ctx, i), newItem);
                }
                cleanup();
                return true;
            }
            if (JS_GetOwnPropertyNames(ctx, &prop_tab, &prop_len, originJsv.get(0), JS_GPN_ALL) == 0) {
                for (uint32_t i = 0; i < prop_len; i++) {
                    JSPropertyEnum* prop = &prop_tab[i];
                    JSValue jsKey = JS_AtomToValue(ctx, prop->atom);
                    JSV keyJsv = JSV(ctx, &jsKey).cset(1);
                    JSValue jsValue = JS_GetProperty(ctx, originJsv.get(0), prop->atom);
                    JSV originPropVal = JSV(ctx, &jsValue).cset(1);

                    JSV newPropVal;
                    if (!JS_IsObject(originPropVal.get(0)) || JS_IsNull(originPropVal.get(0))) {
                        JSValue dupVal = JS_DupValue(ctx, originPropVal.get(0));
                        newPropVal = JSV(ctx, &dupVal).cset(1);
                    }
                    else {
                        JSValue newVal = JS_IsArray(originPropVal.get(0)) ? JS_NewArray(ctx) : JS_NewObject(ctx);
                        if (JS_IsException(newVal)) {
                            continue;
                        }
                        JSV tempTarget = JSV(ctx, &newVal).cset(1);
                        CopyObject(ctx, originPropVal, tempTarget);
                        newPropVal = tempTarget;
                    }
                    SetAttribute(ctx, targetJsv, keyJsv, newPropVal);
                }
            }
            cleanup();
            return true;
        }
        static bool ModifyJSValue(JSContext* ctx, JSV originJsv, JSV targetJsv) {
            JSValue targetBuffer = JS_UNDEFINED;
            JSValue originBuffer = JS_UNDEFINED;

            auto cleanup = [&]() {
                JS_FreeValue(ctx, targetBuffer);
                JS_FreeValue(ctx, originBuffer);
                };

            if (JS_IsException(originJsv.get(0)) || JS_IsException(targetJsv.get(0))) {
                cleanup();
                return false;
            }
            if (!JS_IsObject(originJsv.get(0)) || !JS_IsObject(targetJsv.get(0))) {
                cleanup();
                return false;
            }

            bool isHandled = false;

            targetBuffer = JS_GetPropertyStr(ctx, targetJsv.get(0), "buffer");
            if (!JS_IsException(targetBuffer) && JS_IsArrayBuffer(targetBuffer)) {
                size_t targetLen = 0;
                uint8_t* targetData = JS_GetArrayBuffer(ctx, &targetLen, targetBuffer);
                if (!(targetData != nullptr && targetLen > 0)) {
                    cleanup();
                    return false;
                }
                originBuffer = JS_GetPropertyStr(ctx, originJsv.get(0), "buffer");
                if (JS_IsException(originBuffer) || !JS_IsArrayBuffer(originBuffer)) {
                    cleanup();
                    return false;
                }

                size_t originLen = 0;
                uint8_t* originData = JS_GetArrayBuffer(ctx, &originLen, originBuffer);
                if (originData != nullptr && originLen >= targetLen) {
                    memcpy(originData, targetData, targetLen);
                    isHandled = true;
                }
                else {
                    cleanup();
                    return false;
                }
            }
            if (!isHandled && JS_IsArrayBuffer(targetJsv.get(0))) {
                size_t targetLen = 0;
                uint8_t* targetData = JS_GetArrayBuffer(ctx, &targetLen, targetJsv.get(0));
                if (!(targetData != nullptr && targetLen > 0)) {
                    cleanup();
                    return false;
                }
                if (!JS_IsArrayBuffer(originJsv.get(0))) {
                    cleanup();
                    return false;
                }

                size_t originLen = 0;
                uint8_t* originData = JS_GetArrayBuffer(ctx, &originLen, originJsv.get(0));
                if (originData != nullptr && originLen >= targetLen) {
                    memcpy(originData, targetData, targetLen);
                    isHandled = true;
                }
                else {
                    cleanup();
                    return false;
                }
            }
            if (!isHandled) {
                isHandled = true;
            }
            cleanup();
            return isHandled;
        }
        static bool IsArrowFunction(JSContext* ctx, JSV func) {
            if (!JS_IsFunction(ctx, func.get(0))) {
                return false;
            }
            JSValue toString = JS_GetPropertyStr(ctx, func.get(0), "toString");
            if (JS_IsException(toString)) {
                JS_FreeValue(ctx, toString);
                return false;
            }
            JSValue str_val = JS_Call(ctx, toString, func.get(0), 0, NULL);
            JS_FreeValue(ctx, toString);
            if (JS_IsException(str_val)) {
                JS_FreeValue(ctx, str_val);
                return 0;
            }
            const char* func_str = JS_ToCString(ctx, str_val);
            bool is_arrow = 0;
            if (func_str) {
                if (strncmp(func_str, "function", 8) != 0) {
                    is_arrow = true;
                }
                JS_FreeCString(ctx, func_str);
            }
            JS_FreeValue(ctx, str_val);
            return is_arrow;
        }
        static std::string GetInvalidTypeString(JSV obj) {
            JSValue object = obj.get(0);
            if (JS_IsUndefined(object)) return "undefined";
            else if (JS_IsNull(object)) return "null";
            else if (JS_IsException(object)) return "exception";
            return "";
        }
        static std::string GetTypeString(JSContext* ctx, JSV obj) {
            JSValue object = obj.get(0);
            if (JS_IsUndefined(object)) return "undefined";
            else if (JS_IsNull(object)) return "null";
            else if (JS_IsException(object)) return "exception";
            return GetPrototypeName(ctx, object);
        }

        static bool IsSameValue(JSContext* ctx, JSV obj1, JSV obj2) {
            return JS_IsSameValue(ctx, obj1.get(0), obj2.get(0));
        }

        static ULL AddTask(JSContext* ctx, JSV task, JSV thisVal, std::vector<JSV> args, JSV flags = {}) {
            JSMData* jsmdPtr = nullptr;
            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) return 0;
            ULL id = GetNewTaskId(ctx);
            Task t = {};
            t.task = task;
            t.thisVal = thisVal;
            t.args = args;
            t.flags = flags;
            jsmdPtr->taskList[id] = t;
            return id;
        }
        static bool waitTask(JSContext* ctx, ULL id) {
            JSMData* jsmdPtr = nullptr;
            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr || !jsmdPtr->taskList.count(id)) {
                return false;
            }
            while (!jsmdPtr->isQuit && !isQuit) {
                if (jsmdPtr->runnedTaskList.count(id)) {
                    break;
                }
                AdvSleep(1);
            }
            return true;
        }
        static TaskData queryTask(JSContext* ctx, ULL id) {
            JSMData* jsmdPtr = nullptr;
            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                return {};
            }
            if (jsmdPtr->runnedTaskList.count(id)) return jsmdPtr->runnedTaskList[id];
            else return {};
        }
        static bool deleteTask(JSContext* ctx, ULL id) {
            JSMData* jsmdPtr = nullptr;
            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr || !jsmdPtr->taskList.count(id)) {
                return false;
            }
            return jsmdPtr->taskList.erase(id) || jsmdPtr->runnedTaskList.erase(id);
        }
        static void RunTask(JSContext* ctx) {

            JSMData* jsmdPtr = nullptr;
            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                return;
            }

            if (jsmdPtr->isRunningTask) return;
            jsmdPtr->isRunningTask = true;

            JSRuntime* rt = JS_GetRuntime(ctx);
            while ((((JS_IsJobPending(rt) || !jsmdPtr->taskList.empty()) || !jsmdPtr->threadList.empty()) && !jsmdPtr->isQuit) && !isQuit) {

                if (!jsmdPtr->threadList.empty() && (!JS_IsJobPending(rt) && jsmdPtr->taskList.empty())) {
                    update(ctx);
                    AdvSleep(1.0);
                    continue;
                }

                if (jsmdPtr->threadList.empty() && (!JS_IsJobPending(rt) && jsmdPtr->taskList.empty())) break;

                JSContext* ctx_unused = nullptr;
                JS_ExecutePendingJob(rt, &ctx_unused);

                auto it = jsmdPtr->taskList.begin();
                if (it == jsmdPtr->taskList.end()) {
                    continue;
                }
                ULL id = it->first;
                Task task = it->second;

                JSV ret = CallFunction(ctx, task.task, task.thisVal, task.args);

                TaskData td = {};
                td.isValid = true;
                td.task = task;
                td.ret = ret;
                jsmdPtr->runnedTaskList[id] = td;

                jsmdPtr->taskList.erase(it);

                update(ctx);
            }

            jsmdPtr->isRunningTask = false;

        }

        static ULL GetCJSValue(JSContext* ctx, JSV jsv) {
            JSMData* jsmdPtr = nullptr;
            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) return 0;
            ULL id = GetNewCJSValueId(ctx);
            jsmdPtr->hModuleCJSValueList[id] = jsv;
            return id;
        }
        static ULL GetNewFileControllerId(JSContext* ctx) {
            JSMData* jsmdPtr = nullptr;
            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) return 0;
            static ULL counter = 0;
            return GetNewIdGeneric(ctx, jsmdPtr->fileControllerList, counter);
        }
        static ULL GetNewExecuteJsId(JSContext* ctx) {
            JSMData* jsmdPtr = nullptr;
            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) return 0;
            static ULL counter = 0;
            return GetNewIdGeneric(ctx, jsmdPtr->executeJsList, counter);
        }
        static ULL GetNewFormDataId(JSContext* ctx) {
            JSMData* jsmdPtr = nullptr;
            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) return 0;
            static ULL counter = 0;
            return GetNewIdGeneric(ctx, jsmdPtr->formDataList, counter);
        }
        static ULL GetNewNetworkHttpId(JSContext* ctx) {
            JSMData* jsmdPtr = nullptr;
            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) return 0;
            static ULL counter = 0;
            return GetNewIdGeneric(ctx, jsmdPtr->networkHttpList, counter);
        }
        static ULL GetNewTimeoutId(JSContext* ctx) {
            JSMData* jsmdPtr = nullptr;
            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) return 0;
            static ULL counter = 0;
            return GetNewIdGeneric(ctx, jsmdPtr->timeoutList, counter);
        }
        static ULL GetNewPromiseId(JSContext* ctx) {
            JSMData* jsmdPtr = nullptr;
            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) return 0;
            static ULL counter = 0;
            return GetNewIdGeneric(ctx, jsmdPtr->promiseList, counter);
        }
        static ULL GetNewTaskId(JSContext* ctx) {
            JSMData* jsmdPtr = nullptr;
            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) return 0;
            static ULL counter = 0;
            return GetNewIdGeneric(ctx, jsmdPtr->taskList, counter);
        }
        static ULL GetNewCJSValueId(JSContext* ctx) {
            JSMData* jsmdPtr = nullptr;
            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) return 0;
            static ULL counter = 0;
            return GetNewIdGeneric(ctx, jsmdPtr->hModuleCJSValueList, counter);
        }
        static ULL GetNewArgumentPackageId(JSContext* ctx) {
            JSMData* jsmdPtr = nullptr;
            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) return 0;
            static ULL counter = 0;
            return GetNewIdGeneric(ctx, jsmdPtr->argumentPackageList, counter);
        }
        static ULL GetNewCJSByteId(JSContext* ctx) {
            JSMData* jsmdPtr = nullptr;
            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) return 0;
            static ULL counter = 0;
            return GetNewIdGeneric(ctx, jsmdPtr->cjsByteDataList, counter);
        }

    private:

        static BYTEBUFFER crypto_getRandomValues_core(size_t length) {
            if (length == 0) {
                return {};
            }
            BYTEBUFFER randomBuffer(length);
            NTSTATUS status = BCryptGenRandom(
                nullptr,
                reinterpret_cast<PUCHAR>(randomBuffer.data()),
                static_cast<ULONG>(length),
                BCRYPT_USE_SYSTEM_PREFERRED_RNG
            );
            if (!BCRYPT_SUCCESS(status)) {
                return {};
            }
            return randomBuffer;
        }

        static bool crypto_subtle_digest_core(std::string hash, BYTEBUFFER_PTR inBinary, BYTEBUFFER_PTR outBinary) {
            if (!inBinary || !outBinary) return false;
            outBinary->clear();
            const unsigned char* data = inBinary->data();
            size_t len = inBinary->size();
            try {
                if (hash == "SHA-1") {
                    CryptoPP::SHA1 sha;
                    outBinary->resize(sha.DigestSize());
                    sha.CalculateDigest(outBinary->data(), data, len);
                }
                else if (hash == "SHA-224") {
                    CryptoPP::SHA224 sha;
                    outBinary->resize(sha.DigestSize());
                    sha.CalculateDigest(outBinary->data(), data, len);
                }
                else if (hash == "SHA-256") {
                    CryptoPP::SHA256 sha;
                    outBinary->resize(sha.DigestSize());
                    sha.CalculateDigest(outBinary->data(), data, len);
                }
                else if (hash == "SHA-384") {
                    CryptoPP::SHA384 sha;
                    outBinary->resize(sha.DigestSize());
                    sha.CalculateDigest(outBinary->data(), data, len);
                }
                else if (hash == "SHA-512") {
                    CryptoPP::SHA512 sha;
                    outBinary->resize(sha.DigestSize());
                    sha.CalculateDigest(outBinary->data(), data, len);
                }
                else if (hash == "SHA-3-224") {
                    CryptoPP::SHA3_224 sha;
                    outBinary->resize(sha.DigestSize());
                    sha.CalculateDigest(outBinary->data(), data, len);
                }
                else if (hash == "SHA-3-256") {
                    CryptoPP::SHA3_256 sha;
                    outBinary->resize(sha.DigestSize());
                    sha.CalculateDigest(outBinary->data(), data, len);
                }
                else if (hash == "SHA-3-384") {
                    CryptoPP::SHA3_384 sha;
                    outBinary->resize(sha.DigestSize());
                    sha.CalculateDigest(outBinary->data(), data, len);
                }
                else if (hash == "SHA-3-512") {
                    CryptoPP::SHA3_512 sha;
                    outBinary->resize(sha.DigestSize());
                    sha.CalculateDigest(outBinary->data(), data, len);
                }
                else if (hash == "SHA-512/224") {
                    CryptoPP::SHA512 sha;
                    outBinary->resize(28);
                    byte temp[64];
                    sha.CalculateDigest(temp, data, len);
                    memcpy(outBinary->data(), temp, 28);
                }
                else if (hash == "SHA-512/256") {
                    CryptoPP::SHA512 sha;
                    outBinary->resize(32);
                    byte temp[64];
                    sha.CalculateDigest(temp, data, len);
                    memcpy(outBinary->data(), temp, 32);
                }
                else {
                    return false;
                }
                return true;
            }
            catch (...) {
                outBinary->clear();
                return false;
            }
        }

        static bool crypto_subtle_generateKey_core(std::string algo, uint64_t length, BYTEBUFFER_PTR outBinary, ...)
        {
            if (outBinary == nullptr) {
                return false;
            }
            outBinary->clear();

            std::string curve = "P-256";
            std::string padding = "PKCS1";
            uint64_t publicExponent = 65537;
            std::string hashName = "SHA-256";
            std::string mode = "GCM";
            BYTEBUFFER_PTR privateKey = nullptr;

            va_list args;
            va_start(args, outBinary);
            try {
                while (true) {
                    const char* param = va_arg(args, const char*);
                    if (param == nullptr) break;

                    std::string paramStr = param;
                    size_t eqPos = paramStr.find('=');
                    if (eqPos == std::string::npos || eqPos == paramStr.length() - 1) {
                        continue;
                    }

                    std::string key = paramStr.substr(0, eqPos);
                    std::string value = paramStr.substr(eqPos + 1);

                    if (value.empty()) continue;

                    if (key == "curve") curve = value;
                    else if (key == "padding") padding = value;
                    else if (key == "publicExponent") {
                        try {
                            publicExponent = std::stoull(value);
                        }
                        catch (...) {
                            publicExponent = 65537;
                        }
                    }
                    else if (key == "hash") hashName = value;
                    else if (key == "mode") mode = value;
                }
                privateKey = static_cast<BYTEBUFFER_PTR>(va_arg(args, void*));
            }
            catch (...) {
                va_end(args);
                return false;
            }
            va_end(args);

            static CryptoPP::AutoSeededRandomPool rng;

            if (algo.find("AES") != std::string::npos) {
                const size_t keySizeBytes = static_cast<size_t>(length / 8);
                if (keySizeBytes < 16 || keySizeBytes > 64 || (keySizeBytes % 8) != 0) {
                    return false;
                }

                outBinary->resize(keySizeBytes);
                rng.GenerateBlock(outBinary->data(), keySizeBytes);
                return !outBinary->empty() && outBinary->size() == keySizeBytes;
            }
            else if (algo.find("HMAC") != std::string::npos) {
                if (length < 8 || length > 4096) {
                    return false;
                }
                const size_t keySizeBytes = static_cast<size_t>(length / 8);

                outBinary->resize(keySizeBytes);
                rng.GenerateBlock(outBinary->data(), keySizeBytes);
                return !outBinary->empty() && outBinary->size() == keySizeBytes;
            }
            else if (algo == "Ed25519" || algo == "EdDSA") {
                unsigned char sk[32] = { 0 };
                unsigned char pk[32] = { 0 };

                try {
                    rng.GenerateBlock(sk, 32);

                    CryptoPP::ed25519Signer signer(sk);
                    CryptoPP::ByteQueue pubQueue;
                    signer.AccessKey().Save(pubQueue);

                    size_t pubSize = static_cast<size_t>(pubQueue.MaxRetrievable());
                    if (pubSize >= 32) {
                        pubQueue.Skip(pubSize - 32);
                        pubQueue.Get(pk, 32);
                    }
                    else {
                        return false;
                    }

                    outBinary->assign(pk, pk + 32);
                    if (privateKey != nullptr) {
                        privateKey->clear();
                        privateKey->assign(sk, sk + 32);
                    }
                    return !outBinary->empty() && outBinary->size() == 32;
                }
                catch (...) {
                    outBinary->clear();
                    if (privateKey != nullptr) privateKey->clear();
                    return false;
                }
            }
            else if (algo == "X25519" || algo == "XDH") {
                unsigned char sk[32] = { 0 };
                unsigned char pk[32] = { 0 };

                try {
                    rng.GenerateBlock(sk, 32);
                    CryptoPP::x25519 x25519Key;
                    x25519Key.GeneratePublicKey(rng, sk, pk);

                    outBinary->assign(pk, pk + 32);
                    if (privateKey != nullptr) {
                        privateKey->clear();
                        privateKey->assign(sk, sk + 32);
                    }
                    return !outBinary->empty() && outBinary->size() == 32;
                }
                catch (...) {
                    outBinary->clear();
                    if (privateKey != nullptr) privateKey->clear();
                    return false;
                }
            }
            else if (algo.find("RSA") != std::string::npos) {
                if (length < 1024 || length > 16384 || (length % 8) != 0) {
                    return false;
                }
                if (publicExponent < 3 || (publicExponent % 2) == 0) {
                    return false;
                }
                if (padding != "PKCS1" && padding != "OAEP" && padding != "PSS") {
                    return false;
                }

                try {
                    CryptoPP::InvertibleRSAFunction rsaPrivKey;
                    rsaPrivKey.Initialize(rng, static_cast<unsigned int>(length),
                        static_cast<CryptoPP::Integer>(static_cast<long>(publicExponent)));

                    CryptoPP::RSAFunction rsaPubKey;
                    rsaPubKey.Initialize(rsaPrivKey.GetModulus(), rsaPrivKey.GetPublicExponent());

                    CryptoPP::ByteQueue pubQueue;
                    rsaPubKey.Save(pubQueue);
                    outBinary->resize(static_cast<size_t>(pubQueue.MaxRetrievable()));
                    pubQueue.Get(outBinary->data(), outBinary->size());

                    if (privateKey != nullptr) {
                        privateKey->clear();
                        CryptoPP::ByteQueue privQueue;
                        rsaPrivKey.Save(privQueue);
                        privateKey->resize(static_cast<size_t>(privQueue.MaxRetrievable()));
                        privQueue.Get(privateKey->data(), privateKey->size());
                    }
                    return !outBinary->empty() && (privateKey == nullptr || !privateKey->empty());
                }
                catch (...) {
                    outBinary->clear();
                    if (privateKey != nullptr) privateKey->clear();
                    return false;
                }
            }

            else if (algo == "ECDSA" || algo == "ECDH") {
                CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> ecParams;
                bool curveValid = false;
                if (curve == "P-256") { ecParams.Initialize(CryptoPP::ASN1::secp256r1()); curveValid = true; }
                else if (curve == "P-384") { ecParams.Initialize(CryptoPP::ASN1::secp384r1()); curveValid = true; }
                else if (curve == "P-521") { ecParams.Initialize(CryptoPP::ASN1::secp521r1()); curveValid = true; }
                else if (curve == "secp256k1") { ecParams.Initialize(CryptoPP::ASN1::secp256k1()); curveValid = true; }
                else if (curve == "P-192") { ecParams.Initialize(CryptoPP::ASN1::secp192r1()); curveValid = true; }
                else if (curve == "secp192k1") { ecParams.Initialize(CryptoPP::ASN1::secp192k1()); curveValid = true; }
                else if (curve == "secp224r1") { ecParams.Initialize(CryptoPP::ASN1::secp224r1()); curveValid = true; }
                else if (curve == "secp224k1") { ecParams.Initialize(CryptoPP::ASN1::secp224k1()); curveValid = true; }
                if (!curveValid) {
                    return false;
                }

                try {
                    if (algo == "ECDSA") {
                        bool hashValid = false;
                        if (hashName == "SHA-1" || hashName == "SHA-224" || hashName == "SHA-256" || hashName == "SHA-384" ||
                            hashName == "SHA-512" || hashName == "SHA-3-224" || hashName == "SHA-3-256" || hashName == "SHA-3-384" ||
                            hashName == "SHA-3-512" || hashName == "SHA-512/224" || hashName == "SHA-512/256") {
                            hashValid = true;
                        }
                        if (!hashValid) {
                            return false;
                        }

                        void* privKeyPtr = nullptr;
                        void* pubKeyPtr = nullptr;
                        bool needTruncate224 = false;
                        bool needTruncate256 = false;

                        if (hashName == "SHA-1") {
                            auto priv = new CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA1>::PrivateKey();
                            auto pub = new CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA1>::PublicKey();
                            privKeyPtr = priv;
                            pubKeyPtr = pub;
                        }
                        else if (hashName == "SHA-224") {
                            auto priv = new CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA224>::PrivateKey();
                            auto pub = new CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA224>::PublicKey();
                            privKeyPtr = priv;
                            pubKeyPtr = pub;
                        }
                        else if (hashName == "SHA-256") {
                            auto priv = new CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey();
                            auto pub = new CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey();
                            privKeyPtr = priv;
                            pubKeyPtr = pub;
                        }
                        else if (hashName == "SHA-384") {
                            auto priv = new CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA384>::PrivateKey();
                            auto pub = new CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA384>::PublicKey();
                            privKeyPtr = priv;
                            pubKeyPtr = pub;
                        }
                        else if (hashName == "SHA-512") {
                            auto priv = new CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA512>::PrivateKey();
                            auto pub = new CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA512>::PublicKey();
                            privKeyPtr = priv;
                            pubKeyPtr = pub;
                        }
                        else if (hashName == "SHA-3-224") {
                            auto priv = new CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA3_224>::PrivateKey();
                            auto pub = new CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA3_224>::PublicKey();
                            privKeyPtr = priv;
                            pubKeyPtr = pub;
                        }
                        else if (hashName == "SHA-3-256") {
                            auto priv = new CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA3_256>::PrivateKey();
                            auto pub = new CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA3_256>::PublicKey();
                            privKeyPtr = priv;
                            pubKeyPtr = pub;
                        }
                        else if (hashName == "SHA-3-384") {
                            auto priv = new CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA3_384>::PrivateKey();
                            auto pub = new CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA3_384>::PublicKey();
                            privKeyPtr = priv;
                            pubKeyPtr = pub;
                        }
                        else if (hashName == "SHA-3-512") {
                            auto priv = new CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA3_512>::PrivateKey();
                            auto pub = new CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA3_512>::PublicKey();
                            privKeyPtr = priv;
                            pubKeyPtr = pub;
                        }
                        else if (hashName == "SHA-512/224") {
                            auto priv = new CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA512>::PrivateKey();
                            auto pub = new CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA512>::PublicKey();
                            privKeyPtr = priv;
                            pubKeyPtr = pub;
                            needTruncate224 = true;
                        }
                        else if (hashName == "SHA-512/256") {
                            auto priv = new CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA512>::PrivateKey();
                            auto pub = new CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA512>::PublicKey();
                            privKeyPtr = priv;
                            pubKeyPtr = pub;
                            needTruncate256 = true;
                        }

                        if (!privKeyPtr || !pubKeyPtr) {
                            return false;
                        }

                        auto& eccPrivKey = *static_cast<CryptoPP::DL_PrivateKey_EC<CryptoPP::ECP>*>(privKeyPtr);
                        auto& eccPubKey = *static_cast<CryptoPP::DL_PublicKey_EC<CryptoPP::ECP>*>(pubKeyPtr);

                        eccPrivKey.Initialize(rng, ecParams);
                        eccPrivKey.MakePublicKey(eccPubKey);

                        CryptoPP::ByteQueue pubQueue;
                        eccPubKey.Save(pubQueue);
                        outBinary->resize(static_cast<size_t>(pubQueue.MaxRetrievable()));
                        pubQueue.Get(outBinary->data(), outBinary->size());

                        if (needTruncate224 && outBinary->size() > 28) {
                            outBinary->resize(28);
                        }
                        if (needTruncate256 && outBinary->size() > 32) {
                            outBinary->resize(32);
                        }

                        if (privateKey != nullptr) {
                            privateKey->clear();
                            CryptoPP::ByteQueue privQueue;
                            eccPrivKey.Save(privQueue);
                            privateKey->resize(static_cast<size_t>(privQueue.MaxRetrievable()));
                            privQueue.Get(privateKey->data(), privateKey->size());

                            if (needTruncate224 && privateKey->size() > 28) {
                                privateKey->resize(28);
                            }
                            if (needTruncate256 && privateKey->size() > 32) {
                                privateKey->resize(32);
                            }
                        }

                        delete static_cast<void*>(privKeyPtr);
                        delete static_cast<void*>(pubKeyPtr);
                    }
                    else if (algo == "ECDH") {
                        using ECDHDomain = CryptoPP::DH_Domain<CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>>;
                        ECDHDomain ecdhDomain(ecParams);

                        CryptoPP::SecByteBlock ecdhPrivKey(ecdhDomain.PrivateKeyLength());
                        CryptoPP::SecByteBlock ecdhPubKey(ecdhDomain.PublicKeyLength());
                        ecdhDomain.GenerateKeyPair(rng, ecdhPrivKey, ecdhPubKey);

                        CryptoPP::ByteQueue pubQueue;
                        CryptoPP::DL_PublicKey_EC<CryptoPP::ECP> pubKey;
                        CryptoPP::ECP::Point pubPoint;
                        ecParams.GetCurve().DecodePoint(pubPoint, ecdhPubKey.data(), ecdhPubKey.size());
                        pubKey.Initialize(ecParams, pubPoint);
                        pubKey.Save(pubQueue);

                        outBinary->resize(static_cast<size_t>(pubQueue.MaxRetrievable()));
                        pubQueue.Get(outBinary->data(), outBinary->size());

                        if (privateKey != nullptr) {
                            privateKey->clear();
                            CryptoPP::ByteQueue privQueue;
                            CryptoPP::DL_PrivateKey_EC<CryptoPP::ECP> privKey;
                            privKey.Initialize(ecParams, CryptoPP::Integer(ecdhPrivKey.data(), ecdhPrivKey.size()));
                            privKey.Save(privQueue);
                            privateKey->resize(static_cast<size_t>(privQueue.MaxRetrievable()));
                            privQueue.Get(privateKey->data(), privateKey->size());
                        }
                    }
                    return !outBinary->empty();
                }
                catch (...) {
                    outBinary->clear();
                    if (privateKey != nullptr) privateKey->clear();
                    return false;
                }
            }
            else if (algo == "ChaCha20-Poly1305") {
                if (length < 128 || length > 256 || (length % 8) != 0) {
                    return false;
                }
                const size_t keySizeBytes = static_cast<size_t>(length / 8);
                outBinary->resize(keySizeBytes);
                rng.GenerateBlock(outBinary->data(), keySizeBytes);
                return !outBinary->empty() && outBinary->size() == keySizeBytes;
            }
            else {
                return false;
            }
        }
        static bool crypto_subtle_generateKey_AES(uint64_t keyLength, const std::string& mode, BYTEBUFFER_PTR outKey)
        {
            if (!outKey || mode.empty()) {
                return false;
            }
            std::string modeParam = "mode=" + mode;
            return crypto_subtle_generateKey_core("AES", keyLength, outKey, modeParam.c_str(), NULL);
        }
        static bool crypto_subtle_generateKey_RSA(uint64_t modulusLength, uint64_t publicExponent, const std::string& paddingMode, const std::string& hashName, BYTEBUFFER_PTR publicKey, BYTEBUFFER_PTR privateKey)
        {
            if (!publicKey || !privateKey || paddingMode.empty() || hashName.empty()) {
                return false;
            }
            std::string pubExpParam = "publicExponent=" + std::to_string(publicExponent);
            std::string paddingParam = "padding=" + paddingMode;
            std::string hashParam = "hash=" + hashName;
            return crypto_subtle_generateKey_core("RSA", modulusLength, publicKey,
                pubExpParam.c_str(), paddingParam.c_str(), hashParam.c_str(), NULL,
                privateKey, NULL);
        }
        static bool crypto_subtle_generateKey_EC(const std::string& keyType, const std::string& nameCurve, const std::string& hashName, BYTEBUFFER_PTR publicKey, BYTEBUFFER_PTR privateKey)
        {
            if (!publicKey || !privateKey || keyType.empty() || nameCurve.empty() || hashName.empty()) {
                return false;
            }
            uint64_t length = 0;
            if (nameCurve == "P-192") length = 192;
            else if (nameCurve == "secp192k1") length = 192;
            else if (nameCurve == "secp224r1" || nameCurve == "secp224k1") length = 224;
            else if (nameCurve == "P-256" || nameCurve == "secp256k1") length = 256;
            else if (nameCurve == "P-384") length = 384;
            else if (nameCurve == "P-521") length = 521;
            else length = 256;

            std::string curveParam = "curve=" + nameCurve;
            std::string hashParam = "hash=" + hashName;
            return crypto_subtle_generateKey_core(keyType, length, publicKey,
                curveParam.c_str(), hashParam.c_str(), NULL,
                privateKey, NULL);
        }
        static bool crypto_subtle_generateKey_HMAC(const std::string& hashName, uint64_t keyLength, BYTEBUFFER_PTR keyBinary)
        {
            if (!keyBinary || hashName.empty()) {
                return false;
            }
            std::string hashParam = "hash=" + hashName;
            return crypto_subtle_generateKey_core("HMAC", keyLength, keyBinary, hashParam.c_str(), NULL);
        }
        static bool crypto_subtle_generateKey_Ed25519(BYTEBUFFER_PTR publicKey, BYTEBUFFER_PTR privateKey)
        {
            if (!publicKey || !privateKey) {
                return false;
            }
            return crypto_subtle_generateKey_core("Ed25519", 0, publicKey, NULL, privateKey, NULL);
        }
        static bool crypto_subtle_generateKey_X25519(BYTEBUFFER_PTR publicKey, BYTEBUFFER_PTR privateKey)
        {
            if (!publicKey || !privateKey) {
                return false;
            }
            return crypto_subtle_generateKey_core("X25519", 0, publicKey, NULL, privateKey, NULL);
        }
        static bool crypto_subtle_generateKey_ChaCha20Poly1305(BYTEBUFFER_PTR keyBinary)
        {
            if (!keyBinary) {
                return false;
            }
            return crypto_subtle_generateKey_core("ChaCha20-Poly1305", 256, keyBinary, NULL);
        }

        static bool crypto_subtle_importKey_jwk_RSA(BYTEBUFFER_PTR e, BYTEBUFFER_PTR n, BYTEBUFFER_PTR outputBinary, BYTEBUFFER_PTR d = nullptr, BYTEBUFFER_PTR p = nullptr, BYTEBUFFER_PTR q = nullptr, BYTEBUFFER_PTR dp = nullptr, BYTEBUFFER_PTR dq = nullptr, BYTEBUFFER_PTR qi = nullptr)
        {
            if (e == nullptr || n == nullptr || outputBinary == nullptr || e->empty() || n->empty())
            {
                return false;
            }

            outputBinary->clear();

            try
            {
                CryptoPP::AutoSeededRandomPool rng;

                CryptoPP::Integer n_int(n->data(), n->size());
                CryptoPP::Integer e_int(e->data(), e->size());

                bool isPrivateKey = (d != nullptr && !d->empty());

                if (isPrivateKey)
                {
                    CryptoPP::Integer d_int(d->data(), d->size());
                    CryptoPP::Integer p_int, q_int, dp_int, dq_int, qi_int;

                    if (p != nullptr && !p->empty())
                        p_int = CryptoPP::Integer(p->data(), p->size());
                    if (q != nullptr && !q->empty())
                        q_int = CryptoPP::Integer(q->data(), q->size());
                    if (dp != nullptr && !dp->empty())
                        dp_int = CryptoPP::Integer(dp->data(), dp->size());
                    if (dq != nullptr && !dq->empty())
                        dq_int = CryptoPP::Integer(dq->data(), dq->size());
                    if (qi != nullptr && !qi->empty())
                        qi_int = CryptoPP::Integer(qi->data(), qi->size());

                    CryptoPP::RSA::PrivateKey rsaPrivKey;
                    if (p_int.IsZero() || q_int.IsZero())
                    {
                        rsaPrivKey.Initialize(n_int, e_int, d_int);
                    }
                    else
                    {
                        rsaPrivKey.Initialize(n_int, e_int, d_int, p_int, q_int, dp_int, dq_int, qi_int);
                    }

                    if (!rsaPrivKey.Validate(rng, 3))
                    {
                        return false;
                    }

                    CryptoPP::ByteQueue privQueue;
                    rsaPrivKey.Save(privQueue);

                    size_t privSize = static_cast<size_t>(privQueue.MaxRetrievable());
                    if (privSize == 0)
                    {
                        return false;
                    }
                    outputBinary->resize(privSize);
                    privQueue.Get(outputBinary->data(), privSize);
                }
                else
                {
                    CryptoPP::RSA::PublicKey rsaPubKey;
                    rsaPubKey.Initialize(n_int, e_int);

                    if (!rsaPubKey.Validate(rng, 3))
                    {
                        return false;
                    }

                    CryptoPP::ByteQueue pubQueue;
                    rsaPubKey.Save(pubQueue);

                    size_t pubSize = static_cast<size_t>(pubQueue.MaxRetrievable());
                    if (pubSize == 0)
                    {
                        return false;
                    }
                    outputBinary->resize(pubSize);
                    pubQueue.Get(outputBinary->data(), pubSize);
                }

                return !outputBinary->empty();
            }
            catch (...)
            {
                outputBinary->clear();
                return false;
            }
        }
        static bool crypto_subtle_importKey_jwk_EC(std::string crv, BYTEBUFFER_PTR outBinary, BYTEBUFFER_PTR d = nullptr, BYTEBUFFER_PTR x = nullptr, BYTEBUFFER_PTR y = nullptr)
        {
            if (outBinary == nullptr) {
                return false;
            }
            outBinary->clear();

            CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> ecParams;
            bool curveValid = false;
            if (crv == "P-256") {
                ecParams.Initialize(CryptoPP::ASN1::secp256r1());
                curveValid = true;
            }
            else if (crv == "P-384") {
                ecParams.Initialize(CryptoPP::ASN1::secp384r1());
                curveValid = true;
            }
            else if (crv == "P-521") {
                ecParams.Initialize(CryptoPP::ASN1::secp521r1());
                curveValid = true;
            }
            if (!curveValid) {
                return false;
            }

            try {
                if (d == nullptr && x != nullptr && y != nullptr && !x->empty() && !y->empty()) {
                    CryptoPP::ECP::Point pubPoint;
                    pubPoint.x = CryptoPP::Integer(x->data(), x->size());
                    pubPoint.y = CryptoPP::Integer(y->data(), y->size());
                    pubPoint.identity = false;

                    CryptoPP::DL_PublicKey_EC<CryptoPP::ECP> pubKey;
                    pubKey.Initialize(ecParams, pubPoint);

                    CryptoPP::ByteQueue spkiQueue;
                    pubKey.Save(spkiQueue);
                    outBinary->resize(static_cast<size_t>(spkiQueue.MaxRetrievable()));
                    spkiQueue.Get(outBinary->data(), outBinary->size());
                }
                else if (d != nullptr && !d->empty() && x == nullptr && y == nullptr) {
                    CryptoPP::DL_PrivateKey_EC<CryptoPP::ECP> privKey;
                    privKey.Initialize(ecParams, CryptoPP::Integer(d->data(), d->size()));

                    CryptoPP::ByteQueue pkcs8Queue;
                    privKey.Save(pkcs8Queue);
                    outBinary->resize(static_cast<size_t>(pkcs8Queue.MaxRetrievable()));
                    pkcs8Queue.Get(outBinary->data(), outBinary->size());
                }
                else {
                    return false;
                }

                return !outBinary->empty();
            }
            catch (...) {
                outBinary->clear();
                return false;
            }
        }

        static RSAJWKDATA crypto_subtle_exportKey_jwk_RSA(BYTEBUFFER_PTR binary) {
            RSAJWKDATA result;
            if (!binary || binary->empty()) {
                return result;
            }

            try {
                CryptoPP::ByteQueue queue;
                queue.Put(binary->data(), binary->size());
                queue.MessageEnd();

                CryptoPP::AutoSeededRandomPool rng;
                bool isPrivate = false;

                CryptoPP::RSA::PublicKey pubKey;
                CryptoPP::RSA::PrivateKey privKey;

                try {
                    privKey.Load(queue);
                    if (privKey.Validate(rng, 3)) {
                        isPrivate = true;
                        result.isPrivate = true;

                        CryptoPP::Integer n = privKey.GetModulus();
                        CryptoPP::Integer e = privKey.GetPublicExponent();
                        CryptoPP::Integer d = privKey.GetPrivateExponent();
                        CryptoPP::Integer p = privKey.GetPrime1();
                        CryptoPP::Integer q = privKey.GetPrime2();
                        CryptoPP::Integer dp = privKey.GetModPrime1PrivateExponent();
                        CryptoPP::Integer dq = privKey.GetModPrime2PrivateExponent();
                        CryptoPP::Integer qi = privKey.GetMultiplicativeInverseOfPrime2ModPrime1();

                        size_t nLen = n.MinEncodedSize();
                        result.n.resize(nLen);
                        n.Encode(result.n.data(), nLen);

                        size_t eLen = e.MinEncodedSize();
                        result.e.resize(eLen);
                        e.Encode(result.e.data(), eLen);

                        size_t dLen = d.MinEncodedSize();
                        result.d.resize(dLen);
                        d.Encode(result.d.data(), dLen);

                        size_t pLen = p.MinEncodedSize();
                        result.p.resize(pLen);
                        p.Encode(result.p.data(), pLen);

                        size_t qLen = q.MinEncodedSize();
                        result.q.resize(qLen);
                        q.Encode(result.q.data(), qLen);

                        size_t dpLen = dp.MinEncodedSize();
                        result.dp.resize(dpLen);
                        dp.Encode(result.dp.data(), dpLen);

                        size_t dqLen = dq.MinEncodedSize();
                        result.dq.resize(dqLen);
                        dq.Encode(result.dq.data(), dqLen);

                        size_t qiLen = qi.MinEncodedSize();
                        result.qi.resize(qiLen);
                        qi.Encode(result.qi.data(), qiLen);

                        result.isValid = true;
                    }
                }
                catch (...) {
                    queue.Clear();
                    queue.Put(binary->data(), binary->size());
                    queue.MessageEnd();

                    pubKey.Load(queue);
                    if (pubKey.Validate(rng, 3)) {
                        CryptoPP::Integer n = pubKey.GetModulus();
                        CryptoPP::Integer e = pubKey.GetPublicExponent();

                        size_t nLen = n.MinEncodedSize();
                        result.n.resize(nLen);
                        n.Encode(result.n.data(), nLen);

                        size_t eLen = e.MinEncodedSize();
                        result.e.resize(eLen);
                        e.Encode(result.e.data(), eLen);

                        result.isValid = true;
                    }
                }
            }
            catch (...) {
                result.isValid = false;
            }

            return result;
        }
        static ECJWKDATA crypto_subtle_exportKey_jwk_EC(BYTEBUFFER_PTR binary) {
            ECJWKDATA result;
            if (!binary || binary->empty()) {
                return result;
            }

            try {
                CryptoPP::ByteQueue queue;
                queue.Put(binary->data(), binary->size());
                queue.MessageEnd();

                CryptoPP::AutoSeededRandomPool rng;
                CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> ecParams;

                try {
                    CryptoPP::DL_PrivateKey_EC<CryptoPP::ECP> privKey;
                    privKey.Load(queue);
                    if (privKey.Validate(rng, 3)) {
                        result.isPrivate = true;

                        const CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>& params = privKey.GetGroupParameters();
                        const CryptoPP::ECP& curve = params.GetCurve();

                        CryptoPP::Integer d = privKey.GetPrivateExponent();
                        size_t dLen = d.MinEncodedSize();
                        result.d.resize(dLen);
                        d.Encode(result.d.data(), dLen);

                        CryptoPP::ECP::Point pubPoint = params.ExponentiateBase(d);
                        CryptoPP::Integer x = pubPoint.x, y = pubPoint.y;

                        size_t xLen = x.MinEncodedSize();
                        result.x.resize(xLen);
                        x.Encode(result.x.data(), xLen);

                        size_t yLen = y.MinEncodedSize();
                        result.y.resize(yLen);
                        y.Encode(result.y.data(), yLen);

                        result.isValid = true;
                        return result;
                    }
                }
                catch (...) {}

                queue.Clear();
                queue.Put(binary->data(), binary->size());
                queue.MessageEnd();

                CryptoPP::DL_PublicKey_EC<CryptoPP::ECP> pubKey;
                pubKey.Load(queue);
                if (pubKey.Validate(rng, 3)) {
                    CryptoPP::ECP::Point pubPoint = pubKey.GetPublicElement();
                    CryptoPP::Integer x = pubPoint.x, y = pubPoint.y;

                    size_t xLen = x.MinEncodedSize();
                    result.x.resize(xLen);
                    x.Encode(result.x.data(), xLen);

                    size_t yLen = y.MinEncodedSize();
                    result.y.resize(yLen);
                    y.Encode(result.y.data(), yLen);

                    result.isValid = true;
                }
            }
            catch (...) {
                result.isValid = false;
            }

            return result;
        }
        static bool crypto_subtle_exportKey_jwk_Ed25519_X25519(BYTEBUFFER_PTR binary, BYTEBUFFER_PTR outBinary) {
            if (!binary || !outBinary || binary->empty() || binary->size() != 32) {
                outBinary->clear();
                return false;
            }

            CryptoPP::AutoSeededRandomPool rng;
            unsigned char pubKeyBuf[32] = { 0 };
            bool success = false;

            try {
                unsigned char hash[64] = { 0 };
                CryptoPP::SHA512 sha;
                sha.CalculateDigest(hash, binary->data(), 32);
                hash[0] &= 0xF8;
                hash[31] &= 0x7F;
                hash[31] |= 0x40;

                CryptoPP::ed25519Signer signer(hash);
                CryptoPP::ByteQueue pubQueue;
                signer.AccessKey().Save(pubQueue);
                size_t pubSize = static_cast<size_t>(pubQueue.MaxRetrievable());
                if (pubSize >= 32) {
                    pubQueue.Skip(pubSize - 32);
                    pubQueue.Get(pubKeyBuf, 32);
                    success = true;
                }
            }
            catch (...) {
                CryptoPP::x25519 x25519Key;
                unsigned char sk[32];
                memcpy(sk, binary->data(), 32);
                sk[0] &= 0xF8;
                sk[31] &= 0x7F;
                sk[31] |= 0x40;
                x25519Key.GeneratePublicKey(rng, sk, pubKeyBuf);

                bool isAllZero = true;
                for (int i = 0; i < 32; ++i) {
                    if (pubKeyBuf[i] != 0) {
                        isAllZero = false;
                        break;
                    }
                }
                success = !isAllZero;
            }

            if (success) {
                outBinary->assign(pubKeyBuf, pubKeyBuf + 32);
                return true;
            }
            else {
                outBinary->clear();
                return false;
            }
        }

        static bool crypto_subtle_encrypt_core(const std::string& algo, const std::string& operation, BYTEBUFFER_PTR input, BYTEBUFFER_PTR key, BYTEBUFFER_PTR output, ...) {
            if (!input || !key || !output || key->empty()) {
                output->clear();
                return false;
            }
            output->clear();
            bool operationSuccess = false;

            va_list args;
            va_start(args, output);
            try {
                static CryptoPP::AutoSeededRandomPool rng;
                BYTEBUFFER_PTR iv = nullptr;
                uint64_t tagLength = 128;
                BYTEBUFFER_PTR additionalData = nullptr;
                std::string hash = "SHA-256";

                while (true) {
                    const char* param = va_arg(args, const char*);
                    if (!param) break;
                    std::string paramStr = param;
                    size_t eqPos = paramStr.find('=');
                    if (eqPos == std::string::npos) continue;

                    std::string k = paramStr.substr(0, eqPos);
                    std::string v = paramStr.substr(eqPos + 1);
                    if (k == "iv") iv = reinterpret_cast<BYTEBUFFER_PTR>(va_arg(args, void*));
                    else if (k == "tagLength") tagLength = std::stoull(v);
                    else if (k == "additionalData") additionalData = reinterpret_cast<BYTEBUFFER_PTR>(va_arg(args, void*));
                    else if (k == "hash") hash = v;
                }

                if (algo == "AES-GCM" || algo == "AES-CBC" || algo == "AES-CTR" || algo == "RSA-OAEP" || algo == "ChaCha20-Poly1305") {
                    if (((algo != "RSA-OAEP" && algo != "AES-KW" && !iv) || (algo == "AES-GCM" && (tagLength < 96 || tagLength > 128 || tagLength % 8 != 0)))) {
                        va_end(args);
                        return false;
                    }

                    if (algo == "AES-GCM") {
                        CryptoPP::GCM<CryptoPP::AES>::Encryption gcmEnc;
                        CryptoPP::GCM<CryptoPP::AES>::Decryption gcmDec;
                        if (operation == "encrypt") {
                            gcmEnc.SetKeyWithIV(key->data(), key->size(), iv->data(), iv->size());

                            const size_t tagSize = static_cast<size_t>(tagLength / 8);
                            output->resize(input->size() + tagSize);

                            if (additionalData && !additionalData->empty()) {
                                gcmEnc.Update(additionalData->data(), additionalData->size());
                            }
                            if (!input->empty()) {
                                gcmEnc.ProcessData(output->data(), input->data(), input->size());
                            }
                            gcmEnc.Final(output->data() + input->size());
                            operationSuccess = true;
                        }
                        else if (operation == "decrypt") {
                            gcmDec.SetKeyWithIV(key->data(), key->size(), iv->data(), iv->size());

                            const size_t tagSize = static_cast<size_t>(tagLength / 8);
                            if (input->size() < tagSize) {
                                va_end(args);
                                return false;
                            }
                            output->resize(input->size() - tagSize);

                            if (additionalData && !additionalData->empty()) {
                                gcmDec.Update(additionalData->data(), additionalData->size());
                            }
                            if (input->size() > tagSize) {
                                gcmDec.ProcessData(output->data(), input->data(), input->size() - tagSize);
                            }
                            bool tagValid = gcmDec.Verify(input->data() + (input->size() - tagSize));

                            if (tagValid) {
                                operationSuccess = true;
                            }
                            else {
                                output->clear();
                            }
                        }
                    }
                    else if (algo == "AES-CBC") {
                        if (!iv || iv->size() != CryptoPP::AES::BLOCKSIZE) {
                            va_end(args);
                            return false;
                        }
                        CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption enc;
                        CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption dec;

                        if (operation == "encrypt") {
                            enc.SetKeyWithIV(key->data(), key->size(), iv->data(), iv->size());
                            output->resize(input->size() + CryptoPP::AES::BLOCKSIZE);
                            CryptoPP::ArraySink sink(output->data(), output->size());
                            CryptoPP::StreamTransformationFilter filter(enc, new CryptoPP::Redirector(sink));
                            if (!input->empty()) {
                                filter.Put(input->data(), input->size());
                            }
                            filter.MessageEnd();
                            output->resize(static_cast<size_t>(sink.TotalPutLength()));
                            operationSuccess = true;
                        }
                        else if (operation == "decrypt") {
                            dec.SetKeyWithIV(key->data(), key->size(), iv->data(), iv->size());
                            output->resize(input->size());
                            CryptoPP::ArraySink sink(output->data(), output->size());
                            CryptoPP::StreamTransformationFilter filter(dec, new CryptoPP::Redirector(sink));
                            if (!input->empty()) {
                                filter.Put(input->data(), input->size());
                            }
                            filter.MessageEnd();
                            output->resize(static_cast<size_t>(sink.TotalPutLength()));
                            operationSuccess = true;
                        }
                    }
                    else if (algo == "AES-CTR") {
                        if (!iv || iv->size() != CryptoPP::AES::BLOCKSIZE) {
                            va_end(args);
                            return false;
                        }
                        CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption enc;
                        CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption dec;

                        if (operation == "encrypt" || operation == "decrypt") {
                            (operation == "encrypt" ? enc : dec).SetKeyWithIV(key->data(), key->size(), iv->data(), iv->size());
                            output->resize(input->size());
                            if (!input->empty()) {
                                (operation == "encrypt" ? enc : dec).ProcessData(output->data(), input->data(), input->size());
                            }
                            operationSuccess = true;
                        }
                    }
                    else if (algo == "ChaCha20-Poly1305") {
                        if (!iv || iv->size() != 12 || key->size() != 32) {
                            va_end(args);
                            return false;
                        }
                        const size_t tagSize = 16;

                        if (operation == "encrypt") {
                            CryptoPP::ChaCha20Poly1305::Encryption chacha;
                            chacha.SetKeyWithIV(key->data(), 32, iv->data(), 12);

                            output->resize(input->size() + tagSize);

                            if (additionalData && !additionalData->empty()) {
                                chacha.Update(additionalData->data(), additionalData->size());
                            }
                            if (!input->empty()) {
                                chacha.ProcessData(output->data(), input->data(), input->size());
                            }
                            chacha.Final(output->data() + input->size());
                            operationSuccess = true;
                        }
                        else if (operation == "decrypt") {
                            CryptoPP::ChaCha20Poly1305::Decryption chacha;
                            chacha.SetKeyWithIV(key->data(), 32, iv->data(), 12);

                            if (input->size() < tagSize) {
                                va_end(args);
                                return false;
                            }
                            output->resize(input->size() - tagSize);
                            if (additionalData && !additionalData->empty()) {
                                chacha.Update(additionalData->data(), additionalData->size());
                            }
                            if (input->size() > tagSize) {
                                chacha.ProcessData(output->data(), input->data(), input->size() - tagSize);
                            }
                            bool tagValid = chacha.Verify(input->data() + (input->size() - tagSize));

                            if (tagValid) {
                                operationSuccess = true;
                            }
                            else {
                                output->clear();
                            }
                        }
                    }
                    else if (algo == "RSA-OAEP") {
                        CryptoPP::RSAFunction rsaPubKey;
                        CryptoPP::InvertibleRSAFunction rsaPrivKey;
                        CryptoPP::ByteQueue queue;
                        CryptoPP::AutoSeededRandomPool rng;

                        if (operation == "encrypt") {
                            queue.Put(key->data(), key->size());
                            queue.MessageEnd();
                            rsaPubKey.Load(queue);

                            CryptoPP::RSAES_OAEP_SHA_Encryptor encryptor(rsaPubKey);

                            size_t maxPlaintextLen = encryptor.FixedMaxPlaintextLength();
                            if (!input->empty() && input->size() > maxPlaintextLen) {
                                va_end(args);
                                return false;
                            }

                            output->resize(encryptor.CiphertextLength(input->size()));
                            if (!input->empty()) {
                                encryptor.Encrypt(rng, reinterpret_cast<const byte*>(input->data()), input->size(), reinterpret_cast<byte*>(output->data()));
                            }
                            else {
                                encryptor.Encrypt(rng, nullptr, 0, reinterpret_cast<byte*>(output->data()));
                            }
                            operationSuccess = true;
                        }
                        else if (operation == "decrypt") {
                            queue.Put(key->data(), key->size());
                            queue.MessageEnd();
                            rsaPrivKey.Load(queue);

                            CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(rsaPrivKey);

                            output->resize(decryptor.MaxPlaintextLength(input->size()));
                            CryptoPP::DecodingResult result = decryptor.Decrypt(
                                rng, reinterpret_cast<const byte*>(input->data()), input->size(), reinterpret_cast<byte*>(output->data())
                            );

                            if (result.isValidCoding) {
                                output->resize(result.messageLength);
                                operationSuccess = true;
                            }
                            else {
                                output->clear();
                            }
                        }
                    }
                }
                va_end(args);
                return operationSuccess;
            }
            catch (...) {
                va_end(args);
                output->clear();
                return false;
            }
        }
        static bool crypto_subtle_sign_core(const std::string& algo, const std::string& operation, BYTEBUFFER_PTR data, BYTEBUFFER_PTR key, BYTEBUFFER_PTR signature, ...) {
            if (!data || !key || !signature || key->empty()) {
                if (operation == "verify") return false;
                signature->clear();
                return false;
            }
            if (operation == "sign") signature->clear();
            bool operationSuccess = false;

            va_list args;
            va_start(args, signature);
            try {
                static CryptoPP::AutoSeededRandomPool rng;
                std::string hash = "SHA-256";
                size_t saltLength = 32;
                std::string curve = "P-256";

                while (true) {
                    const char* param = va_arg(args, const char*);
                    if (!param) break;
                    std::string paramStr = param;
                    size_t eqPos = paramStr.find('=');
                    if (eqPos == std::string::npos) continue;

                    std::string k = paramStr.substr(0, eqPos);
                    std::string v = paramStr.substr(eqPos + 1);
                    if (k == "hash") hash = v;
                    else if (k == "saltLength") saltLength = static_cast<size_t>(std::stoull(v));
                    else if (k == "curve") curve = v;
                }

                if (allowedShaName.find(hash) == allowedShaName.end()) {
                    va_end(args);
                    return false;
                }

                if (algo == "HMAC") {
                    CryptoPP::HashTransformation* hmac = nullptr;
                    if (hash == "SHA-1") hmac = new CryptoPP::HMAC<CryptoPP::SHA1>(key->data(), key->size());
                    else if (hash == "SHA-224") hmac = new CryptoPP::HMAC<CryptoPP::SHA224>(key->data(), key->size());
                    else if (hash == "SHA-256") hmac = new CryptoPP::HMAC<CryptoPP::SHA256>(key->data(), key->size());
                    else if (hash == "SHA-384") hmac = new CryptoPP::HMAC<CryptoPP::SHA384>(key->data(), key->size());
                    else if (hash == "SHA-3-224") hmac = new CryptoPP::HMAC<CryptoPP::SHA3_224>(key->data(), key->size());
                    else if (hash == "SHA-3-256") hmac = new CryptoPP::HMAC<CryptoPP::SHA3_256>(key->data(), key->size());
                    else if (hash == "SHA-3-384") hmac = new CryptoPP::HMAC<CryptoPP::SHA3_384>(key->data(), key->size());
                    else if (hash == "SHA-3-512") hmac = new CryptoPP::HMAC<CryptoPP::SHA3_512>(key->data(), key->size());
                    else if (hash == "SHA-512" || hash == "SHA-512/224" || hash == "SHA-512/256") {
                        hmac = new CryptoPP::HMAC<CryptoPP::SHA512>(key->data(), key->size());
                    }
                    if (!hmac) {
                        va_end(args);
                        return false;
                    }

                    if (operation == "sign") {
                        byte temp[64];
                        hmac->CalculateDigest(temp, data->data(), data->size());
                        if (hash == "SHA-512/224") {
                            signature->resize(28);
                            memcpy(signature->data(), temp, 28);
                        }
                        else if (hash == "SHA-512/256") {
                            signature->resize(32);
                            memcpy(signature->data(), temp, 32);
                        }
                        else {
                            signature->resize(hmac->DigestSize());
                            memcpy(signature->data(), temp, hmac->DigestSize());
                        }
                        operationSuccess = true;
                        delete hmac;
                    }
                    else if (operation == "verify") {
                        bool ret = false;
                        if (hash == "SHA-512/224" || hash == "SHA-512/256") {
                            byte temp[64];
                            hmac->CalculateDigest(temp, data->data(), data->size());
                            size_t len = (hash == "SHA-512/224") ? 28 : 32;
                            ret = (memcmp(temp, signature->data(), len) == 0);
                        }
                        else {
                            ret = hmac->VerifyDigest(signature->data(), data->data(), data->size());
                        }
                        operationSuccess = ret;
                        delete hmac;
                        va_end(args);
                        return operationSuccess;
                    }
                }
                else if (algo == "RSA-PSS") {
                    CryptoPP::RSA::PrivateKey rsaPrivKey;
                    CryptoPP::RSA::PublicKey rsaPubKey;
                    CryptoPP::ByteQueue queue;
                    queue.Put(key->data(), key->size());
                    queue.MessageEnd();

                    if (operation == "sign") {
                        rsaPrivKey.Load(queue);
                        if (hash == "SHA-1") {
                            CryptoPP::RSASS<CryptoPP::PSS, CryptoPP::SHA1>::Signer signer(rsaPrivKey);
                            signature->resize(signer.MaxSignatureLength());
                            signature->resize(signer.SignMessage(rng, data->data(), data->size(), signature->data()));
                            operationSuccess = true;
                        }
                        else if (hash == "SHA-224") {
                            CryptoPP::RSASS<CryptoPP::PSS, CryptoPP::SHA224>::Signer signer(rsaPrivKey);
                            signature->resize(signer.MaxSignatureLength());
                            signature->resize(signer.SignMessage(rng, data->data(), data->size(), signature->data()));
                            operationSuccess = true;
                        }
                        else if (hash == "SHA-256") {
                            CryptoPP::RSASS<CryptoPP::PSS, CryptoPP::SHA256>::Signer signer(rsaPrivKey);
                            signature->resize(signer.MaxSignatureLength());
                            signature->resize(signer.SignMessage(rng, data->data(), data->size(), signature->data()));
                            operationSuccess = true;
                        }
                        else if (hash == "SHA-384") {
                            CryptoPP::RSASS<CryptoPP::PSS, CryptoPP::SHA384>::Signer signer(rsaPrivKey);
                            signature->resize(signer.MaxSignatureLength());
                            signature->resize(signer.SignMessage(rng, data->data(), data->size(), signature->data()));
                            operationSuccess = true;
                        }
                        else if (hash == "SHA-3-224") {
                            CryptoPP::RSASS<CryptoPP::PSS, CryptoPP::SHA3_224>::Signer signer(rsaPrivKey);
                            signature->resize(signer.MaxSignatureLength());
                            signature->resize(signer.SignMessage(rng, data->data(), data->size(), signature->data()));
                            operationSuccess = true;
                        }
                        else if (hash == "SHA-3-256") {
                            CryptoPP::RSASS<CryptoPP::PSS, CryptoPP::SHA3_256>::Signer signer(rsaPrivKey);
                            signature->resize(signer.MaxSignatureLength());
                            signature->resize(signer.SignMessage(rng, data->data(), data->size(), signature->data()));
                            operationSuccess = true;
                        }
                        else if (hash == "SHA-3-384") {
                            CryptoPP::RSASS<CryptoPP::PSS, CryptoPP::SHA3_384>::Signer signer(rsaPrivKey);
                            signature->resize(signer.MaxSignatureLength());
                            signature->resize(signer.SignMessage(rng, data->data(), data->size(), signature->data()));
                            operationSuccess = true;
                        }
                        else if (hash == "SHA-3-512") {
                            CryptoPP::RSASS<CryptoPP::PSS, CryptoPP::SHA3_512>::Signer signer(rsaPrivKey);
                            signature->resize(signer.MaxSignatureLength());
                            signature->resize(signer.SignMessage(rng, data->data(), data->size(), signature->data()));
                            operationSuccess = true;
                        }
                        else if (hash == "SHA-512" || hash == "SHA-512/224" || hash == "SHA-512/256") {
                            CryptoPP::RSASS<CryptoPP::PSS, CryptoPP::SHA512>::Signer signer(rsaPrivKey);
                            signature->resize(signer.MaxSignatureLength());
                            size_t sigLen = signer.SignMessage(rng, data->data(), data->size(), signature->data());
                            signature->resize(sigLen);
                            operationSuccess = true;
                        }
                        va_end(args);
                        return operationSuccess;
                    }
                    else if (operation == "verify") {
                        rsaPubKey.Load(queue);
                        if (hash == "SHA-1") {
                            CryptoPP::RSASS<CryptoPP::PSS, CryptoPP::SHA1>::Verifier verifier(rsaPubKey);
                            operationSuccess = verifier.VerifyMessage(data->data(), data->size(), signature->data(), signature->size());
                        }
                        else if (hash == "SHA-224") {
                            CryptoPP::RSASS<CryptoPP::PSS, CryptoPP::SHA224>::Verifier verifier(rsaPubKey);
                            operationSuccess = verifier.VerifyMessage(data->data(), data->size(), signature->data(), signature->size());
                        }
                        else if (hash == "SHA-256") {
                            CryptoPP::RSASS<CryptoPP::PSS, CryptoPP::SHA256>::Verifier verifier(rsaPubKey);
                            operationSuccess = verifier.VerifyMessage(data->data(), data->size(), signature->data(), signature->size());
                        }
                        else if (hash == "SHA-384") {
                            CryptoPP::RSASS<CryptoPP::PSS, CryptoPP::SHA384>::Verifier verifier(rsaPubKey);
                            operationSuccess = verifier.VerifyMessage(data->data(), data->size(), signature->data(), signature->size());
                        }
                        else if (hash == "SHA-3-224") {
                            CryptoPP::RSASS<CryptoPP::PSS, CryptoPP::SHA3_224>::Verifier verifier(rsaPubKey);
                            operationSuccess = verifier.VerifyMessage(data->data(), data->size(), signature->data(), signature->size());
                        }
                        else if (hash == "SHA-3-256") {
                            CryptoPP::RSASS<CryptoPP::PSS, CryptoPP::SHA3_256>::Verifier verifier(rsaPubKey);
                            operationSuccess = verifier.VerifyMessage(data->data(), data->size(), signature->data(), signature->size());
                        }
                        else if (hash == "SHA-3-384") {
                            CryptoPP::RSASS<CryptoPP::PSS, CryptoPP::SHA3_384>::Verifier verifier(rsaPubKey);
                            operationSuccess = verifier.VerifyMessage(data->data(), data->size(), signature->data(), signature->size());
                        }
                        else if (hash == "SHA-3-512") {
                            CryptoPP::RSASS<CryptoPP::PSS, CryptoPP::SHA3_512>::Verifier verifier(rsaPubKey);
                            operationSuccess = verifier.VerifyMessage(data->data(), data->size(), signature->data(), signature->size());
                        }
                        else if (hash == "SHA-512" || hash == "SHA-512/224" || hash == "SHA-512/256") {
                            BYTEBUFFER digestBuf;
                            BYTEBUFFER_PTR digestPtr = &digestBuf;
                            crypto_subtle_digest_core(hash, data, digestPtr);
                            CryptoPP::RSASS<CryptoPP::PSS, CryptoPP::SHA512>::Verifier verifier(rsaPubKey);
                            operationSuccess = verifier.VerifyMessage(digestBuf.data(), digestBuf.size(), signature->data(), signature->size());
                        }
                        va_end(args);
                        return operationSuccess;
                    }
                }
                else if (algo == "RSASSA-PKCS1-v1_5") {
                    CryptoPP::RSA::PrivateKey rsaPrivKey;
                    CryptoPP::RSA::PublicKey rsaPubKey;
                    CryptoPP::ByteQueue queue;
                    queue.Put(key->data(), key->size());
                    queue.MessageEnd();

                    if (operation == "sign") {
                        rsaPrivKey.Load(queue);
                        if (hash == "SHA-1") {
                            CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA1>::Signer signer(rsaPrivKey);
                            signature->resize(signer.MaxSignatureLength());
                            signature->resize(signer.SignMessage(rng, data->data(), data->size(), signature->data()));
                            operationSuccess = true;
                        }
                        else if (hash == "SHA-224") {
                            CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA224>::Signer signer(rsaPrivKey);
                            signature->resize(signer.MaxSignatureLength());
                            signature->resize(signer.SignMessage(rng, data->data(), data->size(), signature->data()));
                            operationSuccess = true;
                        }
                        else if (hash == "SHA-256") {
                            CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA256>::Signer signer(rsaPrivKey);
                            signature->resize(signer.MaxSignatureLength());
                            signature->resize(signer.SignMessage(rng, data->data(), data->size(), signature->data()));
                            operationSuccess = true;
                        }
                        else if (hash == "SHA-384") {
                            CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA384>::Signer signer(rsaPrivKey);
                            signature->resize(signer.MaxSignatureLength());
                            signature->resize(signer.SignMessage(rng, data->data(), data->size(), signature->data()));
                            operationSuccess = true;
                        }
                        else if (hash == "SHA-3-224") {
                            CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA3_224>::Signer signer(rsaPrivKey);
                            signature->resize(signer.MaxSignatureLength());
                            signature->resize(signer.SignMessage(rng, data->data(), data->size(), signature->data()));
                            operationSuccess = true;
                        }
                        else if (hash == "SHA-3-256") {
                            CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA3_256>::Signer signer(rsaPrivKey);
                            signature->resize(signer.MaxSignatureLength());
                            signature->resize(signer.SignMessage(rng, data->data(), data->size(), signature->data()));
                            operationSuccess = true;
                        }
                        else if (hash == "SHA-3-384") {
                            CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA3_384>::Signer signer(rsaPrivKey);
                            signature->resize(signer.MaxSignatureLength());
                            signature->resize(signer.SignMessage(rng, data->data(), data->size(), signature->data()));
                            operationSuccess = true;
                        }
                        else if (hash == "SHA-3-512") {
                            CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA3_512>::Signer signer(rsaPrivKey);
                            signature->resize(signer.MaxSignatureLength());
                            signature->resize(signer.SignMessage(rng, data->data(), data->size(), signature->data()));
                            operationSuccess = true;
                        }
                        else if (hash == "SHA-512" || hash == "SHA-512/224" || hash == "SHA-512/256") {
                            CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA512>::Signer signer(rsaPrivKey);
                            signature->resize(signer.MaxSignatureLength());
                            size_t sigLen = signer.SignMessage(rng, data->data(), data->size(), signature->data());
                            signature->resize(sigLen);
                            operationSuccess = true;
                        }
                        va_end(args);
                        return operationSuccess;
                    }
                    else if (operation == "verify") {
                        rsaPubKey.Load(queue);
                        if (hash == "SHA-1") {
                            CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA1>::Verifier verifier(rsaPubKey);
                            operationSuccess = verifier.VerifyMessage(data->data(), data->size(), signature->data(), signature->size());
                        }
                        else if (hash == "SHA-224") {
                            CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA224>::Verifier verifier(rsaPubKey);
                            operationSuccess = verifier.VerifyMessage(data->data(), data->size(), signature->data(), signature->size());
                        }
                        else if (hash == "SHA-256") {
                            CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA256>::Verifier verifier(rsaPubKey);
                            operationSuccess = verifier.VerifyMessage(data->data(), data->size(), signature->data(), signature->size());
                        }
                        else if (hash == "SHA-384") {
                            CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA384>::Verifier verifier(rsaPubKey);
                            operationSuccess = verifier.VerifyMessage(data->data(), data->size(), signature->data(), signature->size());
                        }
                        else if (hash == "SHA-3-224") {
                            CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA3_224>::Verifier verifier(rsaPubKey);
                            operationSuccess = verifier.VerifyMessage(data->data(), data->size(), signature->data(), signature->size());
                        }
                        else if (hash == "SHA-3-256") {
                            CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA3_256>::Verifier verifier(rsaPubKey);
                            operationSuccess = verifier.VerifyMessage(data->data(), data->size(), signature->data(), signature->size());
                        }
                        else if (hash == "SHA-3-384") {
                            CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA3_384>::Verifier verifier(rsaPubKey);
                            operationSuccess = verifier.VerifyMessage(data->data(), data->size(), signature->data(), signature->size());
                        }
                        else if (hash == "SHA-3-512") {
                            CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA3_512>::Verifier verifier(rsaPubKey);
                            operationSuccess = verifier.VerifyMessage(data->data(), data->size(), signature->data(), signature->size());
                        }
                        else if (hash == "SHA-512" || hash == "SHA-512/224" || hash == "SHA-512/256") {
                            BYTEBUFFER digestBuf;
                            BYTEBUFFER_PTR digestPtr = &digestBuf;
                            crypto_subtle_digest_core(hash, data, digestPtr);
                            CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA512>::Verifier verifier(rsaPubKey);
                            operationSuccess = verifier.VerifyMessage(digestBuf.data(), digestBuf.size(), signature->data(), signature->size());
                        }
                        va_end(args);
                        return operationSuccess;
                    }
                }
                else if (algo == "ECDSA") {
                    if (allowedCurveName.find(curve) == allowedCurveName.end()) {
                        va_end(args);
                        return false;
                    }

                    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey eccPrivKey;
                    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey eccPubKey;
                    CryptoPP::ByteQueue queue;
                    queue.Put(key->data(), key->size());
                    queue.MessageEnd();

                    CryptoPP::OID curveOID;
                    if (curve == "P-192") curveOID = CryptoPP::ASN1::secp192r1();
                    else if (curve == "P-256") curveOID = CryptoPP::ASN1::secp256r1();
                    else if (curve == "P-384") curveOID = CryptoPP::ASN1::secp384r1();
                    else if (curve == "P-521") curveOID = CryptoPP::ASN1::secp521r1();
                    else if (curve == "secp192k1") curveOID = CryptoPP::ASN1::secp192k1();
                    else if (curve == "secp224r1") curveOID = CryptoPP::ASN1::secp224r1();
                    else if (curve == "secp224k1") curveOID = CryptoPP::ASN1::secp224k1();
                    else if (curve == "secp256k1") curveOID = CryptoPP::ASN1::secp256k1();
                    else {
                        va_end(args);
                        return false;
                    }

                    if (operation == "sign") {
                        eccPrivKey.Load(queue);
                        if (hash == "SHA-1") {
                            CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA1>::Signer signer(eccPrivKey);
                            signature->resize(signer.MaxSignatureLength());
                            signature->resize(signer.SignMessage(rng, data->data(), data->size(), signature->data()));
                            operationSuccess = true;
                        }
                        else if (hash == "SHA-224") {
                            CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA224>::Signer signer(eccPrivKey);
                            signature->resize(signer.MaxSignatureLength());
                            signature->resize(signer.SignMessage(rng, data->data(), data->size(), signature->data()));
                            operationSuccess = true;
                        }
                        else if (hash == "SHA-256") {
                            CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Signer signer(eccPrivKey);
                            signature->resize(signer.MaxSignatureLength());
                            signature->resize(signer.SignMessage(rng, data->data(), data->size(), signature->data()));
                            operationSuccess = true;
                        }
                        else if (hash == "SHA-384") {
                            CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA384>::Signer signer(eccPrivKey);
                            signature->resize(signer.MaxSignatureLength());
                            signature->resize(signer.SignMessage(rng, data->data(), data->size(), signature->data()));
                            operationSuccess = true;
                        }
                        else if (hash == "SHA-3-224") {
                            CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA3_224>::Signer signer(eccPrivKey);
                            signature->resize(signer.MaxSignatureLength());
                            signature->resize(signer.SignMessage(rng, data->data(), data->size(), signature->data()));
                            operationSuccess = true;
                        }
                        else if (hash == "SHA-3-256") {
                            CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA3_256>::Signer signer(eccPrivKey);
                            signature->resize(signer.MaxSignatureLength());
                            signature->resize(signer.SignMessage(rng, data->data(), data->size(), signature->data()));
                            operationSuccess = true;
                        }
                        else if (hash == "SHA-3-384") {
                            CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA3_384>::Signer signer(eccPrivKey);
                            signature->resize(signer.MaxSignatureLength());
                            signature->resize(signer.SignMessage(rng, data->data(), data->size(), signature->data()));
                            operationSuccess = true;
                        }
                        else if (hash == "SHA-3-512") {
                            CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA3_512>::Signer signer(eccPrivKey);
                            signature->resize(signer.MaxSignatureLength());
                            signature->resize(signer.SignMessage(rng, data->data(), data->size(), signature->data()));
                            operationSuccess = true;
                        }
                        else if (hash == "SHA-512" || hash == "SHA-512/224" || hash == "SHA-512/256") {
                            CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA512>::Signer signer(eccPrivKey);
                            signature->resize(signer.MaxSignatureLength());
                            size_t sigLen = signer.SignMessage(rng, data->data(), data->size(), signature->data());
                            signature->resize(sigLen);
                            operationSuccess = true;
                        }
                        va_end(args);
                        return operationSuccess;
                    }
                    else if (operation == "verify") {
                        eccPubKey.Load(queue);
                        if (hash == "SHA-1") {
                            CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA1>::Verifier verifier(eccPubKey);
                            operationSuccess = verifier.VerifyMessage(data->data(), data->size(), signature->data(), signature->size());
                        }
                        else if (hash == "SHA-224") {
                            CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA224>::Verifier verifier(eccPubKey);
                            operationSuccess = verifier.VerifyMessage(data->data(), data->size(), signature->data(), signature->size());
                        }
                        else if (hash == "SHA-256") {
                            CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Verifier verifier(eccPubKey);
                            operationSuccess = verifier.VerifyMessage(data->data(), data->size(), signature->data(), signature->size());
                        }
                        else if (hash == "SHA-384") {
                            CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA384>::Verifier verifier(eccPubKey);
                            operationSuccess = verifier.VerifyMessage(data->data(), data->size(), signature->data(), signature->size());
                        }
                        else if (hash == "SHA-3-224") {
                            CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA3_224>::Verifier verifier(eccPubKey);
                            operationSuccess = verifier.VerifyMessage(data->data(), data->size(), signature->data(), signature->size());
                        }
                        else if (hash == "SHA-3-256") {
                            CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA3_256>::Verifier verifier(eccPubKey);
                            operationSuccess = verifier.VerifyMessage(data->data(), data->size(), signature->data(), signature->size());
                        }
                        else if (hash == "SHA-3-384") {
                            CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA3_384>::Verifier verifier(eccPubKey);
                            operationSuccess = verifier.VerifyMessage(data->data(), data->size(), signature->data(), signature->size());
                        }
                        else if (hash == "SHA-3-512") {
                            CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA3_512>::Verifier verifier(eccPubKey);
                            operationSuccess = verifier.VerifyMessage(data->data(), data->size(), signature->data(), signature->size());
                        }
                        else if (hash == "SHA-512" || hash == "SHA-512/224" || hash == "SHA-512/256") {
                            BYTEBUFFER digestBuf;
                            BYTEBUFFER_PTR digestPtr = &digestBuf;
                            crypto_subtle_digest_core(hash, data, digestPtr);
                            CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA512>::Verifier verifier(eccPubKey);
                            operationSuccess = verifier.VerifyMessage(digestBuf.data(), digestBuf.size(), signature->data(), signature->size());
                        }
                        va_end(args);
                        return operationSuccess;
                    }
                }

                va_end(args);
                return operationSuccess;
            }
            catch (...) {
                va_end(args);
                if (operation == "sign") signature->clear();
                return false;
            }
        }
        static bool crypto_subtle_deriveKey_core(const std::string& algo, BYTEBUFFER_PTR privateKey, BYTEBUFFER_PTR peerPublicKey, BYTEBUFFER_PTR derivedKey, const std::string& curve, uint64_t derivedLength) {
            if (!privateKey || !peerPublicKey || !derivedKey || privateKey->empty() || peerPublicKey->empty()) {
                derivedKey->clear();
                return false;
            }
            derivedKey->clear();

            try {
                if (algo == "ECDH") {
                    CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> ecParams;
                    if (curve == "P-192") ecParams.Initialize(CryptoPP::ASN1::secp192r1());
                    else if (curve == "P-256") ecParams.Initialize(CryptoPP::ASN1::secp256r1());
                    else if (curve == "P-384") ecParams.Initialize(CryptoPP::ASN1::secp384r1());
                    else if (curve == "P-521") ecParams.Initialize(CryptoPP::ASN1::secp521r1());
                    else if (curve == "secp192k1") ecParams.Initialize(CryptoPP::ASN1::secp192k1());
                    else if (curve == "secp224r1") ecParams.Initialize(CryptoPP::ASN1::secp224r1());
                    else if (curve == "secp224k1") ecParams.Initialize(CryptoPP::ASN1::secp224k1());
                    else if (curve == "secp256k1") ecParams.Initialize(CryptoPP::ASN1::secp256k1());
                    else return false;

                    // 解析PKCS8 DER私钥
                    CryptoPP::SecByteBlock privKeyRaw;
                    {
                        CryptoPP::ByteQueue privQueue;
                        privQueue.Put(privateKey->data(), privateKey->size());
                        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA1>::PrivateKey ecPrivKey;
                        try {
                            ecPrivKey.Load(privQueue);
                        }
                        catch (const CryptoPP::Exception&) { // 消除未引用变量警告
                            derivedKey->clear();
                            return false;
                        }

                        // 无参获取私钥曲线参数
                        const CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>& privEcParams = ecPrivKey.GetGroupParameters();
                        if (!privEcParams.GetCurve().operator==(ecParams.GetCurve())) {
                            derivedKey->clear();
                            return false;
                        }

                        // 提取私钥并标准化长度
                        const CryptoPP::Integer& privExponent = ecPrivKey.GetPrivateExponent();
                        size_t fieldSize = ecParams.GetCurve().GetField().GetModulus().ByteCount();
                        privKeyRaw.New(fieldSize);
                        memset(privKeyRaw.data(), 0, fieldSize);
                        size_t privByteCount = privExponent.ByteCount();
                        if (privByteCount > fieldSize) {
                            derivedKey->clear();
                            return false;
                        }
                        privExponent.Encode(privKeyRaw.data() + (fieldSize - privByteCount), privByteCount);
                    }

                    // 解析SPKI DER公钥
                    CryptoPP::SecByteBlock pubKeyRaw;
                    {
                        CryptoPP::ByteQueue pubQueue;
                        pubQueue.Put(peerPublicKey->data(), peerPublicKey->size());
                        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA1>::PublicKey ecPubKey;
                        try {
                            ecPubKey.Load(pubQueue);
                        }
                        catch (const CryptoPP::Exception&) { // 消除未引用变量警告
                            derivedKey->clear();
                            return false;
                        }

                        // 无参获取公钥曲线参数
                        const CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>& pubEcParams = ecPubKey.GetGroupParameters();
                        if (!pubEcParams.GetCurve().operator==(ecParams.GetCurve())) {
                            derivedKey->clear();
                            return false;
                        }

                        // 标准化公钥编码
                        const CryptoPP::ECP::Point& pubPoint = ecPubKey.GetPublicElement();
                        const CryptoPP::ECP& curveRef = ecParams.GetCurve();
                        size_t encodedSize = curveRef.EncodedPointSize(false);
                        pubKeyRaw.New(encodedSize);
                        curveRef.EncodePoint(pubKeyRaw.data(), pubPoint, false);

                        // 校验公钥有效性
                        CryptoPP::ECP::Point verifyPoint;
                        if (!curveRef.DecodePoint(verifyPoint, pubKeyRaw.data(), encodedSize) || !curveRef.VerifyPoint(verifyPoint)) {
                            derivedKey->clear();
                            return false;
                        }
                    }

                    // ECDH密钥协商
                    using ECDHDomain = CryptoPP::DH_Domain<CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>>;
                    ECDHDomain ecdhDomain(ecParams);

                    if (privKeyRaw.size() != ecdhDomain.PrivateKeyLength() || pubKeyRaw.size() != ecdhDomain.PublicKeyLength()) {
                        derivedKey->clear();
                        return false;
                    }

                    size_t agreeLength = ecdhDomain.AgreedValueLength();
                    derivedKey->resize(agreeLength, 0);

                    bool agreeResult = false;
                    try {
                        agreeResult = ecdhDomain.Agree(derivedKey->data(), privKeyRaw, pubKeyRaw);
                    }
                    catch (const CryptoPP::DL_BadElement&) { // 消除未引用变量警告
                        derivedKey->clear();
                        return false;
                    }

                    if (!agreeResult) {
                        derivedKey->clear();
                        return false;
                    }

                    if (derivedLength > 0 && derivedLength < derivedKey->size()) {
                        derivedKey->resize(static_cast<size_t>(derivedLength));
                    }
                }
                else if (algo == "X25519") {
                    CryptoPP::x25519 x25519Key;
                    CryptoPP::SecByteBlock privKey(privateKey->data(), privateKey->size());
                    CryptoPP::SecByteBlock pubKey(peerPublicKey->data(), peerPublicKey->size());

                    derivedKey->resize(32);
                    bool agreeResult = x25519Key.Agree(derivedKey->data(), privKey, pubKey);
                    if (!agreeResult) {
                        derivedKey->clear();
                        return false;
                    }
                    if (derivedLength > 0 && derivedLength < 32) {
                        derivedKey->resize(static_cast<size_t>(derivedLength));
                    }
                }
                return !derivedKey->empty();
            }
            catch (...) {
                derivedKey->clear();
                return false;
            }
        }
        static bool crypto_subtle_deriveBits_core(const std::string& algo, BYTEBUFFER_PTR baseKey, BYTEBUFFER_PTR derivedBits, uint64_t length, const std::string& curve, const std::string& hash, BYTEBUFFER_PTR salt, BYTEBUFFER_PTR info, uint64_t iterations) {
            if (!baseKey || !derivedBits || baseKey->empty() || length == 0 || (length % 8) != 0) {
                derivedBits->clear();
                return false;
            }
            derivedBits->clear();
            size_t byteLength = static_cast<size_t>(length / 8);
            bool operationSuccess = false;

            try {
                if (algo == "ECDH") {
                    if (curve.empty() || allowedCurveName.find(curve) == allowedCurveName.end() || !info) return false;
                    CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> ecParams;
                    if (curve == "P-192") ecParams.Initialize(CryptoPP::ASN1::secp192r1());
                    else if (curve == "P-256") ecParams.Initialize(CryptoPP::ASN1::secp256r1());
                    else if (curve == "P-384") ecParams.Initialize(CryptoPP::ASN1::secp384r1());
                    else if (curve == "P-521") ecParams.Initialize(CryptoPP::ASN1::secp521r1());
                    else if (curve == "secp192k1") ecParams.Initialize(CryptoPP::ASN1::secp192k1());
                    else if (curve == "secp224r1") ecParams.Initialize(CryptoPP::ASN1::secp224r1());
                    else if (curve == "secp224k1") ecParams.Initialize(CryptoPP::ASN1::secp224k1());
                    else if (curve == "secp256k1") ecParams.Initialize(CryptoPP::ASN1::secp256k1());
                    else return false;

                    CryptoPP::SecByteBlock privKeyRaw;
                    {
                        CryptoPP::ByteQueue privQueue;
                        privQueue.Put(baseKey->data(), baseKey->size());
                        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA1>::PrivateKey ecPrivKey;
                        try {
                            ecPrivKey.Load(privQueue);
                        }
                        catch (const CryptoPP::Exception&) {
                            derivedBits->clear();
                            return false;
                        }

                        const CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>& privEcParams = ecPrivKey.GetGroupParameters();
                        if (!privEcParams.GetCurve().operator==(ecParams.GetCurve())) {
                            derivedBits->clear();
                            return false;
                        }

                        const CryptoPP::Integer& privExponent = ecPrivKey.GetPrivateExponent();
                        size_t fieldSize = ecParams.GetCurve().GetField().GetModulus().ByteCount();
                        privKeyRaw.New(fieldSize);
                        memset(privKeyRaw.data(), 0, fieldSize);
                        size_t privByteCount = privExponent.ByteCount();
                        if (privByteCount > fieldSize) {
                            derivedBits->clear();
                            return false;
                        }
                        privExponent.Encode(privKeyRaw.data() + (fieldSize - privByteCount), privByteCount);
                    }

                    CryptoPP::SecByteBlock pubKeyRaw;
                    {
                        CryptoPP::ByteQueue pubQueue;
                        pubQueue.Put(info->data(), info->size());
                        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA1>::PublicKey ecPubKey;
                        try {
                            ecPubKey.Load(pubQueue);
                        }
                        catch (const CryptoPP::Exception&) {
                            derivedBits->clear();
                            return false;
                        }

                        const CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>& pubEcParams = ecPubKey.GetGroupParameters();
                        if (!pubEcParams.GetCurve().operator==(ecParams.GetCurve())) {
                            derivedBits->clear();
                            return false;
                        }

                        const CryptoPP::ECP::Point& pubPoint = ecPubKey.GetPublicElement();
                        const CryptoPP::ECP& curveRef = ecParams.GetCurve();
                        size_t encodedSize = curveRef.EncodedPointSize(false);
                        pubKeyRaw.New(encodedSize);
                        curveRef.EncodePoint(pubKeyRaw.data(), pubPoint, false);

                        CryptoPP::ECP::Point verifyPoint;
                        if (!curveRef.DecodePoint(verifyPoint, pubKeyRaw.data(), encodedSize) || !curveRef.VerifyPoint(verifyPoint)) {
                            derivedBits->clear();
                            return false;
                        }
                    }

                    using ECDHDomain = CryptoPP::DH_Domain<CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>>;
                    ECDHDomain ecdhDomain(ecParams);

                    if (privKeyRaw.size() != ecdhDomain.PrivateKeyLength() || pubKeyRaw.size() != ecdhDomain.PublicKeyLength()) {
                        derivedBits->clear();
                        return false;
                    }

                    std::vector<unsigned char> tempKey(ecdhDomain.AgreedValueLength(), 0);
                    bool agreeResult = false;
                    try {
                        agreeResult = ecdhDomain.Agree(tempKey.data(), privKeyRaw, pubKeyRaw);
                    }
                    catch (const CryptoPP::DL_BadElement&) {
                        derivedBits->clear();
                        return false;
                    }

                    if (agreeResult) {
                        derivedBits->resize(byteLength);
                        memcpy(derivedBits->data(), tempKey.data(), std::min(tempKey.size(), byteLength));
                        operationSuccess = true;
                    }
                    else {
                        derivedBits->clear();
                    }
                }
                else if (algo == "PBKDF2") {
                    if (hash.empty() || allowedShaName.find(hash) == allowedShaName.end() || iterations == 0 || !salt) return false;

                    CryptoPP::SecByteBlock key(baseKey->data(), baseKey->size());
                    CryptoPP::SecByteBlock saltBytes(salt->data(), salt->size());
                    derivedBits->resize(byteLength);

                    if (hash == "SHA-1") {
                        CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA1> pbkdf2;
                        pbkdf2.DeriveKey(derivedBits->data(), byteLength, 0, key.data(), key.size(), saltBytes.data(), saltBytes.size(), static_cast<unsigned int>(iterations));
                        operationSuccess = true;
                    }
                    else if (hash == "SHA-224") {
                        CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA224> pbkdf2;
                        pbkdf2.DeriveKey(derivedBits->data(), byteLength, 0, key.data(), key.size(), saltBytes.data(), saltBytes.size(), static_cast<unsigned int>(iterations));
                        operationSuccess = true;
                    }
                    else if (hash == "SHA-256") {
                        CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> pbkdf2;
                        pbkdf2.DeriveKey(derivedBits->data(), byteLength, 0, key.data(), key.size(), saltBytes.data(), saltBytes.size(), static_cast<unsigned int>(iterations));
                        operationSuccess = true;
                    }
                    else if (hash == "SHA-384") {
                        CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA384> pbkdf2;
                        pbkdf2.DeriveKey(derivedBits->data(), byteLength, 0, key.data(), key.size(), saltBytes.data(), saltBytes.size(), static_cast<unsigned int>(iterations));
                        operationSuccess = true;
                    }
                    else if (hash == "SHA-512") {
                        CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA512> pbkdf2;
                        pbkdf2.DeriveKey(derivedBits->data(), byteLength, 0, key.data(), key.size(), saltBytes.data(), saltBytes.size(), static_cast<unsigned int>(iterations));
                        operationSuccess = true;
                    }
                    else if (hash == "SHA-3-224") {
                        CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA3_224> pbkdf2;
                        pbkdf2.DeriveKey(derivedBits->data(), byteLength, 0, key.data(), key.size(), saltBytes.data(), saltBytes.size(), static_cast<unsigned int>(iterations));
                        operationSuccess = true;
                    }
                    else if (hash == "SHA-3-256") {
                        CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA3_256> pbkdf2;
                        pbkdf2.DeriveKey(derivedBits->data(), byteLength, 0, key.data(), key.size(), saltBytes.data(), saltBytes.size(), static_cast<unsigned int>(iterations));
                        operationSuccess = true;
                    }
                    else if (hash == "SHA-3-384") {
                        CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA3_384> pbkdf2;
                        pbkdf2.DeriveKey(derivedBits->data(), byteLength, 0, key.data(), key.size(), saltBytes.data(), saltBytes.size(), static_cast<unsigned int>(iterations));
                        operationSuccess = true;
                    }
                    else if (hash == "SHA-3-512") {
                        CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA3_512> pbkdf2;
                        pbkdf2.DeriveKey(derivedBits->data(), byteLength, 0, key.data(), key.size(), saltBytes.data(), saltBytes.size(), static_cast<unsigned int>(iterations));
                        operationSuccess = true;
                    }
                    else if (hash == "SHA-512/224") {
                        CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA512> pbkdf2;
                        std::vector<unsigned char> tempKey(byteLength);
                        pbkdf2.DeriveKey(tempKey.data(), byteLength, 0, key.data(), key.size(), saltBytes.data(), saltBytes.size(), static_cast<unsigned int>(iterations));
                        derivedBits->resize(28);
                        memcpy(derivedBits->data(), tempKey.data(), 28);
                        operationSuccess = true;
                    }
                    else if (hash == "SHA-512/256") {
                        CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA512> pbkdf2;
                        std::vector<unsigned char> tempKey(byteLength);
                        pbkdf2.DeriveKey(tempKey.data(), byteLength, 0, key.data(), key.size(), saltBytes.data(), saltBytes.size(), static_cast<unsigned int>(iterations));
                        derivedBits->resize(32);
                        memcpy(derivedBits->data(), tempKey.data(), 32);
                        operationSuccess = true;
                    }
                }
                else if (algo == "HKDF") {
                    if (hash.empty() || allowedShaName.find(hash) == allowedShaName.end()) return false;

                    CryptoPP::SecByteBlock ikm(baseKey->data(), baseKey->size());
                    CryptoPP::SecByteBlock saltBytes(salt ? salt->data() : nullptr, salt ? salt->size() : 0);
                    CryptoPP::SecByteBlock infoBytes(info ? info->data() : nullptr, info ? info->size() : 0);
                    derivedBits->resize(byteLength);

                    if (hash == "SHA-1") {
                        CryptoPP::HKDF<CryptoPP::SHA1> hkdf;
                        hkdf.DeriveKey(derivedBits->data(), byteLength, ikm, ikm.size(), saltBytes, saltBytes.size(), infoBytes, infoBytes.size());
                        operationSuccess = true;
                    }
                    else if (hash == "SHA-224") {
                        CryptoPP::HKDF<CryptoPP::SHA224> hkdf;
                        hkdf.DeriveKey(derivedBits->data(), byteLength, ikm, ikm.size(), saltBytes, saltBytes.size(), infoBytes, infoBytes.size());
                        operationSuccess = true;
                    }
                    else if (hash == "SHA-256") {
                        CryptoPP::HKDF<CryptoPP::SHA256> hkdf;
                        hkdf.DeriveKey(derivedBits->data(), byteLength, ikm, ikm.size(), saltBytes, saltBytes.size(), infoBytes, infoBytes.size());
                        operationSuccess = true;
                    }
                    else if (hash == "SHA-384") {
                        CryptoPP::HKDF<CryptoPP::SHA384> hkdf;
                        hkdf.DeriveKey(derivedBits->data(), byteLength, ikm, ikm.size(), saltBytes, saltBytes.size(), infoBytes, infoBytes.size());
                        operationSuccess = true;
                    }
                    else if (hash == "SHA-512") {
                        CryptoPP::HKDF<CryptoPP::SHA512> hkdf;
                        hkdf.DeriveKey(derivedBits->data(), byteLength, ikm, ikm.size(), saltBytes, saltBytes.size(), infoBytes, infoBytes.size());
                        operationSuccess = true;
                    }
                    else if (hash == "SHA-3-224") {
                        CryptoPP::HKDF<CryptoPP::SHA3_224> hkdf;
                        hkdf.DeriveKey(derivedBits->data(), byteLength, ikm, ikm.size(), saltBytes, saltBytes.size(), infoBytes, infoBytes.size());
                        operationSuccess = true;
                    }
                    else if (hash == "SHA-3-256") {
                        CryptoPP::HKDF<CryptoPP::SHA3_256> hkdf;
                        hkdf.DeriveKey(derivedBits->data(), byteLength, ikm, ikm.size(), saltBytes, saltBytes.size(), infoBytes, infoBytes.size());
                        operationSuccess = true;
                    }
                    else if (hash == "SHA-3-384") {
                        CryptoPP::HKDF<CryptoPP::SHA3_384> hkdf;
                        hkdf.DeriveKey(derivedBits->data(), byteLength, ikm, ikm.size(), saltBytes, saltBytes.size(), infoBytes, infoBytes.size());
                        operationSuccess = true;
                    }
                    else if (hash == "SHA-3-512") {
                        CryptoPP::HKDF<CryptoPP::SHA3_512> hkdf;
                        hkdf.DeriveKey(derivedBits->data(), byteLength, ikm, ikm.size(), saltBytes, saltBytes.size(), infoBytes, infoBytes.size());
                        operationSuccess = true;
                    }
                    else if (hash == "SHA-512/224") {
                        CryptoPP::HKDF<CryptoPP::SHA512> hkdf;
                        std::vector<unsigned char> tempKey(byteLength);
                        hkdf.DeriveKey(tempKey.data(), byteLength, ikm, ikm.size(), saltBytes, saltBytes.size(), infoBytes, infoBytes.size());
                        derivedBits->resize(28);
                        memcpy(derivedBits->data(), tempKey.data(), 28);
                        operationSuccess = true;
                    }
                    else if (hash == "SHA-512/256") {
                        CryptoPP::HKDF<CryptoPP::SHA512> hkdf;
                        std::vector<unsigned char> tempKey(byteLength);
                        hkdf.DeriveKey(tempKey.data(), byteLength, ikm, ikm.size(), saltBytes, saltBytes.size(), infoBytes, infoBytes.size());
                        derivedBits->resize(32);
                        memcpy(derivedBits->data(), tempKey.data(), 32);
                        operationSuccess = true;
                    }
                }
                else if (algo == "X25519") {
                    if (!info) return false;
                    CryptoPP::x25519 x25519Key;
                    CryptoPP::SecByteBlock privKey(baseKey->data(), baseKey->size());
                    CryptoPP::SecByteBlock pubKey(info->data(), info->size());

                    std::vector<unsigned char> tempKey(32);
                    bool agreeResult = x25519Key.Agree(tempKey.data(), privKey, pubKey);
                    if (agreeResult) {
                        derivedBits->resize(byteLength);
                        memcpy(derivedBits->data(), tempKey.data(), std::min(tempKey.size(), byteLength));
                        operationSuccess = true;
                    }
                    else {
                        derivedBits->clear();
                    }
                }
                else {
                    derivedBits->clear();
                    return false;
                }

                return operationSuccess;
            }
            catch (...) {
                derivedBits->clear();
                return false;
            }
        }

        static bool crypto_subtle_deriveBits_PBKDF2(BYTEBUFFER_PTR baseKey, BYTEBUFFER_PTR derivedBits, uint64_t length, BYTEBUFFER_PTR salt, uint64_t iterations, std::string hash) {
            return crypto_subtle_deriveBits_core("PBKDF2", baseKey, derivedBits, length, "", hash, salt, nullptr, iterations);
        }
        static bool crypto_subtle_deriveBits_ECDH(BYTEBUFFER_PTR baseKey, BYTEBUFFER_PTR derivedBits, uint64_t length, BYTEBUFFER_PTR publicKeyBinary, const std::string& curve) {
            return crypto_subtle_deriveBits_core("ECDH", baseKey, derivedBits, length, curve, "", nullptr, publicKeyBinary, 0);
        }
        static bool crypto_subtle_deriveBits_HKDF(BYTEBUFFER_PTR baseKey, BYTEBUFFER_PTR derivedBits, uint64_t length, BYTEBUFFER_PTR info, std::string hash, BYTEBUFFER_PTR salt) {
            return crypto_subtle_deriveBits_core("HKDF", baseKey, derivedBits, length, "", hash, salt, info, 0);
        }
        static bool crypto_subtle_deriveKey_X25519(BYTEBUFFER_PTR privateKey, BYTEBUFFER_PTR derivedKey, uint64_t length, BYTEBUFFER_PTR publicKeyBinary) {
            if (!derivedKey) {
                return false;
            }
            derivedKey->clear();
            return crypto_subtle_deriveKey_core("X25519", privateKey, publicKeyBinary, derivedKey, "", length);
        }
        static bool crypto_subtle_deriveKey_ECDH(BYTEBUFFER_PTR privateKey, BYTEBUFFER_PTR derivedKey, uint64_t length, BYTEBUFFER_PTR publicKeyBinary, const std::string& curve) {
            if (!derivedKey) {
                return false;
            }
            derivedKey->clear();
            return crypto_subtle_deriveKey_core("ECDH", privateKey, publicKeyBinary, derivedKey, curve, length);
        }
        static bool crypto_subtle_deriveKey_PBKDF2(BYTEBUFFER_PTR baseKey, BYTEBUFFER_PTR derivedKey, uint64_t length, BYTEBUFFER_PTR salt, uint64_t iterations, std::string hash) {
            if (!derivedKey) {
                return false;
            }
            derivedKey->clear();
            std::vector<unsigned char> tempBits;
            BYTEBUFFER_PTR tempBitsPtr = &tempBits;
            if (!crypto_subtle_deriveBits_PBKDF2(baseKey, tempBitsPtr, length, salt, iterations, hash)) {
                return false;
            }
            *derivedKey = tempBits;
            return !derivedKey->empty();
        }
        static bool crypto_subtle_deriveKey_HKDF(BYTEBUFFER_PTR baseKey, BYTEBUFFER_PTR derivedKey, uint64_t length, BYTEBUFFER_PTR info, std::string hash, BYTEBUFFER_PTR salt) {
            if (!derivedKey) {
                return false;
            }
            derivedKey->clear();
            std::vector<unsigned char> tempBits;
            BYTEBUFFER_PTR tempBitsPtr = &tempBits;
            if (!crypto_subtle_deriveBits_HKDF(baseKey, tempBitsPtr, length, info, hash, salt)) {
                return false;
            }
            *derivedKey = tempBits;
            return !derivedKey->empty();
        }

        static bool crypto_subtle_sign_RSA_PSS(BYTEBUFFER_PTR data, BYTEBUFFER_PTR privateKey, BYTEBUFFER_PTR signature, const std::string& hash = "SHA-256") {
            return crypto_subtle_sign_core("RSA-PSS", "sign", data, privateKey, signature, "hash=" + hash, nullptr);
        }
        static bool crypto_subtle_verify_RSA_PSS(BYTEBUFFER_PTR data, BYTEBUFFER_PTR publicKey, BYTEBUFFER_PTR signature, const std::string& hash = "SHA-256") {
            return crypto_subtle_sign_core("RSA-PSS", "verify", data, publicKey, signature, "hash=" + hash, nullptr);
        }
        static bool crypto_subtle_sign_RSA_PKCS1_v1_5(BYTEBUFFER_PTR data, BYTEBUFFER_PTR privateKey, BYTEBUFFER_PTR signature, const std::string& hash = "SHA-256") {
            return crypto_subtle_sign_core("RSASSA-PKCS1-v1_5", "sign", data, privateKey, signature, "hash=" + hash, nullptr);
        }
        static bool crypto_subtle_verify_RSA_PKCS1_v1_5(BYTEBUFFER_PTR data, BYTEBUFFER_PTR publicKey, BYTEBUFFER_PTR signature, const std::string& hash = "SHA-256") {
            return crypto_subtle_sign_core("RSASSA-PKCS1-v1_5", "verify", data, publicKey, signature, "hash=" + hash, nullptr);
        }
        static bool crypto_subtle_sign_HMAC(BYTEBUFFER_PTR data, BYTEBUFFER_PTR secretKey, BYTEBUFFER_PTR signature, const std::string& hash = "SHA-256") {
            return crypto_subtle_sign_core("HMAC", "sign", data, secretKey, signature, "hash=" + hash, nullptr);
        }
        static bool crypto_subtle_verify_HMAC(BYTEBUFFER_PTR data, BYTEBUFFER_PTR secretKey, BYTEBUFFER_PTR signature, const std::string& hash = "SHA-256") {
            return crypto_subtle_sign_core("HMAC", "verify", data, secretKey, signature, "hash=" + hash, nullptr);
        }
        static bool crypto_subtle_sign_ECDSA(BYTEBUFFER_PTR data, BYTEBUFFER_PTR privateKey, BYTEBUFFER_PTR signature, const std::string& hash = "SHA-256", const std::string& curve = "P-256") {
            return crypto_subtle_sign_core("ECDSA", "sign", data, privateKey, signature, "hash=" + hash, "curve=" + curve, nullptr);
        }
        static bool crypto_subtle_verify_ECDSA(BYTEBUFFER_PTR data, BYTEBUFFER_PTR publicKey, BYTEBUFFER_PTR signature, const std::string& hash = "SHA-256", const std::string& curve = "P-256") {
            return crypto_subtle_sign_core("ECDSA", "verify", data, publicKey, signature, "hash=" + hash, "curve=" + curve, nullptr);
        }

        static bool crypto_subtle_encrypt_AES_GCM(BYTEBUFFER_PTR plaintext, BYTEBUFFER_PTR key, BYTEBUFFER_PTR ciphertext, BYTEBUFFER_PTR iv, uint64_t tagLength, BYTEBUFFER_PTR additionalData) {
            return crypto_subtle_encrypt_core("AES-GCM", "encrypt", plaintext, key, ciphertext, "iv=ptr", iv, "tagLength=" + std::to_string(tagLength), "additionalData=ptr", additionalData, nullptr);
        }
        static bool crypto_subtle_decrypt_AES_GCM(BYTEBUFFER_PTR ciphertext, BYTEBUFFER_PTR key, BYTEBUFFER_PTR plaintext, BYTEBUFFER_PTR iv, uint64_t tagLength, BYTEBUFFER_PTR additionalData) {
            return crypto_subtle_encrypt_core("AES-GCM", "decrypt", ciphertext, key, plaintext, "iv=ptr", iv, "tagLength=" + std::to_string(tagLength), "additionalData=ptr", additionalData, nullptr);
        }
        static bool crypto_subtle_encrypt_AES_CBC(BYTEBUFFER_PTR plaintext, BYTEBUFFER_PTR key, BYTEBUFFER_PTR ciphertext, BYTEBUFFER_PTR iv) {
            return crypto_subtle_encrypt_core("AES-CBC", "encrypt", plaintext, key, ciphertext, "iv=ptr", iv, nullptr);
        }
        static bool crypto_subtle_decrypt_AES_CBC(BYTEBUFFER_PTR ciphertext, BYTEBUFFER_PTR key, BYTEBUFFER_PTR plaintext, BYTEBUFFER_PTR iv) {
            return crypto_subtle_encrypt_core("AES-CBC", "decrypt", ciphertext, key, plaintext, "iv=ptr", iv, nullptr);
        }
        static bool crypto_subtle_encrypt_AES_CTR(BYTEBUFFER_PTR plaintext, BYTEBUFFER_PTR key, BYTEBUFFER_PTR ciphertext, BYTEBUFFER_PTR iv) {
            return crypto_subtle_encrypt_core("AES-CTR", "encrypt", plaintext, key, ciphertext, "iv=ptr", iv, nullptr);
        }
        static bool crypto_subtle_decrypt_AES_CTR(BYTEBUFFER_PTR ciphertext, BYTEBUFFER_PTR key, BYTEBUFFER_PTR plaintext, BYTEBUFFER_PTR iv) {
            return crypto_subtle_encrypt_core("AES-CTR", "decrypt", ciphertext, key, plaintext, "iv=ptr", iv, nullptr);
        }
        static bool crypto_subtle_encrypt_ChaCha20_Poly1305(BYTEBUFFER_PTR plaintext, BYTEBUFFER_PTR key, BYTEBUFFER_PTR ciphertext, BYTEBUFFER_PTR iv, BYTEBUFFER_PTR additionalData) {
            return crypto_subtle_encrypt_core("ChaCha20-Poly1305", "encrypt", plaintext, key, ciphertext, "iv=ptr", iv, "additionalData=ptr", additionalData, nullptr);
        }
        static bool crypto_subtle_decrypt_ChaCha20_Poly1305(BYTEBUFFER_PTR ciphertext, BYTEBUFFER_PTR key, BYTEBUFFER_PTR plaintext, BYTEBUFFER_PTR iv, BYTEBUFFER_PTR additionalData) {
            return crypto_subtle_encrypt_core("ChaCha20-Poly1305", "decrypt", ciphertext, key, plaintext, "iv=ptr", iv, "additionalData=ptr", additionalData, nullptr);
        }
        static bool crypto_subtle_encrypt_RSA_OAEP(BYTEBUFFER_PTR plaintext, BYTEBUFFER_PTR pubKey, BYTEBUFFER_PTR ciphertext, const std::string& hash) {
            return crypto_subtle_encrypt_core("RSA-OAEP", "encrypt", plaintext, pubKey, ciphertext, "hash=" + hash, nullptr);
        }
        static bool crypto_subtle_decrypt_RSA_OAEP(BYTEBUFFER_PTR ciphertext, BYTEBUFFER_PTR privKey, BYTEBUFFER_PTR plaintext, const std::string& hash) {
            return crypto_subtle_encrypt_core("RSA-OAEP", "decrypt", ciphertext, privKey, plaintext, "hash=" + hash, nullptr);
        }

        template <typename Container>
        static ULL GetNewIdGeneric(JSContext* ctx, const Container& container, ULL& counter) {
            JSMData* jsmdPtr = nullptr;
            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
                return 0;
            }
            if (counter < ULLONG_MAX) {
                ULL candidate = ++counter;
                if (container.find(candidate) == container.end()) {
                    return candidate;
                }
            }
            ULL fallback = 1;
            while (fallback < ULLONG_MAX) {
                if (container.find(fallback) == container.end()) {
                    counter = fallback + 1;
                    return fallback;
                }
                fallback++;
            }
            return 0;
        }

        static void update(JSContext* ctx) {

            JSMData* jsmdPtr = nullptr;
            if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) return;

            if (jsmdPtr->isUpdating) return;
            jsmdPtr->isUpdating = true;

            jsmdPtr->timeoutList.lock();
            for (auto it = jsmdPtr->timeoutList.begin(); it != jsmdPtr->timeoutList.end();) {
                if (it->second.thread.isQuit()) it = jsmdPtr->timeoutList.erase(it);
                else ++it;
            }
            jsmdPtr->timeoutList.unlock();

            jsmdPtr->threadList.lock();
            for (auto it = jsmdPtr->threadList.begin(); it != jsmdPtr->threadList.end();) {
                if (it->isQuit()) it = jsmdPtr->threadList.erase(it);
                else ++it;
            }
            jsmdPtr->threadList.unlock();

            jsmdPtr->isUpdating = false;

        }

    };

    class JavaScript {
    public:
        ~JavaScript() {

            OutputDebugStringW(L"JS被析构\n");

            try {

                if (jsm != nullptr) {
                    delete jsm;
                    jsm = nullptr;
                }

                if (jsContext && !isSharedContext) {
                    JS_FreeContext(jsContext);
                    jsContext = nullptr;
                }

                if (jsRuntime && !isSharedRuntime) {
                    JS_FreeRuntime(jsRuntime);
                    jsRuntime = nullptr;
                }

            }
            catch (...) {}

            isAlive = false;
            isInit1 = false;

        }

        bool init(JSRuntime* InjsRuntime = nullptr, JSContext* InjsContext = nullptr) {
            if (isInit1) return true;
            isInit1 = true;
            isAlive = true;

            if (InjsRuntime == nullptr) {
                jsRuntime = JS_NewRuntime();
                isSharedRuntime = false;
            }
            else {
                jsRuntime = InjsRuntime;
                isSharedRuntime = true;
            }
            if (jsRuntime == nullptr) {
                return false;
            }
            if (InjsContext == nullptr) {
                jsContext = JS_NewContext(jsRuntime);
                isSharedContext = false;
            }
            else {
                jsContext = InjsContext;
                isSharedContext = true;
            }
            if (jsContext == nullptr) {
                JS_FreeRuntime(jsRuntime);
                jsRuntime = nullptr;
                return false;
            }

            try {
                jsm = new JavaScriptMethod(this, jsRuntime, jsContext);
            }
            catch (...) {

                isInit1 = false;
                isAlive = false;

                if (jsContext) JS_FreeContext(jsContext);
                jsContext = nullptr;
                if (jsRuntime) JS_FreeRuntime(jsRuntime);
                jsRuntime = nullptr;

                return false;
            }

            return true;
        }
        bool isInit() {
            return isInit1;
        }
        JSINFO eval(const std::wstring& InCode, const std::wstring& fileName = L"typein", const bool isHookOutput = false) {
            if (!isInit()) return {};
            std::string code = wstringToString(InCode);

            bool tempIsConsoleEnv = isConsoleEnv;
            if (isHookOutput) isConsoleEnv = false;
            if (isHookOutput) ClearOutput();

            JavaScriptMethod::SetAttribute(jsContext, JavaScriptMethod::GetProperty(jsContext, JavaScriptMethod::NewGlobalObject(jsContext), "system"), "fileName", wstringToString(fileName));
            JSValue ret = JS_Eval(
                jsContext,
                code.c_str(),
                code.length(),
                wstringToString(fileName).c_str(),
                JS_EVAL_TYPE_GLOBAL | JS_EVAL_FLAG_ASYNC
            );
            JavaScriptMethod::RunTask(jsContext);
            JSV result = JSV(jsContext, ret).cset(1);
            JSV promiseResult = JSV(jsContext, JS_PromiseResult(jsContext, result.get(0))).cset(1);
            bool isSuccess = JS_PromiseState(jsContext, result.get(0)) == JS_PROMISE_FULFILLED && !JS_IsException(result.get(0));
            promiseResult = (!isSuccess) ? promiseResult : JavaScriptMethod::GetProperty(jsContext, promiseResult, "value");

            JSINFO jsif = {};
            if (isHookOutput) jsif.output = outputTemp;
            if (isHookOutput) ClearOutput();
            if (isHookOutput) isConsoleEnv = tempIsConsoleEnv;
            jsif.isValid = true;
            jsif.result = promiseResult;

            if (!isSuccess) {
                std::string errorType = "";
                std::string errorMessage = "";
                if (JS_IsException(result.get(0))) {
                    JSV exception = JSV(jsContext, JS_GetException(jsContext)).cset(1);
                    promiseResult = exception;
                    JavaScriptMethod::ReadJSValueAsString(jsContext, JavaScriptMethod::GetProperty(jsContext, exception, "name"), errorType, false);
                    JavaScriptMethod::ReadJSValueAsString(jsContext, JavaScriptMethod::GetProperty(jsContext, exception, "message"), errorMessage, false);
                }
                else {
                    JavaScriptMethod::ReadJSValueAsString(jsContext, JavaScriptMethod::GetProperty(jsContext, promiseResult, "name"), errorType, false);
                    JavaScriptMethod::ReadJSValueAsString(jsContext, JavaScriptMethod::GetProperty(jsContext, promiseResult, "message"), errorMessage, false);
                }
                if (errorMessage == "[native code] Quit the context") {
                    jsif.isSuccess = true;
                    jsif.message = L"undefined";
                    goto EndProcess;
                }
                jsif.isSuccess = false;
                jsif.message = stringToWstring("Uncaught " + errorType + ": " + errorMessage);
                jsif.errorFront = GetErrorFront(jsContext, promiseResult.get(0));
                jsif.errorStack = GetErrorFrontStack(jsContext, promiseResult.get(0));
            }
            else {
                std::string message = "";
                JavaScriptMethod::ReadJSValueAsString(jsContext, promiseResult, message, false);
                jsif.isSuccess = true;
                jsif.message = stringToWstring(message);
                bool tempIsConsoleEnv = isConsoleEnv;
                isConsoleEnv = false;
                ClearOutput();
                JavaScriptMethod::CallFunction(jsContext, JavaScriptMethod::GetProperty(jsContext, JavaScriptMethod::NewGlobalObject(jsContext), { {"console"}, {"log"} }), JS_UNDEFINED, { {promiseResult} });
                jsif.detail = outputTemp;
                ClearOutput();
                isConsoleEnv = tempIsConsoleEnv;
            }
        EndProcess:;
            return jsif;
        }
        JavaScriptMethod* getMethodThis() {
            return jsm;
        }
        JSContext* getContextThis() {
            return jsContext;
        }
        JSRuntime* getRuntimeThis() {
            return jsRuntime;
        }

        bool alive() {
            return isAlive;
        }

        void child_system_exit() {
            isAlive = false;
        }
    private:
        bool isAlive = false;
        bool isInit1 = false;
        JSRuntime* jsRuntime = nullptr;
        bool isSharedRuntime = false;
        JSContext* jsContext = nullptr;
        bool isSharedContext = false;
        JavaScriptMethod* jsm = nullptr;
    };

    typedef std::shared_ptr<JavaScript> JS;
    JSINFO EvalInstance(JavaScript* instance, const std::wstring& code, const std::wstring& fileName) {
        return instance->eval(code, fileName);
    }
    void DeleteInstance(JavaScript* instance) {
        return delete instance;
    }
    JavaScript* NewInstance() {
        return new JavaScript();
    }
    bool InitInstance(JavaScript* instance, JSRuntime* InjsRuntime, JSContext* InjsContext) {
        return instance->init(InjsRuntime, InjsContext);
    }
    JavaScriptMethod* GetInstanceMethodThis(JavaScript* instance) {
        return instance->getMethodThis();
    }
    JSContext* GetContextThis(JavaScript* instance) {
        return instance->getContextThis();
    }
    JSRuntime* GetRuntimeThis(JavaScript* instance) {
        return instance->getRuntimeThis();
    }
    void ChildSystemExitInstance(JavaScript* instance) {
        return instance->child_system_exit();
    }
    bool IsAliveInstance(JavaScript* instance) {
        return instance->alive();
    }
    static JSV CallFunction(JSContext* ctx, JSV func, JSV thisVal, std::vector<JSV> args, bool isAsync, bool isWait) {
        return JavaScriptMethod::CallFunction(ctx, func, thisVal, args, isAsync, isWait);
    }
    static JSV CallFunction(JSContext* ctx, JSV func, JSV thisVal, int argc, JSValueConst* argv, bool isAsync, bool isWait) {
        return JavaScriptMethod::CallFunction(ctx, func, thisVal, argc, argv, isAsync, isWait);
    }

#include "../include/cjsapic.hpp"

    bool InitLibrary(JSMData* jsmdPtr, std::wstring path) {

        HMODULE hm = LoadLibraryW(path.c_str());
        if (hm == NULL) {
            CreateOutput(L"Warning: Library '" + path + L"' is invalid.\n", GetColorValue(L"Warning"));
            return false;
        }
        jsmdPtr->hModuleList.push_back(hm);

        CJSVERSION version = 0;

        bool ret = CallLibraryFunction(hm, "cjs_versionExchanger", version, nullptr);
        if (!ret) {
            return false;
        }

        void* cjs_main_info_ptr = nullptr;
        std::function<void()> deleteFunc = []() {};
        if (version) {
            cjs_main_info_1* cmi = new cjs_main_info_1();
            cmi->ctx = (CJSContext)jsmdPtr->ctx;
            cmi->global = JavaScriptMethod::GetCJSValue(jsmdPtr->ctx, JavaScriptMethod::NewGlobalObject(jsmdPtr->ctx));
            cjs_main_info_ptr = (void*)cmi;
            deleteFunc = [=]() {
                delete cmi;
                };
        }

        CARESULT returnCode = -1;
        ret = CallLibraryFunction(hm, "cjs_main", returnCode, cjs_main_info_ptr);
        deleteFunc();
        if (!ret) {
            CreateOutput(L"Libraries include a invalid dll\n", GetColorValue(L"Warning"));
            return false;
        }

        return true;
    }
    bool UnInitLibrary(JSMData* jsmdPtr, HMODULE hm) {

        CARESULT returnCode = -1;
        bool ret = CallLibraryFunction(hm, "cjs_exit", returnCode);

        return true;
    }

    bool IsStartByFastCgi() {
        // 1. 检查FCGX是否初始化（可选）
        // 2. 检查标准输入是否为套接字（FastCGI特征）
        HANDLE hStdIn = GetStdHandle(STD_INPUT_HANDLE);
        if (hStdIn == INVALID_HANDLE_VALUE) return false;
        DWORD fileType = GetFileType(hStdIn);
        return (fileType == FILE_TYPE_PIPE);
    }

    std::string GetEnv(const char* name, FCGX_ParamArray envp) {
        const char* env = FCGX_GetParam(name, envp);
        return (env) ? env : "";
    }
    std::wstring GetResponseHeader(OBJECT object) {
        std::wostringstream oss;
        for (const auto& [key, obj_struct] : object) {
            if (obj_struct.isObject()) {
                oss << key << L": " << L"[object Object]" << L"\r\n";
            }
            else if (obj_struct.isString()) {
                oss << key << L": " << obj_struct.get<std::wstring>() << L"\r\n";
            }
            else if (obj_struct.isBool()) {
                oss << key << L": " << (obj_struct.get<bool>() ? L"true" : L"false") << L"\r\n";
            }
            else if (obj_struct.isInt()) {
                oss << key << L": " << std::to_wstring(obj_struct.get<int>()) << L"\r\n";
            }
            else if (obj_struct.isLong()) {
                oss << key << L": " << std::to_wstring(obj_struct.get<long>()) << L"\r\n";
            }
            else if (obj_struct.isLongLong()) {
                oss << key << L": " << std::to_wstring(obj_struct.get<long long>()) << L"\r\n";
            }
            else if (obj_struct.isDouble()) {
                oss << key << L": " << std::to_wstring(obj_struct.get<double>()) << L"\r\n";
            }
            else if (obj_struct.isUInt()) {
                oss << key << L": " << std::to_wstring(obj_struct.get<unsigned int>()) << L"\r\n";
            }
            else if (obj_struct.isULong()) {
                oss << key << L": " << std::to_wstring(obj_struct.get<unsigned long>()) << L"\r\n";
            }
            else if (obj_struct.isULongLong()) {
                oss << key << L": " << std::to_wstring(obj_struct.get<unsigned long long>()) << L"\r\n";
            }
            else if (obj_struct.isNull()) {
                oss << key << L": " << L"" << L"\r\n";
            }
        }
        return oss.str();
    }
    OBJECT GetObjectFromHeader(std::wstring header) {
        OBJECT result;
        size_t start = 0;
        size_t end = 0;

        while ((end = header.find(L"\r\n", start)) != std::wstring::npos) {
            std::wstring line = header.substr(start, end - start);
            start = end + 2;

            size_t lineStart = line.find_first_not_of(L" \t\r\n");
            size_t lineEnd = line.find_last_not_of(L" \t\r\n");
            if (lineStart == std::wstring::npos || lineEnd == std::wstring::npos) {
                continue;
            }
            line = line.substr(lineStart, lineEnd - lineStart + 1);
            if (line.empty()) {
                continue;
            }

            size_t colonPos = line.find(L": ");
            std::wstring key, value;
            if (colonPos == std::wstring::npos) {
                key = line;
                value = L"";
            }
            else {
                size_t keyStart = line.substr(0, colonPos).find_first_not_of(L" \t");
                size_t keyEnd = line.substr(0, colonPos).find_last_not_of(L" \t");
                key = (keyStart != std::wstring::npos) ? line.substr(keyStart, keyEnd - keyStart + 1) : L"";
                std::wstring valPart = line.substr(colonPos + 2);
                size_t valStart = valPart.find_first_not_of(L" \t");
                size_t valEnd = valPart.find_last_not_of(L" \t");
                value = (valStart != std::wstring::npos) ? valPart.substr(valStart, valEnd - valStart + 1) : L"";
            }

            if (key.empty()) {
                continue;
            }

            OBJECTStruct objStruct;
            if (value == L"[object Object]") {
                objStruct.data = OBJECT{};
            }
            else if (value == L"true") {
                objStruct.data = true;
            }
            else if (value == L"false") {
                objStruct.data = false;
            }
            else if (value.empty()) {
                objStruct.data = nullptr_t{};
            }
            else {
                bool isNumber = false;
                try {
                    size_t pos;
                    int intVal = std::stoi(value, &pos);
                    if (pos == value.length()) { objStruct.data = intVal; isNumber = true; }
                }
                catch (...) {}
                if (!isNumber) try {
                    size_t pos;
                    long longVal = std::stol(value, &pos);
                    if (pos == value.length()) { objStruct.data = longVal; isNumber = true; }
                }
                catch (...) {}
                if (!isNumber) try {
                    size_t pos;
                    long long llVal = std::stoll(value, &pos);
                    if (pos == value.length()) { objStruct.data = llVal; isNumber = true; }
                }
                catch (...) {}
                if (!isNumber) try {
                    size_t pos;
                    unsigned int uintVal = std::stoul(value, &pos);
                    if (pos == value.length()) { objStruct.data = uintVal; isNumber = true; }
                }
                catch (...) {}
                if (!isNumber) try {
                    size_t pos;
                    unsigned long ulongVal = std::stoul(value, &pos);
                    if (pos == value.length()) { objStruct.data = ulongVal; isNumber = true; }
                }
                catch (...) {}
                if (!isNumber) try {
                    size_t pos;
                    unsigned long long ullVal = std::stoull(value, &pos);
                    if (pos == value.length()) { objStruct.data = ullVal; isNumber = true; }
                }
                catch (...) {}
                if (!isNumber) try {
                    size_t pos;
                    double doubleVal = std::stod(value, &pos);
                    if (pos == value.length()) { objStruct.data = doubleVal; isNumber = true; }
                }
                catch (...) {}
                if (!isNumber) {
                    objStruct.data = value;
                }
            }

            result.insert(std::make_pair(key, objStruct));
        }

        std::wstring lastLine = header.substr(start);
        size_t llStart = lastLine.find_first_not_of(L" \t\r\n");
        size_t llEnd = lastLine.find_last_not_of(L" \t\r\n");
        if (llStart != std::wstring::npos && llEnd != std::wstring::npos) {
            lastLine = lastLine.substr(llStart, llEnd - llStart + 1);
            if (!lastLine.empty()) {
                size_t colonPos = lastLine.find(L": ");
                std::wstring key, value;
                if (colonPos == std::wstring::npos) {
                    key = lastLine;
                    value = L"";
                }
                else {
                    size_t keyStart = lastLine.substr(0, colonPos).find_first_not_of(L" \t");
                    size_t keyEnd = lastLine.substr(0, colonPos).find_last_not_of(L" \t");
                    key = (keyStart != std::wstring::npos) ? lastLine.substr(keyStart, keyEnd - keyStart + 1) : L"";

                    std::wstring valPart = lastLine.substr(colonPos + 2);
                    size_t valStart = valPart.find_first_not_of(L" \t");
                    size_t valEnd = valPart.find_last_not_of(L" \t");
                    value = (valStart != std::wstring::npos) ? valPart.substr(valStart, valEnd - valStart + 1) : L"";
                }
                if (!key.empty()) {
                    OBJECTStruct objStruct;
                    if (value == L"[object Object]") objStruct.data = OBJECT{};
                    else if (value == L"true") objStruct.data = true;
                    else if (value == L"false") objStruct.data = false;
                    else if (value.empty()) objStruct.data = nullptr_t{};
                    else {
                        bool isNum = false;
                        try { size_t p; int v = std::stoi(value, &p); if (p == value.length()) { objStruct.data = v; isNum = true; } }
                        catch (...) {}
                        if (!isNum) try { size_t p; long v = std::stol(value, &p); if (p == value.length()) { objStruct.data = v; isNum = true; } }
                        catch (...) {}
                        if (!isNum) try { size_t p; long long v = std::stoll(value, &p); if (p == value.length()) { objStruct.data = v; isNum = true; } }
                        catch (...) {}
                        if (!isNum) try { size_t p; unsigned int v = std::stoul(value, &p); if (p == value.length()) { objStruct.data = v; isNum = true; } }
                        catch (...) {}
                        if (!isNum) try { size_t p; unsigned long v = std::stoul(value, &p); if (p == value.length()) { objStruct.data = v; isNum = true; } }
                        catch (...) {}
                        if (!isNum) try { size_t p; unsigned long long v = std::stoull(value, &p); if (p == value.length()) { objStruct.data = v; isNum = true; } }
                        catch (...) {}
                        if (!isNum) try { size_t p; double v = std::stod(value, &p); if (p == value.length()) { objStruct.data = v; isNum = true; } }
                        catch (...) {}
                        if (!isNum) objStruct.data = value;
                    }
                    result.insert(std::make_pair(key, objStruct));
                }
            }
        }

        return result;
    }
    std::string GetRequestHeader(FCGX_Request* request) {
        std::string completeHeaders;
        if (request == nullptr || request->envp == nullptr) {
            return completeHeaders;
        }

        char** envp = request->envp;
        for (int i = 0; envp[i] != nullptr; ++i) {
            std::string envStr = envp[i];
            size_t equalPos = envStr.find('=');
            if (equalPos == std::string::npos || equalPos == envStr.size() - 1) {
                continue;
            }

            std::string key = envStr.substr(0, equalPos);
            std::string value = envStr.substr(equalPos + 1);
            std::string headerName;
            bool isHeader = false;

            if (key.compare(0, 5, "HTTP_") == 0) { // 更严谨的前缀匹配
                headerName = key.substr(5);
                // 还原头名称格式：下划线转横线，首字母大写，其余小写
                for (size_t j = 0; j < headerName.size(); ++j) {
                    if (headerName[j] == '_') {
                        headerName[j] = '-';
                    }
                    else if (j == 0) {
                        headerName[j] = static_cast<char>(std::toupper(static_cast<unsigned char>(headerName[j])));
                    }
                    else {
                        headerName[j] = static_cast<char>(std::tolower(static_cast<unsigned char>(headerName[j])));
                    }
                }
                isHeader = true;
            }
            else if (key == "CONTENT_TYPE") {
                headerName = "Content-Type";
                isHeader = true;
            }
            else if (key == "CONTENT_LENGTH") {
                headerName = "Content-Length";
                isHeader = true;
            }

            if (isHeader) {
                completeHeaders += headerName + ": " + value + "\r\n"; // 标准HTTP头换行符
            }
        }

        return completeHeaders;
    }
    bool ReadRequestBody(FCGX_Request* request, BYTEBUFFER_PTR bp) {
        if (!request || !bp) return false;
        bp->clear();

        const char* lenStr = FCGX_GetParam("CONTENT_LENGTH", request->envp);
        if (!lenStr || *lenStr == '\0') return true;

        char* endptr = nullptr;
        const long len = std::strtol(lenStr, &endptr, 10);
        if (endptr == lenStr || len <= 0) return true;

        bp->reserve(len);
        char tempBuf[4096];
        long totalRead = 0;
        while (totalRead < len) {
            const int toRead = static_cast<int>(std::min(static_cast<long>(sizeof(tempBuf)), len - totalRead));
            const int read = FCGX_GetStr(tempBuf, toRead, request->in);
            if (read <= 0) {
                bp->clear();
                return false;
            }
            bp->insert(bp->end(), reinterpret_cast<unsigned char*>(tempBuf), reinterpret_cast<unsigned char*>(tempBuf) + read);
            totalRead += read;
        }
        return true;
    }
    int GetStatusCode(const std::string& header) {
        const std::string status_prefix = "Status:";
        const size_t prefix_len = status_prefix.length();
        size_t pos = 0;
        const size_t header_len = header.length();
        while (pos <= header_len - prefix_len) {
            bool prefix_match = true;
            for (size_t i = 0; i < prefix_len; ++i) {
                if (tolower(header[pos + i]) != tolower(status_prefix[i])) {
                    prefix_match = false;
                    break;
                }
            }

            if (prefix_match) {
                pos += prefix_len;
                while (pos < header_len && isspace(static_cast<unsigned char>(header[pos]))) {
                    ++pos;
                }
                int status_code = 0;
                while (pos < header_len && isdigit(static_cast<unsigned char>(header[pos]))) {
                    status_code = status_code * 10 + (header[pos] - '0');
                    ++pos;
                }

                if (status_code >= 100 && status_code <= 599) {
                    return status_code;
                }
                else {
                    return -1;
                }
            }

            size_t crlf_pos = header.find("\r\n", pos);
            if (crlf_pos == std::string::npos) {
                break;
            }
            pos = crlf_pos + 2;
        }
        return -1;
    }
    ordered_map<std::string, std::string> GetAcceptAllowList(std::string allowString) {
        const std::string DEFAULT_ALLOW_METHODS = "GET, HEAD, OPTIONS";

        ordered_map<std::string, std::string> allowList;

        // 步骤1：处理输入字符串（空值则使用默认）
        std::string targetStr = allowString;
        if (targetStr.empty()) {
            targetStr = DEFAULT_ALLOW_METHODS;
        }

        // 步骤2：拆分逗号分隔的方法，按顺序处理
        std::istringstream ss(targetStr);
        std::string method;
        while (std::getline(ss, method, ',')) {
            // 去除方法名首尾的空白字符（空格、制表符等）
            method.erase(0, method.find_first_not_of(" \t\r\n"));
            method.erase(method.find_last_not_of(" \t\r\n") + 1);

            // 过滤空方法名
            if (method.empty()) {
                continue;
            }

            // 统一转大写（HTTP方法名标准为大写）
            std::transform(method.begin(), method.end(), method.begin(), ::toupper);

            // 按顺序存入ordered_map（去重：已存在则跳过，保证首次出现的顺序）
            if (allowList.find(method) == allowList.end()) {
                allowList[method] = method;
            }
        }

        // 步骤3：如果解析后为空（如输入全是无效字符），返回默认列表
        if (allowList.empty()) {
            allowList = GetAcceptAllowList(DEFAULT_ALLOW_METHODS);
        }

        return allowList;
    }

}

#endif