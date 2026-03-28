
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

#define MBEDTLS_ALLOW_PRIVATE_ACCESS 1

extern "C" {
#include "./thirdParty/quickjs-ng/include/quickjs.h"

#include "./thirdParty/fastcgi/include/fastcgi.h"
#include "./thirdParty/fastcgi/include/fcgi_config.h"
#include "./thirdParty/fastcgi/include/fcgi_stdio.h"
#include "./thirdParty/fastcgi/include/fcgiapp.h"
#include "./thirdParty/fastcgi/include/fcgimisc.h"
#include "./thirdParty/fastcgi/include/fcgio.h"
#include "./thirdParty/fastcgi/include/fcgios.h"
}

#include "./thirdParty/cryptopp/include/cryptlib.h"
#include "./thirdParty/cryptopp/include/osrng.h"
#include "./thirdParty/cryptopp/include/aes.h"
#include "./thirdParty/cryptopp/include/rsa.h"
#include "./thirdParty/cryptopp/include/eccrypto.h"
#include "./thirdParty/cryptopp/include/oids.h"
#include "./thirdParty/cryptopp/include/sha.h"
#include "./thirdParty/cryptopp/include/sha3.h"
#include "./thirdParty/cryptopp/include/asn.h"
#include "./thirdParty/cryptopp/include/xed25519.h"
#include "./thirdParty/cryptopp/include/chacha.h"


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

#pragma comment(lib, "ws2_32.lib")
#if defined(_WIN64)
#if defined(_DEBUG)
#pragma comment(lib, "\"" __FILE__ "/../thirdParty/quickjs-ng/lib/x64/Debug/qjs.lib\"")
#pragma comment(lib, "\"" __FILE__ "/../thirdParty/fastcgi/lib/x64/Debug/fcgi.lib\"")
#pragma comment(lib, "\"" __FILE__ "/../thirdParty/cryptopp/lib/x64/Debug/cryptopp.lib\"")
#else
#pragma comment(lib, "\"" __FILE__ "/../thirdParty/quickjs-ng/lib/x64/Release/qjs.lib\"")
#pragma comment(lib, "\"" __FILE__ "/../thirdParty/fastcgi/lib/x64/Release/fcgi.lib\"")
#pragma comment(lib, "\"" __FILE__ "/../thirdParty/cryptopp/lib/x64/Release/cryptopp.lib\"")
#endif
#elif defined(_WIN32)
#if defined(_DEBUG)
#pragma comment(lib, "\"" __FILE__ "/../thirdParty/quickjs-ng/lib/x86/Debug/qjs.lib\"")
#pragma comment(lib, "\"" __FILE__ "/../thirdParty/fastcgi/lib/x86/Debug/fcgi.lib\"")
#pragma comment(lib, "\"" __FILE__ "/../thirdParty/cryptopp/lib/x86/Debug/cryptopp.lib\"")
#else
#pragma comment(lib, "\"" __FILE__ "/../thirdParty/quickjs-ng/lib/x86/Release/qjs.lib\"")
#pragma comment(lib, "\"" __FILE__ "/../thirdParty/fastcgi/lib/x86/Release/fcgi.lib\"")
#pragma comment(lib, "\"" __FILE__ "/../thirdParty/cryptopp/lib/x86/Release/cryptopp.lib\"")
#endif
#endif
#undef min
#undef max

#ifndef crypto_auth_hmacsha1_KEYBYTES
#define crypto_auth_hmacsha1_KEYBYTES 20
#endif

#ifndef crypto_auth_hmacsha384_KEYBYTES
#define crypto_auth_hmacsha384_KEYBYTES 48
#endif


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
		return L"";
	}

	typedef unsigned long long ULL;

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


	class RunInThread {
	public:
		RunInThread() = default;

		// 省略原有其他方法（保持不变）...

		// 修复后的execute接口：即调即跑即释放，不阻塞调用线程
		template<typename F, typename... Args>
		static ULL execute(F&& func, Args&&... args) {
			std::lock_guard<std::mutex> lock(s_mtx);
			ULL task_id = 0;

			// 检查ID计数器是否溢出
			if (s_task_id_counter >= ULL(-1)) return 0;
			task_id = ++s_task_id_counter;
			s_pending_ids.insert(task_id);
			s_last_get_id = 0;

			try {
				// 创建一次性的控制块（使用shared_ptr保证生命周期）
				auto cb = std::make_shared<ThreadControlBlock>();
				cb->stop_flag = false;
				cb->task_ready = false;
				cb->task_done = false;
				cb->has_result = false;

				// 包装任务（移除内部锁操作）
				wrap_task_for_execute(cb, task_id, std::forward<F>(func), std::forward<Args>(args)...);

				// 创建线程（修改线程执行逻辑，移除内部锁等待）
				cb->thread = std::thread([cb]() {
					if (!cb->stop_flag && cb->task) {
						cb->task(); // 直接执行任务，无需锁等待
					}
					});

				if (!cb || !cb->thread.joinable()) {
					s_pending_ids.erase(task_id);
					return 0;
				}

				// 将控制块加入映射
				s_used_task_map[task_id] = cb;
				s_pending_ids.erase(task_id);

				// 分离线程，避免阻塞调用线程
				cb->thread.detach();

				return task_id;
			}
			catch (...) {
				s_pending_ids.erase(task_id);
				return 0;
			}
		}

		// 省略原有其他方法（保持不变）...

	private:
		struct ThreadControlBlock {
			std::thread thread;
			std::mutex mtx;
			std::condition_variable cv;
			std::condition_variable cv_await;
			bool stop_flag = false;
			bool task_ready = false;
			bool task_done = false;
			bool has_result = false;
			std::function<void()> task;
			std::any result;
		};

		// 清理execute任务的资源（保持不变）
		static void cleanup_execute_task(ULL task_id) {
			std::lock_guard<std::mutex> lock(s_mtx);
			auto it = s_used_task_map.find(task_id);
			if (it != s_used_task_map.end()) {
				s_used_task_map.erase(it);
			}
		}

		// 修复后的wrap_task_for_execute：移除cb->mtx锁操作
		template<typename F, typename... Args>
		static void wrap_task_for_execute(std::shared_ptr<ThreadControlBlock> cb, ULL task_id, F&& func, Args&&... args) {
			using ReturnType = std::invoke_result_t<F, Args...>;

			if constexpr (std::is_void_v<ReturnType>) {
				cb->task = [cb, task_id, func = std::forward<F>(func), args...]() mutable {
					try {
						func(args...);
					}
					catch (...) {
						// 捕获所有异常，避免线程崩溃
					}

					// 关键修复：移除cb->mtx锁操作
					// 直接标记状态（execute模式下无需线程间同步状态）
					cb->task_done = true;
					cb->has_result = false;
					cb->cv_await.notify_all();

					// 执行完成后立即清理资源
					cleanup_execute_task(task_id);
					};
			}
			else {
				cb->task = [cb, task_id, func = std::forward<F>(func), args...]() mutable {
					try {
						cb->result = func(args...);
						cb->has_result = true;
					}
					catch (...) {
						cb->result = ReturnType{};
						cb->has_result = true;
					}

					// 关键修复：移除cb->mtx锁操作
					cb->task_done = true;
					cb->cv_await.notify_all();

					// 执行完成后立即清理资源
					cleanup_execute_task(task_id);
					};
			}
		}

		// 原有方法保持不变...
		template<typename F, typename... Args>
		static void wrap_task(std::shared_ptr<ThreadControlBlock> cb, F&& func, Args&&... args) {
			using ReturnType = std::invoke_result_t<F, Args...>;

			if constexpr (std::is_void_v<ReturnType>) {
				cb->task = [cb, func = std::forward<F>(func), args...]() {
					try {
						func(args...);
					}
					catch (...) {}
					cb->task_done = true;
					cb->cv_await.notify_all();
					};
				cb->has_result = false;
			}
			else {
				cb->task = [cb, func = std::forward<F>(func), args...]() {
					try {
						cb->result = func(args...);
						cb->has_result = true;
					}
					catch (...) {
						cb->result = ReturnType{};
						cb->has_result = true;
					}
					cb->task_done = true;
					cb->cv_await.notify_all();
					};
			}
		}

		template<typename F, typename... Args>
		static std::shared_ptr<ThreadControlBlock> create_control_block(ULL task_id, F&& func, Args&&... args) {
			auto cb = std::make_shared<ThreadControlBlock>();
			cb->stop_flag = false;
			cb->task_ready = false;
			cb->task_done = false;
			cb->has_result = false;

			wrap_task(cb, std::forward<F>(func), std::forward<Args>(args)...);

			cb->thread = std::thread([cb]() {
				std::unique_lock<std::mutex> lock(cb->mtx);
				while (!cb->stop_flag) {
					cb->cv.wait(lock, [&]() {
						return cb->task_ready || cb->stop_flag;
						});

					if (cb->stop_flag) break;

					if (cb->task) {
						cb->task();
					}

					cb->task_ready = false;
				}
				});

			return cb;
		}

		static void trigger_task(const std::shared_ptr<ThreadControlBlock>& cb) {
			std::lock_guard<std::mutex> lock(cb->mtx);
			cb->task_ready = true;
			cb->cv.notify_one();
		}

		static std::mutex s_mtx;
		static std::atomic<ULL> s_task_id_counter;
		static std::unordered_map<ULL, std::shared_ptr<ThreadControlBlock>> s_used_task_map;
		static std::queue<ULL> s_reserved_ids_queue;
		static std::unordered_set<ULL> s_reserved_ids_set;
		static std::unordered_set<ULL> s_pending_ids;
		static ULL s_last_get_id;
	};
	std::mutex RunInThread::s_mtx;
	std::atomic<ULL> RunInThread::s_task_id_counter{ 10 };
	std::unordered_map<ULL, std::shared_ptr<RunInThread::ThreadControlBlock>> RunInThread::s_used_task_map;
	std::queue<ULL> RunInThread::s_reserved_ids_queue;
	std::unordered_set<ULL> RunInThread::s_reserved_ids_set;
	std::unordered_set<ULL> RunInThread::s_pending_ids;
	ULL RunInThread::s_last_get_id = 0;


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
		// 如果key不存在，返回默认浅灰色
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

	template <typename K, typename V>
	class ordered_map {
	private:
		std::vector<std::pair<K, V>> m_data;    // 有序存储键值对，保持插入顺序
		std::unordered_map<K, size_t> m_index_map; // 键到索引的映射，O(1)查找

	public:
		// 类型别名（与标准map一致）
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

		// 构造函数/析构函数/赋值运算符（标准语义）
		ordered_map() = default;
		ordered_map(std::initializer_list<value_type> init) {
			for (const auto& pair : init) {
				insert(pair);
			}
		}
		// 范围构造函数
		template <typename InputIt>
		ordered_map(InputIt first, InputIt last) {
			insert(first, last);
		}
		// 拷贝构造
		ordered_map(const ordered_map& other) : m_data(other.m_data), m_index_map(other.m_index_map) {}
		// 移动构造
		ordered_map(ordered_map&& other) noexcept
			: m_data(std::move(other.m_data)), m_index_map(std::move(other.m_index_map)) {
		}
		// 拷贝赋值
		ordered_map& operator=(const ordered_map& other) {
			if (this != &other) {
				m_data = other.m_data;
				m_index_map = other.m_index_map;
			}
			return *this;
		}
		// 移动赋值
		ordered_map& operator=(ordered_map&& other) noexcept {
			if (this != &other) {
				m_data = std::move(other.m_data);
				m_index_map = std::move(other.m_index_map);
			}
			return *this;
		}
		// 初始化列表赋值
		ordered_map& operator=(std::initializer_list<value_type> init) {
			clear();
			insert(init);
			return *this;
		}
		~ordered_map() = default;

		// 迭代器（标准map全迭代器支持：正向/const/反向/const反向）
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

		// 容量相关
		bool empty() const noexcept { return m_data.empty(); }
		size_type size() const noexcept { return m_data.size(); }
		size_type max_size() const noexcept { return std::min(m_data.max_size(), m_index_map.max_size()); }

		// 元素访问（修复：保证const正确性，右值键的移动语义）
		V& operator[](const K& key) {
			auto it = m_index_map.find(key);
			if (it != m_index_map.end()) {
				return m_data[it->second].second;
			}
			// 修复：先emplace到vector，再更新索引（避免二次构造）
			m_data.emplace_back(std::piecewise_construct,
				std::forward_as_tuple(key),
				std::forward_as_tuple(V{}));
			m_index_map[key] = m_data.size() - 1;
			return m_data.back().second;
		}

		V& operator[](K&& key) {
			auto it = m_index_map.find(key);
			if (it != m_index_map.end()) {
				return m_data[it->second].second;
			}
			// 修复：移动语义传递完整，避免浅拷贝
			m_data.emplace_back(std::piecewise_construct,
				std::forward_as_tuple(std::move(key)),
				std::forward_as_tuple(V{}));
			m_index_map[m_data.back().first] = m_data.size() - 1;
			return m_data.back().second;
		}

		V& at(const K& key) {
			auto it = m_index_map.find(key);
			if (it == m_index_map.end()) {
				throw std::out_of_range("ordered_map::at: key not found");
			}
			return m_data[it->second].second;
		}

		const V& at(const K& key) const {
			auto it = m_index_map.find(key);
			if (it == m_index_map.end()) {
				throw std::out_of_range("ordered_map::at: key not found");
			}
			return m_data[it->second].second;
		}

		reference at(size_type idx) {
			if (idx >= m_data.size()) {
				throw std::out_of_range("ordered_map::at: index out of range");
			}
			return m_data[idx];
		}

		const_reference at(size_type idx) const {
			if (idx >= m_data.size()) {
				throw std::out_of_range("ordered_map::at: index out of range");
			}
			return m_data[idx];
		}

		// 查找
		iterator find(const K& key) {
			auto it = m_index_map.find(key);
			return (it != m_index_map.end()) ? m_data.begin() + it->second : end();
		}

		const_iterator find(const K& key) const {
			auto it = m_index_map.find(key);
			return (it != m_index_map.end()) ? m_data.cbegin() + it->second : cend();
		}

		size_type count(const K& key) const {
			return m_index_map.count(key);
		}

		bool contains(const K& key) const noexcept {
			return m_index_map.contains(key);
		}

		iterator lower_bound(const K& key) {
			auto it = find(key);
			return it != end() ? it : end();
		}

		const_iterator lower_bound(const K& key) const {
			auto it = find(key);
			return it != cend() ? it : cend();
		}

		iterator upper_bound(const K& key) {
			auto it = find(key);
			return it != end() ? std::next(it) : end();
		}

		const_iterator upper_bound(const K& key) const {
			auto it = find(key);
			return it != cend() ? std::next(it) : cend();
		}

		std::pair<iterator, iterator> equal_range(const K& key) {
			return { lower_bound(key), upper_bound(key) };
		}

		std::pair<const_iterator, const_iterator> equal_range(const K& key) const {
			return { lower_bound(key), upper_bound(key) };
		}

		// 插入（修复：避免覆盖时的键拷贝丢失，保证移动语义）
		std::pair<iterator, bool> insert(const value_type& pair) {
			auto it = m_index_map.find(pair.first);
			if (it != m_index_map.end()) {
				// 仅更新值，不修改键（避免键的意外拷贝）
				m_data[it->second].second = pair.second;
				return { m_data.begin() + it->second, false };
			}
			m_data.push_back(pair);
			m_index_map[pair.first] = m_data.size() - 1;
			return { std::prev(m_data.end()), true };
		}

		std::pair<iterator, bool> insert(value_type&& pair) {
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
			(void)hint;
			return insert(pair).first;
		}

		iterator insert(const_iterator hint, value_type&& pair) {
			(void)hint;
			return insert(std::move(pair)).first;
		}

		template <typename InputIt>
		void insert(InputIt first, InputIt last) {
			for (; first != last; ++first) {
				insert(*first);
			}
		}

		void insert(std::initializer_list<value_type> init) {
			for (const auto& p : init) {
				insert(p);
			}
		}

		// 原位构造（彻底修复：MSVC兼容版，移除结构化绑定，修正返回值逻辑）
		template <typename... Args>
		std::pair<iterator, bool> emplace(Args&&... args) {
			// 步骤1：先构造临时pair，检查键是否已存在（避免vector无效修改）
			value_type temp_pair(std::forward<Args>(args)...);
			auto idx_it = m_index_map.find(temp_pair.first);

			// 键已存在：返回现有迭代器 + false
			if (idx_it != m_index_map.end()) {
				return { m_data.begin() + idx_it->second, false };
			}

			// 键不存在：插入到vector并更新索引
			m_data.push_back(std::move(temp_pair));
			size_type new_idx = m_data.size() - 1;
			m_index_map[m_data.back().first] = new_idx;
			return { m_data.begin() + new_idx, true };
		}

		// 带提示的原位构造
		template <typename... Args>
		iterator emplace_hint(const_iterator hint, Args&&... args) {
			(void)hint; // 忽略提示，保持插入顺序
			return emplace(std::forward<Args>(args)...).first;
		}

		// 擦除（优化：索引更新效率，避免全量遍历）
		size_type erase(const K& key) {
			auto it = m_index_map.find(key);
			if (it == m_index_map.end()) {
				return 0;
			}
			size_type idx = it->second;
			// 擦除vector中的元素
			m_data.erase(m_data.begin() + idx);
			m_index_map.erase(it);
			// 优化：仅遍历索引大于idx的元素，减少开销
			for (auto& [k, i] : m_index_map) {
				if (i > idx) {
					--i;
				}
			}
			return 1;
		}

		iterator erase(iterator pos) {
			if (pos == end()) {
				return end();
			}
			const K& key = pos->first;
			size_type idx = std::distance(begin(), pos);
			m_index_map.erase(key);
			iterator ret = m_data.erase(pos);
			// 仅更新后续索引
			for (auto& [k, i] : m_index_map) {
				if (i > idx) {
					--i;
				}
			}
			return ret;
		}

		iterator erase(const_iterator pos) {
			return erase(begin() + std::distance(cbegin(), pos));
		}

		iterator erase(iterator first, iterator last) {
			if (first == last) {
				return last;
			}
			// 收集要删除的键和起始索引
			std::vector<K> keys_to_erase;
			size_type start_idx = std::distance(begin(), first);
			size_type erase_count = std::distance(first, last);
			for (auto it = first; it != last; ++it) {
				keys_to_erase.push_back(it->first);
			}
			// 擦除vector中的范围
			iterator ret = m_data.erase(first, last);
			// 擦除索引并更新后续索引
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

		// 交换
		void swap(ordered_map& other) noexcept {
			m_data.swap(other.m_data);
			m_index_map.swap(other.m_index_map);
		}

		// 清除
		void clear() noexcept {
			m_data.clear();
			m_index_map.clear();
		}

		// 交换非成员函数
		friend void swap(ordered_map& lhs, ordered_map& rhs) noexcept {
			lhs.swap(rhs);
		}

		// 关系运算符重载
		friend bool operator==(const ordered_map& lhs, const ordered_map& rhs) {
			return lhs.m_data == rhs.m_data;
		}
		friend bool operator!=(const ordered_map& lhs, const ordered_map& rhs) {
			return !(lhs == rhs);
		}
		friend bool operator<(const ordered_map& lhs, const ordered_map& rhs) {
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
		// 存储所有键值对（允许重复键，按插入顺序）
		std::vector<std::pair<K, V>> m_data;
		// 键 -> 对应索引列表（一个键可映射多个索引）
		std::unordered_map<K, std::vector<size_t>> m_index_map;

	public:
		// 标准类型别名（完全对齐std::multimap）
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
		using key_compare = std::less<K>; // 兼容std::multimap的比较器

		// ===================== 构造/析构/赋值 =====================
		ordered_multimap() = default;
		ordered_multimap(std::initializer_list<value_type> init) {
			insert(init);
		}

		template <typename InputIt>
		ordered_multimap(InputIt first, InputIt last) {
			insert(first, last);
		}

		// 拷贝/移动构造/赋值（深拷贝索引和数据）
		ordered_multimap(const ordered_multimap& other)
			: m_data(other.m_data), m_index_map(other.m_index_map) {
		}

		ordered_multimap(ordered_multimap&& other) noexcept
			: m_data(std::move(other.m_data)), m_index_map(std::move(other.m_index_map)) {
		}

		ordered_multimap& operator=(const ordered_multimap& other) {
			if (this != &other) {
				m_data = other.m_data;
				m_index_map = other.m_index_map;
			}
			return *this;
		}

		ordered_multimap& operator=(ordered_multimap&& other) noexcept {
			if (this != &other) {
				m_data = std::move(other.m_data);
				m_index_map = std::move(other.m_index_map);
			}
			return *this;
		}

		ordered_multimap& operator=(std::initializer_list<value_type> init) {
			clear();
			insert(init);
			return *this;
		}

		~ordered_multimap() = default;

		// ===================== 迭代器 =====================
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

		// ===================== 容量 =====================
		bool empty() const noexcept { return m_data.empty(); }
		size_type size() const noexcept { return m_data.size(); }
		size_type max_size() const noexcept { return std::min(m_data.max_size(), m_index_map.max_size()); }

		// ===================== 元素访问 =====================
		// 注意：std::multimap 原生不支持operator[]（避免覆盖），这里可选实现（追加模式）
		// 若要严格对齐标准，可注释此函数
		V& operator[](const K& key) {
			m_data.emplace_back(key, V{});
			size_type new_idx = m_data.size() - 1;
			m_index_map[key].push_back(new_idx); // 追加索引，不覆盖
			return m_data.back().second;
		}

		V& operator[](K&& key) {
			m_data.emplace_back(std::move(key), V{});
			size_type new_idx = m_data.size() - 1;
			m_index_map[m_data.back().first].push_back(new_idx);
			return m_data.back().second;
		}

		// at(key)：std::multimap无此接口，若需要则返回第一个匹配键的值（或抛异常）
		V& at(const K& key) {
			auto it = m_index_map.find(key);
			if (it == m_index_map.end() || it->second.empty()) {
				throw std::out_of_range("ordered_multimap::at: key not found");
			}
			return m_data[it->second.front()].second;
		}

		const V& at(const K& key) const {
			auto it = m_index_map.find(key);
			if (it == m_index_map.end() || it->second.empty()) {
				throw std::out_of_range("ordered_multimap::at: key not found");
			}
			return m_data[it->second.front()].second;
		}

		// 按索引访问（扩展接口，保持原ordered_map特性）
		reference at(size_type idx) {
			if (idx >= m_data.size()) {
				throw std::out_of_range("ordered_multimap::at: index out of range");
			}
			return m_data[idx];
		}

		const_reference at(size_type idx) const {
			if (idx >= m_data.size()) {
				throw std::out_of_range("ordered_multimap::at: index out of range");
			}
			return m_data[idx];
		}

		// ===================== 查找（对齐std::multimap） =====================
		// 查找第一个匹配key的迭代器
		iterator find(const K& key) {
			auto it = m_index_map.find(key);
			if (it == m_index_map.end() || it->second.empty()) {
				return end();
			}
			return m_data.begin() + it->second.front();
		}

		const_iterator find(const K& key) const {
			auto it = m_index_map.find(key);
			if (it == m_index_map.end() || it->second.empty()) {
				return cend();
			}
			return m_data.cbegin() + it->second.front();
		}

		// 返回key的总个数（核心：支持重复键）
		size_type count(const K& key) const {
			auto it = m_index_map.find(key);
			return (it != m_index_map.end()) ? it->second.size() : 0;
		}

		// C++20 包含性检查（只要有一个匹配就返回true）
		bool contains(const K& key) const noexcept {
			auto it = m_index_map.find(key);
			return (it != m_index_map.end()) && !it->second.empty();
		}

		// 下界：第一个>=key的迭代器（按插入顺序返回第一个匹配key的迭代器）
		iterator lower_bound(const K& key) {
			return find(key);
		}

		const_iterator lower_bound(const K& key) const {
			return find(key);
		}

		// 上界：第一个>key的迭代器（按插入顺序返回最后一个匹配key的下一个迭代器）
		iterator upper_bound(const K& key) {
			auto it = m_index_map.find(key);
			if (it == m_index_map.end() || it->second.empty()) {
				return end();
			}
			// 最后一个匹配key的索引 +1
			return m_data.begin() + it->second.back() + 1;
		}

		const_iterator upper_bound(const K& key) const {
			auto it = m_index_map.find(key);
			if (it == m_index_map.end() || it->second.empty()) {
				return cend();
			}
			return m_data.cbegin() + it->second.back() + 1;
		}

		// 等范围：返回所有匹配key的迭代器范围（核心：支持重复键）
		std::pair<iterator, iterator> equal_range(const K& key) {
			return { lower_bound(key), upper_bound(key) };
		}

		std::pair<const_iterator, const_iterator> equal_range(const K& key) const {
			return { lower_bound(key), upper_bound(key) };
		}

		// ===================== 插入（核心：不覆盖，始终追加） =====================
		// 插入单个元素（始终成功，返回新元素迭代器）
		iterator insert(const value_type& pair) {
			size_type new_idx = m_data.size();
			m_data.push_back(pair);
			m_index_map[pair.first].push_back(new_idx); // 追加索引，不覆盖
			return m_data.begin() + new_idx;
		}

		iterator insert(value_type&& pair) {
			size_type new_idx = m_data.size();
			m_data.push_back(std::move(pair));
			m_index_map[m_data.back().first].push_back(new_idx);
			return m_data.begin() + new_idx;
		}

		// 带提示的插入（提示无效，按插入顺序追加）
		iterator insert(const_iterator hint, const value_type& pair) {
			(void)hint;
			return insert(pair);
		}

		iterator insert(const_iterator hint, value_type&& pair) {
			(void)hint;
			return insert(std::move(pair));
		}

		// 范围插入
		template <typename InputIt>
		void insert(InputIt first, InputIt last) {
			for (; first != last; ++first) {
				insert(*first);
			}
		}

		// 初始化列表插入
		void insert(std::initializer_list<value_type> init) {
			for (const auto& p : init) {
				insert(p);
			}
		}

		// 原位构造（emplace）：直接构造，不覆盖，追加新元素
		template <typename... Args>
		iterator emplace(Args&&... args) {
			size_type new_idx = m_data.size();
			m_data.emplace_back(std::forward<Args>(args)...);
			m_index_map[m_data.back().first].push_back(new_idx);
			return m_data.begin() + new_idx;
		}

		// 带提示的原位构造
		template <typename... Args>
		iterator emplace_hint(const_iterator hint, Args&&... args) {
			(void)hint;
			return emplace(std::forward<Args>(args)...);
		}

		// ===================== 擦除（支持删除单个/范围/所有匹配键） =====================
		// 擦除所有匹配key的元素，返回删除的个数
		size_type erase(const K& key) {
			auto it = m_index_map.find(key);
			if (it == m_index_map.end() || it->second.empty()) {
				return 0;
			}

			// 收集要删除的索引（倒序删除，避免索引错乱）
			std::vector<size_type> indices = it->second;
			std::sort(indices.rbegin(), indices.rend());

			size_type erase_count = indices.size();
			for (size_type idx : indices) {
				m_data.erase(m_data.begin() + idx);
			}

			// 移除key的索引记录
			m_index_map.erase(it);

			// 更新所有大于被删除索引的元素的索引
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

		// 擦除单个迭代器指向的元素，返回下一个迭代器
		iterator erase(iterator pos) {
			if (pos == end()) {
				return end();
			}

			const K& key = pos->first;
			size_type idx = std::distance(begin(), pos);

			// 从索引映射中移除该索引
			auto it = m_index_map.find(key);
			if (it != m_index_map.end()) {
				auto& idx_list = it->second;
				auto idx_it = std::find(idx_list.begin(), idx_list.end(), idx);
				if (idx_it != idx_list.end()) {
					idx_list.erase(idx_it);
				}
				// 若该键无剩余索引，移除整个键
				if (idx_list.empty()) {
					m_index_map.erase(it);
				}
			}

			// 擦除vector中的元素
			iterator ret = m_data.erase(pos);

			// 更新后续元素的索引
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

		// const迭代器版本擦除
		iterator erase(const_iterator pos) {
			return erase(begin() + std::distance(cbegin(), pos));
		}

		// 范围擦除
		iterator erase(iterator first, iterator last) {
			if (first == last) {
				return last;
			}

			// 收集要删除的键和索引
			std::vector<K> keys_to_update;
			std::vector<size_type> indices_to_erase;
			size_type start_idx = std::distance(begin(), first);
			size_type erase_count = std::distance(first, last);

			for (auto it = first; it != last; ++it) {
				keys_to_update.push_back(it->first);
				indices_to_erase.push_back(std::distance(begin(), it));
			}

			// 倒序删除vector中的元素
			std::sort(indices_to_erase.rbegin(), indices_to_erase.rend());
			for (size_type idx : indices_to_erase) {
				m_data.erase(m_data.begin() + idx);
			}

			// 从索引映射中移除对应索引
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

			// 更新所有受影响的索引
			for (auto& [k, idx_list] : m_index_map) {
				for (size_t& i : idx_list) {
					if (i >= start_idx) {
						i -= erase_count;
					}
				}
			}

			return begin() + start_idx;
		}

		// ===================== 其他接口 =====================
		void swap(ordered_multimap& other) noexcept {
			m_data.swap(other.m_data);
			m_index_map.swap(other.m_index_map);
		}

		void clear() noexcept {
			m_data.clear();
			m_index_map.clear();
		}

		friend void swap(ordered_multimap& lhs, ordered_multimap& rhs) noexcept {
			lhs.swap(rhs);
		}

		// 关系运算符（按插入顺序比较所有元素）
		friend bool operator==(const ordered_multimap& lhs, const ordered_multimap& rhs) {
			return lhs.m_data == rhs.m_data;
		}

		friend bool operator!=(const ordered_multimap& lhs, const ordered_multimap& rhs) {
			return !(lhs == rhs);
		}

		friend bool operator<(const ordered_multimap& lhs, const ordered_multimap& rhs) {
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

		// 兼容std::multimap的key_comp()
		key_compare key_comp() const {
			return key_compare();
		}
	};
	using GMT = ordered_map<std::wstring, std::wstring>;
	using GMMT = ordered_multimap<std::wstring, std::wstring>;

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
						throw std::invalid_argument("Unsupported type in OBJECTStruct");
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
								throw std::invalid_argument("Expected string key");
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
										throw std::invalid_argument("Incomplete escape");
									}
									if (ptr[pos] == L'"') sk += L'"';
									else if (ptr[pos] == L'\\') sk += L'\\';
									else if (ptr[pos] == L'/') sk += L'/';
									else if (ptr[pos] == L'b') sk += L'\b';
									else if (ptr[pos] == L'f') sk += L'\f';
									else if (ptr[pos] == L'n') sk += L'n';
									else if (ptr[pos] == L'r') sk += L'r';
									else if (ptr[pos] == L't') sk += L't';
									else if (ptr[pos] == L'u') {
										pos++;
										if (pos + 3 >= len) {
											throw std::invalid_argument("Incomplete Unicode");
										}
										wchar_t u[5] = { 0 };
										for (int i = 0; i < 4; i++) {
											u[i] = ptr[pos + i];
											if (!std::iswxdigit(u[i])) {
												throw std::invalid_argument("Invalid Unicode char");
											}
										}
										unsigned int c = std::wcstoul(u, nullptr, 16);
										sk += (wchar_t)c;
										pos += 4;
										continue;
									}
									else {
										throw std::invalid_argument("Invalid escape");
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
								throw std::invalid_argument("Expected colon");
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
								throw std::invalid_argument("Expected comma or brace");
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
								throw std::invalid_argument("Expected comma or bracket");
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
								throw std::invalid_argument("Incomplete escape");
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
									throw std::invalid_argument("Incomplete Unicode");
								}
								wchar_t u[5] = { 0 };
								for (int i = 0; i < 4; i++) {
									u[i] = ptr[pos + i];
									if (!std::iswxdigit(u[i])) {
										throw std::invalid_argument("Invalid Unicode char");
									}
								}
								unsigned int c = std::wcstoul(u, nullptr, 16);
								s += (wchar_t)c;
								pos += 4;
								continue;
							}
							else {
								throw std::invalid_argument("Invalid escape");
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
						throw std::invalid_argument("Invalid true");
					}
					pos += 4;
					res.data = true;
				}
				else if (ptr[pos] == L'f') {
					if (pos + 4 >= len || !(ptr[pos + 1] == L'a' && ptr[pos + 2] == L'l' && ptr[pos + 3] == L's' && ptr[pos + 4] == L'e')) {
						throw std::invalid_argument("Invalid false");
					}
					pos += 5;
					res.data = false;
				}
				else if (ptr[pos] == L'n') {
					if (pos + 3 >= len || !(ptr[pos + 1] == L'u' && ptr[pos + 2] == L'l' && ptr[pos + 3] == L'l')) {
						throw std::invalid_argument("Invalid null");
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
							throw std::invalid_argument("Invalid decimal");
						}
						while (pos < len && std::iswdigit(ptr[pos])) pos++;
					}
					bool hasExponent = false;
					if (pos < len && (ptr[pos] == L'e' || ptr[pos] == L'E')) {
						hasExponent = true;
						pos++;
						if (pos < len && (ptr[pos] == L'+' || ptr[pos] == L'-')) pos++;
						if (pos >= len || !std::iswdigit(ptr[pos])) {
							throw std::invalid_argument("Invalid exponent");
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
					throw std::invalid_argument("Unexpected char: " + wstringToString(std::wstring(1, ptr[pos])));
				}

				if (reviver) {
					res = reviver(key, res);
				}
				return res;
				};

			while (pos < len && ptr[pos] != L'\0' && std::iswspace(ptr[pos])) pos++;
			if (pos >= len || (ptr[pos] != L'{' && ptr[pos] != L'[')) {
				throw std::invalid_argument("Root must be object or array");
			}

			OBJECTStruct root = parseValue(L"");
			if (root.isArray()) {
				OBJECT wrapper;
				wrapper[L""] = root;
				return wrapper;
			}
			if (!std::holds_alternative<OBJECT>(root.data)) {
				throw std::invalid_argument("Root is not object");
			}
			return std::get<OBJECT>(root.data);
		}

	};
	JSONStruct JSON;

	OBJECT configObject = {};

	GMMT extensionList = {};
	HINSTANCE hInst = NULL;
	ordered_map<std::wstring, std::wstring> commandArgList = {};
	std::wstring commandStartFilePath = L"";
	std::wstring errorOutput = L"";
	GMMT outputTemp = {};


	bool isStartByFastCgi = false;

	double timeout = 0.0;
	bool isFlushNamedPipe = false;
	bool isOutputError = false;
	bool isStrictStandard = false;
	bool isModernMode = false;

	bool isShowReturnValue = false;
	bool isShowReturnDetail = false;

	void updateConfig() {

		if (!isStartByFastCgi) {
			try {
				isShowReturnValue = configObject[L"shell"][L"isShowReturnValue"].get<bool>();
				isShowReturnDetail = configObject[L"shell"][L"isShowReturnDetail"].get<bool>();
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

		// ========== 新增：null/NaN/undefined 检测正则（优先匹配） ==========
		const std::wregex specialValueRegex(
			LR"(\b(null|NaN|undefined)\b)",  // 单词边界匹配，避免匹配到包含这些字符的其他单词
			std::regex_constants::optimize | std::regex_constants::icase
		);
		// 原生函数匹配正则（保留优化后的版本）
		const std::wregex funcRegex(
			LR"((function\s+(\w+)\s*\([\s\S]*?\)\s*\{[\s\S]*?\[native code\][\s\S]*?\}))",
			std::regex_constants::optimize
		);

		std::wsmatch match;
		std::wstring remainingCode = code;
		// 第一步：优先处理 null/NaN/undefined
		while (std::regex_search(remainingCode, match, specialValueRegex)) {
			// 1. 处理匹配前的未识别内容（默认DarkGray）
			if (match.position() > 0) {
				std::wstring unMatched = remainingCode.substr(0, match.position());
				colorMap[unMatched] = L"DarkGray";
			}
			// 2. 处理 null/NaN/undefined（强制DarkGray）
			std::wstring specialValue = match[1].str();
			colorMap[specialValue] = L"DarkGray";
			// 3. 更新剩余文本
			size_t matchEndPos = match.position() + match.length();
			remainingCode = remainingCode.substr(matchEndPos);
			if (remainingCode.empty()) break;
		}

		// 第二步：处理原生函数（复用之前优化的逻辑）
		std::wsmatch funcMatch;
		while (std::regex_search(remainingCode, funcMatch, funcRegex)) {
			// 1. 处理函数匹配前的未识别内容（默认Gray）
			if (funcMatch.position() > 0) {
				std::wstring unMatched = remainingCode.substr(0, funcMatch.position());
				colorMap[unMatched] = L"Gray";
			}

			// 2. 处理匹配的函数块（优化后的配色逻辑）
			std::wstring fullFuncBlock = funcMatch[1].str();
			std::wstring funcName = funcMatch[2].str();
			std::wstring colorType = L"Function"; // 默认兜底

			// 核心内置构造函数 → BuiltInObject
			if (funcName == L"Array" || funcName == L"Object" || funcName == L"String" ||
				funcName == L"Number" || funcName == L"Boolean" || funcName == L"Date" ||
				funcName == L"RegExp" || funcName == L"Map" || funcName == L"Set") {
				colorType = L"BuiltInObject";
			}
			// 异步/特殊内置构造函数 → 专属配色
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
			// 全局工具函数 → BuiltInFunction
			else if (funcName == L"parseInt" || funcName == L"parseFloat" || funcName == L"eval" ||
				funcName == L"decodeURI" || funcName == L"encodeURI" || funcName == L"isNaN" ||
				funcName == L"isFinite") {
				colorType = L"BuiltInFunction";
			}
			// 全局对象 → BuiltInObject
			else if (funcName == L"JSON" || funcName == L"console") {
				colorType = L"BuiltInObject";
			}

			colorMap[fullFuncBlock] = colorType;

			// 3. 更新剩余文本
			size_t matchEndPos = funcMatch.position() + funcMatch.length();
			remainingCode = remainingCode.substr(matchEndPos);
			if (remainingCode.empty()) break;
		}

		// 处理最后剩余的未识别内容（兜底Gray）
		if (!remainingCode.empty()) {
			colorMap[remainingCode] = L"DarkGray";
		}

		return colorMap;
	}

	GMT GetCommandArgList() {
		ordered_map<std::wstring, std::wstring> arg_map;
		int argc = 0;
		wchar_t** argv = CommandLineToArgvW(GetCommandLineW(), &argc);

		if (!argv || argc <= 1) {
			if (argv) LocalFree(argv);
			return arg_map;
		}

		for (int i = 1; i < argc; ++i) {
			const wchar_t* arg_ptr = argv[i];
			if (!arg_ptr || !*arg_ptr) continue;

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

	bool CreateConsole(std::wstring title = L"console") {

		isConsoleEnv = true;

		BOOL bAttachSuccess = AttachConsole(ATTACH_PARENT_PROCESS);
		if (bAttachSuccess) {
			SetConsoleTitleW(title.c_str());
			FILE* fp = nullptr;
			freopen_s(&fp, "CONOUT$", "w", stdout);
			freopen_s(&fp, "CONIN$", "r", stdin);

			HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
			SetConsoleMode(hIn, ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT);

			std::ios::sync_with_stdio(true);
			std::wcout.imbue(std::locale(""));
			std::wcin.imbue(std::locale(""));
			return true;
		}

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
		if (lResult == ERROR_SUCCESS) {
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
			}
			else {
				bool bReady = false;
				auto startTime = std::chrono::steady_clock::now();
				int detectInterval = 1;
				const int TOTAL_WAIT_MS = 2000;
				const int HIGH_FREQ_DURATION = 500;

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

					Sleep(detectInterval);
				}

				if (AttachConsole(pi.dwProcessId)) {
					SetConsoleTitleW(title.c_str());
					TerminateProcess(pi.hProcess, 0);
					isWTConsole = true;
				}
				else {
					AllocConsole();
					SetConsoleTitleW(title.c_str());
				}

				CloseHandle(pi.hProcess);
				CloseHandle(pi.hThread);
				delete[] szCmd;
			}
		}
		else {
			if (!AllocConsole()) return false;
			SetConsoleTitleW(title.c_str());
		}

		FILE* fp = nullptr;
		freopen_s(&fp, "CONOUT$", "w", stdout);
		freopen_s(&fp, "CONIN$", "r", stdin);

		HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
		SetConsoleMode(hIn, ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT);

		std::ios::sync_with_stdio(true);
		std::wcout.imbue(std::locale(""));
		std::wcin.imbue(std::locale(""));
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
			// 1. 优先检测退出标记（即时响应，无延迟）
			if (isQuit.load(std::memory_order_acquire)) {
				break;
			}

			std::wstring currentLine;
			WCHAR buffer[BUFFER_SIZE] = { 0 };
			DWORD dwRead = 0;

			// 2. 非阻塞检测输入：无输入时直接循环（无Sleep，无延迟）
			DWORD dwAvail = 0;
			if (!GetNumberOfConsoleInputEvents(hStdIn, &dwAvail)) {
				break;
			}
			// 只有有输入事件时才调用ReadConsoleW（避免阻塞）
			if (dwAvail == 0) {
				continue; // 无输入直接循环，无Sleep，无延迟
			}

			// 3. 读取输入（原生ReadConsoleW，和系统默认输入响应一致）
			ZeroMemory(buffer, sizeof(buffer));
			if (!ReadConsoleW(hStdIn, buffer, BUFFER_SIZE - 1, &dwRead, nullptr)) {
				break;
			}
			currentLine.append(buffer, dwRead);

			// 4. 读取后再次检测退出标记（防止读取中触发退出）
			if (isQuit.load(std::memory_order_acquire)) {
				break;
			}

			// 保留你原有所有换行符处理逻辑（一字未改）
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
		// Hex转RGB逻辑（保留原有容错，仅优化变量命名）
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

		// 解析前景/背景色（区分背景默认值）
		RGBColor fgRgb = hex2rgb(fgColor, false);
		RGBColor bgRgb = hex2rgb(bgColor, true);

		// WT终端模式：返回默认属性字（实际CreateOutput走ANSI逻辑，不影响）
		if (isWTConsole) {
			return 0x0F; // 白字黑底（0x0F = 背景0 + 前景15）
		}

		// 标准控制台16色RGB映射（保留原有精准映射）
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

		// 加权距离计算（保留人眼视觉感知优化）
		auto rgbDist = [](const RGBColor& c1, const RGBColor& c2) -> double {
			int dr = c1.r - c2.r;
			int dg = c1.g - c2.g;
			int db = c1.b - c2.b;
			return std::sqrt(0.299 * dr * dr + 0.587 * dg * dg + 0.114 * db * db);
			};

		// ========== 修复点1：优化前景色匹配逻辑，精准匹配彩色 ==========
		int fgIdx = 7; // 默认浅灰
		double minFgDist = 1e9;
		// 先优先匹配彩色（0-6,9-14），再匹配灰度（7-8,15）
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
		const double SATURATION_THRESHOLD = 0.2;    // 低饱和度阈值（仅灰度色触发）
		const double DISTANCE_THRESHOLD = 100.0;    // 匹配度极低阈值（大幅提高）

		if (saturation < SATURATION_THRESHOLD && minFgDist > DISTANCE_THRESHOLD) {
			// 仅对低饱和度的灰度色执行兜底
			int gray = (fgRgb.r * 299 + fgRgb.g * 587 + fgRgb.b * 114) / 1000;
			if (gray <= 40) fgIdx = 0;    // 近黑 → 0号
			else if (gray <= 120) fgIdx = 8; // 深灰 → 8号
			else if (gray <= 200) fgIdx = 7; // 浅灰 → 7号
			else fgIdx = 15;              // 近白 → 15号
		}

		// ========== 修复点3：背景色匹配逻辑简化，保留原有逻辑但不强制兜底 ==========
		int bgIdx = 0; // 默认黑色
		double minBgDist = 1e9;
		for (int i = 0; i < 16; i++) {
			double dist = rgbDist(bgRgb, console16[i]);
			if (dist < minBgDist) {
				minBgDist = dist;
				bgIdx = i;
			}
		}

		// 生成最终16位属性字（高4位背景，低4位前景）
		WORD finalAttr = (static_cast<WORD>(bgIdx) << 4) | static_cast<WORD>(fgIdx);

		// 最终兜底：仅避免纯黑字黑底（0），保留其他彩色组合
		if (finalAttr == 0) finalAttr = 0x08; // 深灰字黑底

		return finalAttr;
	}

	void CreateOutput(const std::wstring& outputData, WORD color) {
		if (!isConsoleEnv) {
			outputTemp[outputData] = L"";
			return;
		}
		HANDLE hConsole = CreateFileW(L"CONOUT$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (hConsole == INVALID_HANDLE_VALUE) { std::wcout << outputData; std::wcout.flush(); return; }
		CONSOLE_SCREEN_BUFFER_INFO csbi = { 0 };
		WORD originalAttr = 0x0F;
		if (GetConsoleScreenBufferInfo(hConsole, &csbi)) originalAttr = csbi.wAttributes;
		SetConsoleTextAttribute(hConsole, color);
		std::wcout.flush(); std::wcout << outputData; std::wcout.flush();
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
			std::wcout << ansi << outputData << L"\x1b[0m" << std::flush;
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

	std::wstreambuf* RedirectOutputWstream(std::wstringstream& wss) {
		try {
			std::wstreambuf* original_buf = std::wcout.rdbuf();
			std::wcout.rdbuf(wss.rdbuf());
			return original_buf;
		}
		catch (...) {
			return nullptr;
		}
	}
	void RestoreOutputWstream(std::wstreambuf* original_buf) {
		if (original_buf != nullptr) {
			std::wcout.rdbuf(original_buf);
		}
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

	std::wstring GetErrorFront(JSContext* jsContext, JSValue& exception) {
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

	std::vector<std::wstring> GetErrorFrontStack(JSContext* jsContext, JSValue& exception) {
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

	typedef std::vector<unsigned char> BYTEBUFFER, *BYTEBUFFER_PTR;

	std::string GetTextFromBinary(BYTEBUFFER_PTR binaryPtr)
	{
		// 边界校验1：指针为空，直接返回空字符串
		if (binaryPtr == nullptr)
		{
			return "";
		}

		// 边界校验2：缓冲区为空，返回空字符串
		const BYTEBUFFER& binaryBuf = *binaryPtr;
		if (binaryBuf.empty())
		{
			return "";
		}

		// 核心转换：按字节构造UTF-8字符串
		// 利用std::string的构造函数：string(const char* s, size_t n)
		// (unsigned char*)转char*是安全的，仅符号位差异，不破坏UTF-8字节流
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
			path = GetAbsolutePath(InPath, base);
			isValid = exists();

			if (isValid) {
				hLockedHandle = LockPath(path);
				isValid = (hLockedHandle != INVALID_HANDLE_VALUE);
			}
		}

		~FileController() {
			ReleaseLock();
		}

		FileController(const FileController&) = delete;
		FileController& operator=(const FileController&) = delete;

		FileController(FileController&& other) noexcept {
			path = std::move(other.path);
			isValid = other.isValid;
			hLockedHandle = other.hLockedHandle;
			lockTempFilePath = std::move(other.lockTempFilePath);
			other.hLockedHandle = INVALID_HANDLE_VALUE;
			other.isValid = false;
		}

		FileController& operator=(FileController&& other) noexcept {
			if (this != &other) {
				ReleaseLock();
				path = std::move(other.path);
				isValid = other.isValid;
				hLockedHandle = other.hLockedHandle;
				lockTempFilePath = std::move(other.lockTempFilePath);
				other.hLockedHandle = INVALID_HANDLE_VALUE;
				other.isValid = false;
			}
			return *this;
		}

		bool isValid = true;

		bool isFile() {
			return std::filesystem::is_regular_file(path) || std::filesystem::is_symlink(path);
		}

		bool isDir() {
			return std::filesystem::is_directory(path);
		}

		ULL count() {
			if (!std::filesystem::exists(path)) {
				return 0;
			}
			std::uintmax_t count = 0;
			try {
				if (std::filesystem::is_regular_file(path) || std::filesystem::is_symlink(path)) {
					return 0;
				}
				if (std::filesystem::is_directory(path)) {
					for (const auto& entry : std::filesystem::recursive_directory_iterator(path)) {
						count++;
					}
				}
			}
			catch (...) {}
			return count;
		}

		ULL remove() {
			ReleaseLock();
			return std::filesystem::remove_all(path);
		}

		bool exists() {
			return std::filesystem::exists(path);
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
			catch (const std::filesystem::filesystem_error& e) {
				(void)e;
				return 0;
			}
			catch (const std::exception& e) {
				(void)e;
				return 0;
			}
		}

		GMMT list() {
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

		bool read(ULL base, ULL size, BYTEBUFFER_PTR out) {
			if (std::filesystem::is_directory(path)) {
				return false;
			}

			if (out == nullptr || !exists()) {
				return false;
			}

			try {
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
			if (std::filesystem::is_directory(path)) {
				return 0;
			}

			if (!buffer || buffer->empty()) {
				return 0;
			}

			const ULL write_data_size = buffer->size();
			std::fstream file;
			ULL write_start = base;

			try {
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
				if (file.is_open()) {
					file.close();
				}
				return 0;
			}
		}

		bool clear() {
			std::fstream file;
			try {
				file.open(path, std::ios::out | std::ios::binary | std::ios::trunc);

				if (!file.is_open()) {
					return false;
				}

				file.close();

				return !file.fail();
			}
			catch (...) {
				if (file.is_open()) {
					file.close();
				}
				return false;
			}
		}

	private:
		HANDLE hLockedHandle = INVALID_HANDLE_VALUE;
		std::wstring lockTempFilePath;
		BYTEBUFFER writeDataTemp = {};
		std::wstring path = L"";

		HANDLE LockPath(const std::wstring& path) {
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

		void ReleaseLock() {
			if (hLockedHandle != INVALID_HANDLE_VALUE) {
				CloseHandle(hLockedHandle);
				hLockedHandle = INVALID_HANDLE_VALUE;
			}
			if (!lockTempFilePath.empty() && std::filesystem::exists(lockTempFilePath)) {
				std::filesystem::remove(lockTempFilePath);
				lockTempFilePath.clear();
			}
		}
	};

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
		// 处理空指针或空缓冲区的情况，直接返回空宽字符串
		if (!byteBuffer || byteBuffer->empty())
		{
			return L"";
		}

		// 获取 UTF-8 数据指针和长度
		const char* utf8_data = reinterpret_cast<const char*>(byteBuffer->data());
		int utf8_len = static_cast<int>(byteBuffer->size());

		// 第一步：计算需要的宽字符长度（CP_UTF8 表示源是 UTF-8）
		// MB_ERR_INVALID_CHARS：遇到无效字符时失败，便于排查问题
		int wchar_len = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8_data, utf8_len, nullptr, 0);
		if (wchar_len == 0)
		{
			// 获取错误码，便于调试（生产环境可根据需要记录日志）
			DWORD error = GetLastError();
			// 常见错误：ERROR_NO_UNICODE_TRANSLATION（无效UTF-8字符）
			// 即使转换失败，也返回空字符串保证函数稳定性
			return L"";
		}

		// 第二步：分配内存并执行转换
		std::wstring result(wchar_len, L'\0');
		int converted_len = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8_data, utf8_len, &result[0], wchar_len);

		// 验证转换是否完全成功
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

	const char base16CodingMap[] = "0123456789ABCDEF";
	const char base32CodingMap[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
	const char base58CodingMap[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
	const char base62CodingMap[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	const char base64CodingMap[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	const char base85CodingMap[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~";
	const char base91CodingMap[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~\"";

	const char base64UrlCodingMap[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
	const char base91UrlCodingMap[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~-";

	bool BaseXToBinary(BYTEBUFFER_PTR binaryPtr, uint64_t base /*= 64*/, bool isUrl /*= false*/) {
		if (binaryPtr == nullptr || binaryPtr->empty() || base < 2) {
			return false;
		}
		BYTEBUFFER& input = *binaryPtr;
		BYTEBUFFER result;

		const char* codingMap = nullptr;
		switch (base) {
		case 16: codingMap = base16CodingMap; break;
		case 32: codingMap = base32CodingMap; break;
		case 58: codingMap = base58CodingMap; break;
		case 62: codingMap = base62CodingMap; break;
		case 64: codingMap = isUrl ? base64UrlCodingMap : base64CodingMap; break;
		case 85: codingMap = base85CodingMap; break;
		case 91: codingMap = isUrl ? base91UrlCodingMap : base91CodingMap; break;
		default: return false;
		}

		uint8_t bitWidth = 0;
		switch (base) {
		case 16: bitWidth = 4; break;
		case 32: bitWidth = 5; break;
		case 58: bitWidth = 6; break;
		case 62: bitWidth = 6; break;
		case 64: bitWidth = 6; break;
		case 85: bitWidth = 8; break;
		case 91: bitWidth = 7; break;
		default: return false;
		}
		if (bitWidth == 0) return false;

		size_t padding = 0;
		size_t originalInputSize = input.size();
		if (base == 64 || base == 32) {
			while (!input.empty() && input.back() == '=') {
				padding++;
				input.pop_back();
			}
			if ((base == 64 && padding > 2) || (base == 32 && padding > 6)) {
				return false;
			}
		}

		int charToVal[256];
		memset(charToVal, -1, sizeof(charToVal));
		for (int i = 0; codingMap[i] != '\0'; ++i) {
			charToVal[(unsigned char)codingMap[i]] = i;
		}

		uint64_t buffer = 0;
		size_t bufferBits = 0;
		for (unsigned char c : input) {
			int val = charToVal[(unsigned char)c];
			if (val == -1) return false;

			buffer = (buffer << bitWidth) | (uint64_t)val;
			bufferBits += bitWidth;

			while (bufferBits >= 8) {
				bufferBits -= 8;
				uint8_t byte = (buffer >> bufferBits) & 0xFF;
				result.push_back(byte);
			}
		}

		size_t totalEffectiveBits = (originalInputSize - padding) * bitWidth;
		size_t expectedBytes = totalEffectiveBits / 8;
		if (result.size() > expectedBytes) {
			result.resize(expectedBytes);
		}

		*binaryPtr = std::move(result);
		return true;
	}
	bool BinaryToBaseX(BYTEBUFFER_PTR binaryPtr, uint64_t base /*= 64*/, bool isUrl /*= false*/) {
		if (binaryPtr == nullptr || binaryPtr->empty() || base < 2) {
			return false;
		}
		BYTEBUFFER& input = *binaryPtr;
		BYTEBUFFER result;

		const char* codingMap = nullptr;
		switch (base) {
		case 16: codingMap = base16CodingMap; break;
		case 32: codingMap = base32CodingMap; break;
		case 58: codingMap = base58CodingMap; break;
		case 62: codingMap = base62CodingMap; break;
		case 64: codingMap = isUrl ? base64UrlCodingMap : base64CodingMap; break;
		case 85: codingMap = base85CodingMap; break;
		case 91: codingMap = isUrl ? base91UrlCodingMap : base91CodingMap; break;
		default: return false;
		}

		uint8_t bitWidth = 0;
		switch (base) {
		case 16: bitWidth = 4; break;
		case 32: bitWidth = 5; break;
		case 58: bitWidth = 6; break;
		case 62: bitWidth = 6; break;
		case 64: bitWidth = 6; break;
		case 85: bitWidth = 8; break;
		case 91: bitWidth = 7; break;
		default: return false;
		}
		if (bitWidth == 0) return false;

		uint64_t buffer = 0;
		size_t bufferBits = 0;
		size_t inputSize = input.size();
		for (size_t i = 0; i < inputSize; ++i) {
			buffer = (buffer << 8) | static_cast<uint8_t>(input[i]);
			bufferBits += 8;

			while (bufferBits >= bitWidth) {
				bufferBits -= bitWidth;
				uint64_t val = (buffer >> bufferBits) & ((1ULL << bitWidth) - 1);
				result.push_back(static_cast<unsigned char>(codingMap[val]));
			}
		}

		if (bufferBits > 0) {
			buffer <<= (bitWidth - bufferBits);
			uint64_t val = buffer & ((1ULL << bitWidth) - 1);
			result.push_back(static_cast<unsigned char>(codingMap[val]));
		}

		size_t lcm = 0;
		switch (base) {
		case 16: lcm = 2; break;
		case 32: lcm = 8; break;
		case 58: lcm = 1; break;
		case 62: lcm = 1; break;
		case 64: lcm = 4; break;
		case 85: lcm = 1; break;
		case 91: lcm = 1; break;
		default: lcm = 1;
		}

		if (lcm > 1) {
			size_t paddingCount = (lcm - (result.size() % lcm)) % lcm;
			for (size_t i = 0; i < paddingCount; ++i) {
				result.push_back('=');
			}
		}

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

	void DeleteInstance(JavaScript* instance);
	JavaScript* NewInstance();
	bool InitInstance(JavaScript* instance, JSRuntime* InjsRuntime = nullptr, JSContext* InjsContext = nullptr);
	JavaScriptMethod* GetInstanceMethodThis(JavaScript* instance);
	JSContext* GetContextThis(JavaScript* instance);
	JSRuntime* GetRuntimeThis(JavaScript* instance);
	void ChildSystemExitInstance(JavaScript* instance);
	bool IsAliveInstance(JavaScript* instance);

	void* jsRtValidValue =  (void*)0x00000001;
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

	typedef enum {
		JS_GC_PHASE_NONE,
		JS_GC_PHASE_DECREF,
		JS_GC_PHASE_REMOVE_CYCLES,
	} JSGCPhaseEnum;
	struct list_head {
		struct list_head* prev;
		struct list_head* next;
	};
	typedef enum {
		JS_GC_OBJ_TYPE_JS_OBJECT,
		JS_GC_OBJ_TYPE_FUNCTION_BYTECODE,
		JS_GC_OBJ_TYPE_SHAPE,
		JS_GC_OBJ_TYPE_VAR_REF,
		JS_GC_OBJ_TYPE_ASYNC_FUNCTION,
		JS_GC_OBJ_TYPE_JS_CONTEXT,
	} JSGCObjectTypeEnum;
	struct JSGCObjectHeader {
		int ref_count;
		JSGCObjectTypeEnum gc_obj_type : 4;
		uint8_t mark : 4; /* used by the GC */
		uint8_t dummy1; /* not used by the GC */
		uint16_t dummy2; /* not used by the GC */
		struct list_head link;
	};


	inline size_t GetGCPhaseOffset() {
#ifdef _WIN64
		return 176;
#else
		return 92;
#endif
	}
	inline JSGCPhaseEnum GetJSRuntimeGCPhase(JSRuntime* rt) {
		if (rt == nullptr) {
			return JS_GC_PHASE_NONE;
		}
		char* gc_phase_byte_ptr = reinterpret_cast<char*>(rt) + GetGCPhaseOffset();
		uint8_t phase_byte = *gc_phase_byte_ptr;
		return static_cast<JSGCPhaseEnum>(phase_byte);
	}
	static bool FreeValueSafely(JSContext* ctx, JSValue& jsv);
	static bool IsPointerValid(void* ptr);

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
			jsv = {};
		}
		JSValue* get() {
			return &jsv;
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
		JSValue jsv = {};
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
		JSValue* getPtr() const {
			if (jsvi == nullptr) return nullptr;
			return jsvi->get();
		}
		JSValue get(long long dupRef = 0) const {
			if (jsvi == nullptr) return JS_UNDEFINED;
			if (dupRef > 0) {
				for (long long i = 0; i < dupRef; i++) {
					//扒开底层代码发现这个函数单纯新增了u.ptr的引用计数，返回和入参为相同JSValue
                    if (ctx != nullptr && !JS_IsUndefined(*(jsvi->get())) && !JS_IsNull(*(jsvi->get()))) JS_DupValue(ctx, *(jsvi->get()));
				}
			}
			else if (dupRef < 0) {
				for (long long i = 0; i < -dupRef; i++) {
					//扒开底层代码发现这个函数单纯减少了u.ptr的引用计数，直到减少到0才释放
					if (ctx != nullptr && !JS_IsUndefined(*(jsvi->get())) && !JS_IsNull(*(jsvi->get()))) JS_FreeValue(ctx, *(jsvi->get()));
				}
			}
			return *(jsvi->get());
		}
		JSV& cget(long long dupRef = 0) {
			if (jsvi == nullptr) return *this;
			if (dupRef > 0) {
				for (long long i = 0; i < dupRef; i++) {
					//扒开底层代码发现这个函数单纯新增了u.ptr的引用计数，返回和入参为相同JSValue
					if (ctx != nullptr) JS_DupValue(ctx, *(jsvi->get()));
				}
			}
			else if (dupRef < 0) {
				for (long long i = 0; i < -dupRef; i++) {
					//扒开底层代码发现这个函数单纯减少了u.ptr的引用计数，直到减少到0才释放
					if (ctx != nullptr) JS_FreeValue(ctx, *(jsvi->get()));
				}
			}
			return *this;
		}
		ULL tell() {
			return jsvi->read();
		}
		bool isAutoRelease() const {
			return this->ctx != nullptr && this->jsvi != nullptr && !JS_IsUndefined(*(this->getPtr())) && !JS_IsNull(*(this->getPtr()));
		}
		bool isValid() const {
			return this->jsvi != nullptr && !JS_IsUndefined(*(this->getPtr())) && !JS_IsNull(*(this->getPtr()));
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
				if (ctx != nullptr && jsvi->read() == 0) {
					if (!JS_IsUndefined(*(jsvi->get())) && !JS_IsNull(*(jsvi->get()))) {
						for (ULL i = 0; i < jsvi->qjs_read(); i++) {
							JS_FreeValue(ctx, *(jsvi->get()));
						}
					}
					delete jsvi;
				}
				jsvi = nullptr;
			}
		}
	};

	struct JSINFO {
		bool isValid = false;
		bool isSuccess = false;
		JSV result = JS_UNDEFINED;
		std::wstring message = L"";
		GMMT detail = {};
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

	struct FILEDATA {
        JSV key = JS_UNDEFINED;
        JSV value = JS_UNDEFINED;
        std::string contentType = "";
		std::string name = "";
		std::string fileName = "";
        BYTEBUFFER binary = {};
	};
	typedef ordered_multimap<std::string, FILEDATA> FILELIST;

	struct JSMData {

		JSRuntime* rt = nullptr;
		JSContext* ctx = nullptr;

		JSContext* parentCtx = nullptr;

		JavaScript* js = nullptr;
		JavaScriptMethod* jsm = nullptr;
		
		std::vector<JSV> releaseList = {};
		std::unordered_map<ULL, FileController*> fileControllerList = {};
		std::unordered_map<ULL, JavaScript*> executeJsList = {};

		std::unordered_map<ULL, FILELIST> formDataList = {};
	};
	static std::unordered_map<JSContext*, JSMData> jsinfo = {};
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
	static bool IsPointerValid(void* ptr) {
		if (ptr == nullptr) return false;

		uintptr_t addr = reinterpret_cast<uintptr_t>(ptr);
#ifdef _WIN64
		const uintptr_t INVALID_HEAP_FREED = 0xdddddddddddddddd;    // 已释放堆内存
		const uintptr_t INVALID_HEAP_UNINIT = 0xcdcdcdcdcdcdcdcd;   // 未初始化堆内存
		const uintptr_t INVALID_VIRTUAL_FREED = 0xfeeefeeeefeeeefe; // 已释放虚拟内存
#else
	// 32 位 Windows 无效内存填充值（_WIN32）
		const uintptr_t INVALID_HEAP_FREED = 0xdddddddd;            // 已释放堆内存
		const uintptr_t INVALID_HEAP_UNINIT = 0xcdcdcdcd;           // 未初始化堆内存
		const uintptr_t INVALID_VIRTUAL_FREED = 0xfeeefeee;         // 已释放虚拟内存
#endif
		if (addr == INVALID_HEAP_FREED ||
			addr == INVALID_HEAP_UNINIT ||
			addr == INVALID_VIRTUAL_FREED) {
			return false;
		}
		MEMORY_BASIC_INFORMATION mbi = { 0 };
		if (VirtualQuery(ptr, &mbi, sizeof(mbi)) == 0) {
			return false;
		}
		if ((mbi.State != MEM_COMMIT) ||
			(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD))) {
			return false;
		}

		return true;
	}
	static bool FreeValueSafely(JSContext* ctx, JSValue& jsv){
		uint32_t tag = JS_VALUE_GET_TAG(jsv);
		if (tag == JS_TAG_OBJECT || tag == JS_TAG_FUNCTION_BYTECODE) {
			JSGCObjectHeader* p = static_cast<JSGCObjectHeader*>(JS_VALUE_GET_PTR(jsv));
			if (GetJSRuntimeGCPhase(JS_GetRuntime(ctx)) != JS_GC_PHASE_REMOVE_CYCLES) {
				struct list_head* el = &p->link;
				struct list_head* prev, * next;
				prev = el->prev;
				next = el->next;
				if (!IsPointerValid(prev) || !IsPointerValid(next)) return false;
			}
		}
		JS_FreeValue(ctx, jsv);
		return true;
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
		si.dwFlags = STARTF_USESTDHANDLES;
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
	static JSV CallFunction(JSContext* ctx, JSV func, JSV thisVal, std::vector<JSV> args);
	static JSV CallFunction(JSContext* ctx, JSV func, JSV thisVal, int argc, JSValueConst* argv);

	struct Promise {
		Promise& operator=(const Promise& other) {
			if (this == &other || *this == other) return *this;
			this->promise = other.promise;
			this->resolve = other.resolve;
			this->reject = other.reject;
			return *this;
		}
		bool operator==(const Promise& other) const {
			return this->promise == other.promise && this->resolve == other.resolve && this->reject == other.reject;
		}
		JSV promise = JSV(JS_UNDEFINED);
		JSV resolve = JSV(JS_UNDEFINED);
		JSV reject = JSV(JS_UNDEFINED);
        std::function<JSV(JSContext* ctx, std::vector<JSV> args)> callResolve = nullptr;
        std::function<JSV(JSContext* ctx, std::vector<JSV> args)> callReject = nullptr;
        std::function<JSV(JSContext* ctx, JSV arg)> Resolve = nullptr;
        std::function<JSV(JSContext* ctx, JSV arg)> Reject = nullptr;
	};

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
		// 新增：ChaCha20-Poly1305（raw格式）
		{"ChaCha20-Poly1305", {
			{"name", ""}  // 仅需name，密钥长度固定256位无需验证
		}},
		// HMAC 密钥（raw格式）
		{"HMAC", {
			{"name", ""},          // 必需：算法名称
			{"hash", ""},          // 必需：哈希算法
			{"length", "a"}        // 可选：HMAC密钥长度，值为'a'
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
			{"hash", ""}                   // 新增：必需（ECDSA导入需指定hash）
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
		// 新增：ChaCha20-Poly1305私钥（PKCS#8格式）
		{"ChaCha20-Poly1305", {
			{"name", ""}  // 仅需name，密钥长度固定
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
			{"hash", ""}                   // 新增：必需（ECDSA导入需指定hash）
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
		// 新增：ChaCha20-Poly1305无公钥，无需添加
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
		// 新增：ChaCha20-Poly1305（JWK格式）
		{"ChaCha20-Poly1305", {
			{"name", ""}  // 仅需name，密钥长度固定256位
		}},
		// HMAC 密钥（JWK格式）
		{"HMAC", {
			{"name", ""},
			{"hash", ""}           // 必需：哈希算法
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
			{"hash", ""}           // 新增：必需（ECDSA导入需指定hash）
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

		// -------------------------- 哈希/签名算法 --------------------------
		// HMAC是对称签名，无公私之分，均为空
		{"HMAC", {
			{"sign", ""},
			{"verify", ""}
		}},
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

		size_t keyByteLen = length / 8;
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
		// 1. 校验入参有效性
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

	class JavaScriptMethod {
	public:
		JavaScriptMethod(JavaScript* InInstance, JSRuntime* InjsRuntime, JSContext* InjsContext) {

			JSMData jsmd = {};
			jsmd.rt = InjsRuntime;
			jsmd.ctx = InjsContext;
			jsmd.js = InInstance;
			jsmd.jsm = this;
			SetData(jsmd.ctx, &jsmd);
			JSContext* ctx = jsmd.ctx;

			JSV null = JSV(JS_NULL);
			JSV global = NewGlobalObject(ctx);
			SetSymbolName(ctx, global, "Global");
			SetAttribute(ctx, global, "window", global);
			SetAttribute(ctx, global, "global", global);
			AppendMethod(ctx, global, "eval", eval);
			AppendMethod(ctx, global, "using", global_using);
			AppendMethod(ctx, global, "await", global_await);
			AppendMethod(ctx, global, "btoa", global_btoa);
			AppendMethod(ctx, global, "atob", global_atob);
			JSV FormData = NewConstructor(ctx, "FormData", global_FormData);
			AppendMethod(ctx, global, "FormData", FormData);

			JSV console = NewObject(ctx, global, "console");
            SetSymbolName(ctx, console, "Console");
			AppendMethod(ctx, console, "log", console_log);

			JSV filesystem = NewObject(ctx, global, "filesystem");
			SetSymbolName(ctx, filesystem, "Filesystem");
			AppendMethod(ctx, filesystem, "open", filesystem_open);
			AppendMethod(ctx, filesystem, "exists", filesystem_exists);
			AppendMethod(ctx, filesystem, "remove", filesystem_remove);
			AppendMethod(ctx, filesystem, "count", filesystem_count);

			JSV script = NewObject(ctx, global, "script");
			SetSymbolName(ctx, script, "Script");
			AppendMethod(ctx, script, "include", script_include);
			AppendMethod(ctx, script, "execute", script_execute);

			JSV system = NewObject(ctx, global, "system");
			SetSymbolName(ctx, system, "System");
			SetAttribute(ctx, system, "version", wstringToString(AY_CJS_CPP_VW));
			JSV system_config = CreateObject(ctx, configObject);
			SetSymbolName(ctx, system_config, "ConfigSystem");
			SetAttribute(ctx, system, "config", system_config);
			AppendMethod(ctx, system, "exit", system_exit);
			AppendMethod(ctx, system, "cwd", system_cwd);
			AppendMethod(ctx, system, "ecwd", system_ecwd);
			AppendMethod(ctx, system, "execute", system_execute);
			AppendMethod(ctx, system, "updateConfig", system_updateConfig);
			AppendMethod(ctx, system, "saveConfig", system_saveConfig);

			JSV crypto = NewObject(ctx, global, "crypto");
			SetSymbolName(ctx, crypto, "Crypto");
			AppendMethod(ctx, crypto, "getRandomValues", crypto_getRandomValues);
			JSV subtle = NewObject(ctx, crypto, "subtle");
			SetSymbolName(ctx, subtle, "SubtleCrypto");
			AppendMethod(ctx, subtle, "generateKey", crypto_subtle_generateKey);
			AppendMethod(ctx, subtle, "importKey", crypto_subtle_importKey);


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
			SetAttribute(ctx, request, "header", "");
			SetAttribute(ctx, request, "body", "");
			AppendMethod(ctx, request, "formData", network_request_formData);

			JSV response = NewObject(ctx, network, "response");
			SetSymbolName(ctx, response, "ResponstNetwork");
			SetAttribute(ctx, response, "header", "");
			SetAttribute(ctx, response, "body", "");


			ApplyExtension(jsmd.js);

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

				for (auto& [id, fc] : jsmd->fileControllerList) {
					if (fc != nullptr) {
						delete fc;
						fc = nullptr;
					}
				}
				jsmd->fileControllerList.clear();

				for (auto& [id, js] : jsmd->executeJsList) {
					if (js != nullptr) {
						DeleteInstance(js);
						js = nullptr;
					}
				}
				jsmd->executeJsList.clear();

				jsmd->formDataList.clear();
				jsmd->releaseList.clear();

			}

			RemoveData(ctx);
			jsmd = nullptr;
			ctx = nullptr;
		}

		static JSValue network_request_formData(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
            Promise promise = NewPromise(ctx);
			if (argumentCount != 0) {
                promise.Reject(ctx, NewTypeError(ctx, "[network.response.formData] No arguments are supported"));
				return promise.promise.get(1);
			}

            std::thread([=]() {

                JSV request_body = {};
                BYTEBUFFER binary = {};
                if (!ReadObjectProperty(ctx, thisVal, "body", request_body)) {
					promise.Reject(ctx, NewTypeError(ctx, "[network.request.formData] Missing request body"));
					return;
                }

				promise.Resolve(ctx, CallConstructor(ctx, GetProperty(ctx, NewGlobalObject(ctx), "FormData"), { {request_body} }));
				return;

                }).detach();

            return promise.promise.get(1);
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

				FILEDATA fd = {};
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

				FILEDATA fd = {};
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
					FILELIST& dataList = jsmdPtr->formDataList[id];

					if (!ReadJSValueAsUint64(ctx, GetProperty(ctx, internal, "index"), index)) {
						JS_ThrowInternalError(ctx, "[FormData->entries] This instance is invalid");
						return JS_EXCEPTION;
					}

					JSV returnObject = NewObject(ctx);
					SetAttribute(ctx, returnObject, "done", NewBool(ctx, index >= dataList.size()));
					if (index < dataList.size()) {
						auto& fd = dataList.at(index);
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
					FILELIST& dataList = jsmdPtr->formDataList[id];

					if (!ReadJSValueAsUint64(ctx, GetProperty(ctx, internal, "index"), index)) {
						JS_ThrowInternalError(ctx, "[FormData->keys] This instance is invalid");
						return JS_EXCEPTION;
					}

					JSV returnObject = NewObject(ctx);
					SetAttribute(ctx, returnObject, "done", NewBool(ctx, index >= dataList.size()));
					if (index < dataList.size()) {
						auto& fd = dataList.at(index);
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
					FILELIST& dataList = jsmdPtr->formDataList[id];

					if (!ReadJSValueAsUint64(ctx, GetProperty(ctx, internal, "index"), index)) {
						JS_ThrowInternalError(ctx, "[FormData->values] This instance is invalid");
						return JS_EXCEPTION;
					}

					JSV returnObject = NewObject(ctx);
					SetAttribute(ctx, returnObject, "done", NewBool(ctx, index >= dataList.size()));
					if (index < dataList.size()) {
						auto& fd = dataList.at(index);
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

			JSValue jsPromise = argumentValues[0];
			if (!JS_IsPromise(jsPromise)) {
				return JS_DupValue(ctx, jsPromise);
			}

			JSPromiseStateEnum finallyState = JS_PROMISE_PENDING;
			while (!isQuit) {
				JSPromiseStateEnum state = JS_PromiseState(ctx, jsPromise);
				if (state != JS_PROMISE_PENDING) {
					finallyState = state;
					break;
				}
				AdvSleep(1.0);
			}

			JSValue result = JS_PromiseResult(ctx, jsPromise);
			if (finallyState == JS_PROMISE_FULFILLED) {
				return result;
			}
			else {
				std::string errorString = "Unknown Error";
				const char* error = JS_ToCString(ctx, result);
				if (error == nullptr) {
					JS_FreeValue(ctx, result);
				}
				else {
					errorString = error;
					JS_FreeCString(ctx, error);
					JS_FreeValue(ctx, result);
				}
				JS_ThrowPlainError(ctx, ("(in promise) " + errorString).c_str());
				return JS_EXCEPTION;
			}

		}
		static JSValue global_using(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
			if (argumentCount > 2) {
				JS_ThrowTypeError(ctx, "[using] Only 1 or 2 argument are supported: (object, where?)");
				return JS_EXCEPTION;
			}

			JSV global = NewGlobalObject(ctx);

			JSValue jsObject = argumentValues[0];
			if (!JS_IsObject(jsObject)) {
				JS_ThrowTypeError(ctx, "[using] The first argument must be a object");
				return JS_EXCEPTION;
			}
			if (JS_IsSameValue(ctx, global.get(0), jsObject)) {
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
				if (JS_IsObject(jsWhere) && JS_IsSameValue(ctx, jsWhere, jsObject)) {
					JS_ThrowTypeError(ctx, "[using] The first object cannot be equal to the second object");
					return JS_EXCEPTION;
				}
			}

			JSV object = jsObject;
			JSV where = jsWhere;
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
				if (!JS_IsString(vKey.get(0)) || !ReadJSValueAsString(ctx,vKey, key)) {
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

		static JSValue eval(JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues) {
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
			if (argumentCount != 1) {
				JS_ThrowTypeError(ctx, "[system.execute] Only 1 argument is supported: (cmd)");
				return JS_EXCEPTION;
			}
			JSV vCmd = JSV(&argumentValues[0]);
			std::string cmd = "";
			if (!JS_IsString(vCmd.get(0)) || !ReadJSValueAsString(ctx, vCmd, cmd)) {
				JS_ThrowTypeError(ctx, "[system.execute] The first argument must be a string");
				return JS_EXCEPTION;
			}

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
			return returnValue.get(1);
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

			JS_Throw(ctx, JS_NewString(ctx, "[native code] Quit the context"));
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

			if (arrayType == "Uint8Array") {
				JSV jsData = NewUint8Array(ctx, data);
				if (!ModifyJSValue(ctx, uArray, jsData)) goto ErrorProcess;
			}
			else if (arrayType == "Uint16Array") {
				JSV jsData = NewUint16Array(ctx, data);
				if (!ModifyJSValue(ctx, uArray, jsData)) goto ErrorProcess;
			}
			else if (arrayType == "Uint32Array") {
				JSV jsData = NewUint32Array(ctx, data);
				if (!ModifyJSValue(ctx, uArray, jsData)) goto ErrorProcess;
			}
			else if (arrayType == "Int8Array") {
				JSV jsData = NewInt8Array(ctx, data);
				if (!ModifyJSValue(ctx, uArray, jsData)) goto ErrorProcess;
			}
			else if (arrayType == "Int16Array") {
				JSV jsData = NewInt16Array(ctx, data);
				if (!ModifyJSValue(ctx, uArray, jsData)) goto ErrorProcess;
			}
			else if (arrayType == "Int32Array") {
				JSV jsData = NewInt32Array(ctx, data);
				if (!ModifyJSValue(ctx, uArray, jsData)) goto ErrorProcess;
			}

			if (false) {
			ErrorProcess:;
				JS_ThrowDOMException(ctx, "OperationError", "[crypto.getRandomValues] Failed to apply result");
				return JS_EXCEPTION;
			}

			return JS_UNDEFINED;
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

			std::thread([=]() {

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
							if (alg1 + alg2 == "HS" && alg4 != "-" && alen == 5) {
								name = "HMAC";
								hash = "SHA-" + alg3 + alg4 + alg5;
							}
							else if (alg1 + alg2 == "HS" && alg4 == "-" && (alen == 5 || alen == 6)) {
								name = "HMAC";
								hash = "SHA-" + alg3 + "-" + alg5 + alg6 + alg7;
							}
							else if (alg1 == "A" && alen == 7) {
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
							if (name != a_name) {
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
						if ((name.find("AES") != std::string::npos && tempKeyBinary.size() * 8 != length) || (name == "ChaCha20-Poly1305" && tempKeyBinary.size() != 32) || (name == "HMAC" && hash != a_hash_name)) {
							promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The algorithm does not match the keyData"));
							return;
						}

						keyBinary = std::move(tempKeyBinary);
					}
					else if (jwk[L"kty"].get<std::string>() == "RSA") {

						if (!jwk.count(L"e")) {
							promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The keyData must have an 'e' property"));
							return;
						}
						if (!jwk.count(L"n")) {
							promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The keyData must have an 'n' property"));
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

							if (alg1 + alg2 == "PS" && ((alg4 != "-" && alen == 5) || (alg4 == "-" && alen == 7))) {
								name = "RSA-PSS";
								if (alen == 5) hash = "SHA-" + alg3 + alg4 + alg5;
								else hash = "SHA-" + alg3 + "-" + alg5 + alg6 + alg7;
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

							if (name != a_name || hash != a_hash_name) {
								promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The algorithm does not match the keyData"));
								return;
							}

						}

						BYTEBUFFER tempKeyBinary = {};
						BYTEBUFFER e = ToBinary(jwk[L"e"].get<std::string>());
						uint64_t elen = e.size();
						BYTEBUFFER n = ToBinary(jwk[L"n"].get<std::string>());
						uint64_t nlen = n.size();
						if (e.empty()) {
							promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The 'e' property must not be empty"));
							return;
						}
						if (n.empty()) {
							promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The 'n' property must not be empty"));
							return;
						}
						if (!BaseXToBinary(&e, 64, true) || !BaseXToBinary(&n, 64, true)) {
							if (elen == e.size()) promise.Reject(ctx, NewSyntaxError(ctx, "[crypto.subtle.importKey] The 'e' value is not a valid base64url string"));
							else promise.Reject(ctx, NewSyntaxError(ctx, "[crypto.subtle.importKey] The 'n' value is not a valid base64url string"));
							return;
						}

						if (jwk.count(L"d")) {

							BYTEBUFFER d = ToBinary(jwk[L"d"].get<std::string>());
							uint64_t dlen = d.size();
							if (!BaseXToBinary(&d, 64, true)) {
								promise.Reject(ctx, NewSyntaxError(ctx, "[crypto.subtle.importKey] The 'd' value is not a valid base64url string"));
								return;
							}

							BYTEBUFFER p = ToBinary(jwk[L"p"].get<std::string>());
							if (!p.empty()) BaseXToBinary(&p, 64, true);
							BYTEBUFFER q = ToBinary(jwk[L"q"].get<std::string>());
							if (!q.empty()) BaseXToBinary(&q, 64, true);
							BYTEBUFFER dp = ToBinary(jwk[L"dp"].get<std::string>());
							if (!dp.empty()) BaseXToBinary(&dp, 64, true);
							BYTEBUFFER dq = ToBinary(jwk[L"dq"].get<std::string>());
							if (!dq.empty()) BaseXToBinary(&dq, 64, true);
							BYTEBUFFER qi = ToBinary(jwk[L"qi"].get<std::string>());
							if (!qi.empty()) BaseXToBinary(&qi, 64, true);

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

						if (!jwk.count(L"crv")) {
							promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The keyData must have a 'crv' string property"));
							return;
						}
						std::string crv = jwk[L"crv"].get<std::string>();

						if (crv == "P-256") {
						}
						else if (crv == "P-384") {
						}
						else if (crv == "P-521") {
						}
						else {
							promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The curve '" + crv + "' is not supported"));
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

						if (jwk.count(L"d")) {

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
							if (!jwk.count(L"x")) {
								promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The keyData must have an 'x' property"));
								return;
							}
							if (!jwk.count(L"y")) {
								promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The keyData must have a 'y' property"));
								return;
							}
							BYTEBUFFER x = ToBinary(jwk[L"x"].get<std::string>());
							uint64_t xlen = x.size();
							BYTEBUFFER y = ToBinary(jwk[L"y"].get<std::string>());
							uint64_t ylen = y.size();
							if (x.empty()) {
								promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The 'x' property must not be empty"));
								return;
							}
							if (y.empty()) {
								promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The 'y' property must not be empty"));
								return;
							}
							if (!BaseXToBinary(&x, 64, true) || !BaseXToBinary(&y, 64, true)) {
								if (xlen == x.size()) promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The 'x' value is not a valid base64url string"));
								else promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The 'y' value is not a valid base64url string"));
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
						if (!jwk.count(L"crv")) {
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

							if (jwk.count(L"d")) {
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
								BYTEBUFFER x = ToBinary(jwk[L"x"].get<std::string>());
								if (x.empty()) {
									promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The keyData must have an 'x' property"));
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

				if ((a_name.find("AES") == std::string::npos && a_name != "HMAC" && a_name != "ChaCha20-Poly1305") && a_name != "Ed25519" && a_name != "X25519") pkd = GetPKData(&keyBinary);

				if (pkd.isValid) {

					if (format == "raw" || (pkd.isPrivate && format == "spki") || (!pkd.isPrivate && format == "pkcs8")) {
						promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] Cannot import " + std::string(pkd.isPrivate ? "private" : "public") + " key as format '" + format + "'"));
						return;
					}

					if (pkd.name == a_name || (a_name.find("RSA") != std::string::npos && pkd.name == "RSA")) {
						if (pkd.modulusLength != 0) SetAttribute(ctx, js_algorithm, "modulusLength", NewUint64(ctx, pkd.modulusLength), 0);
						if (pkd.publicExponent != 0) SetAttribute(ctx, js_algorithm, "publicExponent", NewUint64(ctx, pkd.publicExponent), 0);
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
					SetAttribute(ctx, returnValue, "type", pkd.isPrivate ? "private" : "public", 0);
					SetAttribute(ctx, returnValue, "algorithm", js_algorithm, 0);
					SetAttribute(ctx, returnValue, "extractable", js_extractable, 0);
					SetAttribute(ctx, returnValue, "usages", js_keyUsages, 0);

					JSV privateObject = NewObject(ctx);
					JSV data = NewUint8Array(ctx, keyBinary);
					SetAttribute(ctx, privateObject, "data", data, 0);
					SetAttribute(ctx, privateObject, "_isPrivate", NewBool(ctx, true), 0);
					SetAttribute(ctx, returnValue, "internal", privateObject, 0);

					promise.Resolve(ctx, returnValue.get());

				}
				else {

					if (a_name == "HMAC") {
						JSV js_a_hash = {};
						JSV js_hash_name = {};
						std::string a_hash_name = "";
						if (!ReadObjectProperty(ctx, js_algorithm, "hash", js_a_hash) || !ReadObjectProperty(ctx, js_a_hash, "name", js_hash_name) || !ReadJSValueAsString(ctx, js_hash_name, a_hash_name) || !IsHMACMatched(&keyBinary, a_hash_name)) {
							if (!js_a_hash.isValid()) promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The algorithm must have a 'hash' object"));
							else if (!js_hash_name.isValid()) promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The hash must have a 'name' string"));
							else promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The hash does not match the key"));
							return;
						}
					}
					else if (a_name.find("AES") != std::string::npos) {
						JSV js_a_length = {};
						uint64_t a_length = 0;
						if (!ReadObjectProperty(ctx, js_algorithm, "length", js_a_length) || !ReadJSValueAsUint64(ctx, js_a_length, a_length) || !IsAESMatched(&keyBinary, a_length)) {
							if (!js_a_length.isValid()) promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The algorithm must have a 'length' number"));
							else promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The length does not match the key"));
							return;
						}
					}
					else if (a_name == "ChaCha20-Poly1305") {
					}
					else {
						promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.importKey] The algorithm does not match the key"));
						return;
					}

					JSV returnValue = NewObject(ctx);
					SetAttribute(ctx, returnValue, "type", "secret", 0);
					SetAttribute(ctx, returnValue, "algorithm", js_algorithm, 0);
					SetAttribute(ctx, returnValue, "extractable", js_extractable, 0);
					SetAttribute(ctx, returnValue, "usages", js_keyUsages, 0);

					JSV privateObject = NewObject(ctx);
					JSV data = NewUint8Array(ctx, keyBinary);
					SetAttribute(ctx, privateObject, "data", data, 0);
					SetAttribute(ctx, privateObject, "_isPrivate", NewBool(ctx, true), 0);
					SetAttribute(ctx, returnValue, "internal", privateObject, 0);

					promise.Resolve(ctx, returnValue.get());

				}

				return;
				}).detach();

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

				if (hash_name != "SHA-1" && hash_name != "SHA-256" && hash_name != "SHA-384" && hash_name != "SHA-512" && hash_name != "SHA-3-256" && hash_name != "SHA-3-384" && hash_name != "SHA-3-512") {
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
					if (a_length_temp % 8 != 0) {
						promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.generateKey] HMAC key length must be a multiple of 8 bits"));
						return promise.promise.get(1);
					}
					a_length = a_length_temp / 8;
				}

				if (a_length == 0) {
					if (hash_name == "SHA-1") a_length = 20;
					else if (hash_name == "SHA-256") a_length = 32U;
					else if (hash_name == "SHA-384") a_length = 48;
					else if (hash_name == "SHA-512") a_length = 32U;
					else if (hash_name == "SHA-3-256") a_length = 32U;
					else if (hash_name == "SHA-3-384") a_length = 48U;
					else if (hash_name == "SHA-3-512") a_length = 64U;
				}

				std::thread([=]() {

					BYTEBUFFER keyBinary = {};
					if (!crypto_subtle_generateKey_HMAC(hash_name, a_length * 8, &keyBinary)) {
						promise.Reject(ctx, NewInternalError(ctx, "[crypto.subtle.generateKey] Failed to generate key"));
						return;
					}

					JSV returnValue = NewObject(ctx);
					SetAttribute(ctx, returnValue, "type", "secret", 0);
					SetAttribute(ctx, returnValue, "algorithm", uAlgorithm, 0);
					SetAttribute(ctx, returnValue, "extractable", uExtractable, 0);
					SetAttribute(ctx, returnValue, "usages", uKeyUsages, 0);

					JSV privateObject = NewObject(ctx);
					JSV data = NewUint8Array(ctx, keyBinary);
					SetAttribute(ctx, privateObject, "data", data, 0);
					SetAttribute(ctx, privateObject, "_isPrivate", NewBool(ctx, true), 0);
					SetAttribute(ctx, returnValue, "internal", privateObject, 0);

					promise.Resolve(ctx, returnValue.get());

					}).detach();

			}
			else if (a_name == "AES-GCM" || a_name == "AES-CBC" || a_name == "AES-CTR" || a_name == "AES-KW") {

				JSV js_a_length = {};
				uint64_t a_length = 0;
				if (!ReadObjectProperty(ctx, uAlgorithm, "length", js_a_length) || !ReadJSValueAsUint64(ctx, js_a_length, a_length)) {
					promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.generateKey] The key length must be an positive integer"));
					return promise.promise.get(1);
				}

				if (a_length != 128 && a_length != 192 && a_length != 256) {
					promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.generateKey] AES key length must be 128, 192 or 256 bits"));
					return promise.promise.get(1);
				}

				std::thread([=]() {

					BYTEBUFFER keyBinary = {};
					if (!crypto_subtle_generateKey_AES(a_length, a_name.substr(4), &keyBinary)) {
						promise.Reject(ctx, NewInternalError(ctx, "[crypto.subtle.generateKey] Failed to generate key"));
						return;
					}

					std::thread([=, keyBinary = std::move(keyBinary)]() {

						JSV returnValue = NewObject(ctx);
						SetAttribute(ctx, returnValue, "type", "secret", 0);
						SetAttribute(ctx, returnValue, "algorithm", uAlgorithm, 0);
						SetAttribute(ctx, returnValue, "extractable", uExtractable, 0);
						SetAttribute(ctx, returnValue, "usages", uKeyUsages, 0);

						JSV privateObject = NewObject(ctx);
						JSV data = NewUint8Array(ctx, keyBinary);
						SetAttribute(ctx, privateObject, "data", data, 0);
						SetAttribute(ctx, privateObject, "_isPrivate", NewBool(ctx, true), 0);
						SetAttribute(ctx, returnValue, "internal", privateObject, 0);

						promise.Resolve(ctx, returnValue.get());

						}).join();

					}).detach();

			}
			else if (a_name == "ChaCha20-Poly1305") {
				std::thread([=]() {
					BYTEBUFFER keyBinary = {};
					if (!crypto_subtle_generateKey_ChaCha20Poly1305(&keyBinary)) {
						promise.Reject(ctx, NewInternalError(ctx, "[crypto.subtle.generateKey] Failed to generate key"));
						return;
					}

					JSV returnValue = NewObject(ctx);
					SetAttribute(ctx, returnValue, "type", "secret", 0);
					SetAttribute(ctx, returnValue, "algorithm", uAlgorithm, 0);
					SetAttribute(ctx, returnValue, "extractable", uExtractable, 0);
					SetAttribute(ctx, returnValue, "usages", uKeyUsages, 0);

					JSV privateObject = NewObject(ctx);
					JSV data = NewUint8Array(ctx, keyBinary);
					SetAttribute(ctx, privateObject, "data", data, 0);
					SetAttribute(ctx, privateObject, "_isPrivate", NewBool(ctx, true), 0);
					SetAttribute(ctx, returnValue, "internal", privateObject, 0);

					promise.Resolve(ctx, returnValue.get());
					}).detach();
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
				if (a_modulusLength != 1024 && a_modulusLength != 2048 && a_modulusLength != 4096) {
					promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.generateKey] RSA modulus length must be 1024, 2048 or 4096 bits"));
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
				if (a_hash_name != "SHA-1" && a_hash_name != "SHA-256" && a_hash_name != "SHA-384" && a_hash_name != "SHA-512" && a_hash_name != "SHA-3-256" && a_hash_name != "SHA-3-384" && a_hash_name != "SHA-3-512") {
					promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.generateKey] RSA hash name must be 'SHA-1', 'SHA-256', 'SHA-384' or 'SHA-512'"));
					return promise.promise.get(1);
				}

				std::thread([=]() {

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

					promise.Resolve(ctx, returnValue.get());

					}).detach();

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
				if (a_namedCurve != "P-256" && a_namedCurve != "P-384" && a_namedCurve != "P-521") {
					promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.generateKey] EC name curve must be 'P-256', 'P-384' or 'P-521'"));
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
						if (a_hash_name != "SHA-1" && a_hash_name != "SHA-256" && a_hash_name != "SHA-384" && a_hash_name != "SHA-512" && a_hash_name != "SHA-3-256" && a_hash_name != "SHA-3-384" && a_hash_name != "SHA-3-512") {
							promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.generateKey] ECDSA hash name must be 'SHA-1', 'SHA-256', 'SHA-384' or 'SHA-512'"));
							return promise.promise.get(1);
						}
					}
				}

				std::thread([=]() {

					BYTEBUFFER publicKeyBinary = {};
					BYTEBUFFER privateKeyBinary = {};
					if (!crypto_subtle_generateKey_EC(a_name, a_namedCurve, a_hash_name, &publicKeyBinary, &privateKeyBinary)) {
						promise.Reject(ctx, NewInternalError(ctx, "[crypto.subtle.generateKey] Failed to generate key"));
						return;
					}

					JSV returnValue = NewObject(ctx);
					JSV publicKey = NewObject(ctx);
					JSV privateKey = NewObject(ctx);
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

					promise.Resolve(ctx, returnValue.get());

					}).detach();

			}
			else if (a_name == "Ed25519") {

				std::thread([=]() {

					BYTEBUFFER publicKeyBinary = {};
					BYTEBUFFER privateKeyBinary = {};
					if (!crypto_subtle_generateKey_Ed25519(&publicKeyBinary, &privateKeyBinary)) {
						promise.Reject(ctx, NewInternalError(ctx, "[crypto.subtle.generateKey] Failed to generate key"));
						return;
					}

					JSV returnValue = NewObject(ctx);
					JSV publicKey = NewObject(ctx);
					JSV privateKey = NewObject(ctx);
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

					promise.Resolve(ctx, returnValue.get());

					}).detach();

			}
			else if (a_name == "X25519") {

				std::thread([=]() {

					BYTEBUFFER publicKeyBinary = {};
					BYTEBUFFER privateKeyBinary = {};
					if (!crypto_subtle_generateKey_X25519(&publicKeyBinary, &privateKeyBinary)) {
						promise.Reject(ctx, NewInternalError(ctx, "[crypto.subtle.generateKey] Failed to generate key"));
						return;
					}

					JSV returnValue = NewObject(ctx);
					JSV publicKey = NewObject(ctx);
					JSV privateKey = NewObject(ctx);
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

					promise.Resolve(ctx, returnValue.get());

					}).detach();

			}
			else {
				promise.Reject(ctx, NewTypeError(ctx, "[crypto.subtle.generateKey] The algorithm name '" + a_name + "' is not supported"));
				return promise.promise.get(1);
			}
			return promise.promise.get(1);
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

			auto get_color_value = [&](const std::wstring& color_key) -> const std::wstring& {
				auto it = TextLightColorValue.find(color_key);
				if (it != TextLightColorValue.end()) {
					return it->second;
				}
				static std::wstring default_color = TextLightColorValue[L"Default"];
				return default_color;
				};

			auto js_val_to_cstr = [&](JSValueConst val) -> const char* {
				if (JS_IsUndefined(val) || JS_IsNull(val) || JS_IsException(val))
					return nullptr;

				JSValue str_val = JS_ToString(ctx, val);
				if (JS_IsException(str_val)) {
					JS_FreeValue(ctx, str_val);
					return nullptr;
				}
				const char* cstr = JS_ToCString(ctx, str_val);
				JS_FreeValue(ctx, str_val);
				return cstr;
				};

			auto get_to_string_tag = [&](JSValueConst val) -> const char* {
				if (atom_toStringTag == JS_ATOM_NULL) return nullptr;
				JSValue tag_val = JS_GetProperty(ctx, val, atom_toStringTag);
				if (JS_IsUndefined(tag_val) || JS_IsNull(tag_val) || JS_IsException(tag_val)) {
					JS_FreeValue(ctx, tag_val);
					return nullptr;
				}
				const char* tag_cstr = js_val_to_cstr(tag_val);
				JS_FreeValue(ctx, tag_val);
				return tag_cstr;
				};

			auto get_function_type = [&](JSValueConst val) -> std::wstring {
				if (!JS_IsFunction(ctx, val)) return L"";

				bool is_class = false;
				JSValue name_val = JS_GetProperty(ctx, val, atom_name);
				const char* func_name = js_val_to_cstr(name_val);
				if (func_name && strstr(func_name, "class ")) {
					is_class = true;
				}
				if (func_name) JS_FreeCString(ctx, func_name);
				JS_FreeValue(ctx, name_val);

				if (!is_class) {
					JSValue to_str_fun = JS_GetProperty(ctx, val, atom_toString);
					if (!JS_IsUndefined(to_str_fun) && !JS_IsNull(to_str_fun) && !JS_IsException(to_str_fun)) {
						JSValue str_val = JS_Call(ctx, to_str_fun, val, 0, nullptr);
						JS_FreeValue(ctx, to_str_fun);
						if (!JS_IsException(str_val)) {
							const char* fn_to_str = js_val_to_cstr(str_val);
							if (fn_to_str && strstr(fn_to_str, "class ")) {
								is_class = true;
							}
							if (fn_to_str) JS_FreeCString(ctx, fn_to_str);
						}
						JS_FreeValue(ctx, str_val);
					}
					else {
						JS_FreeValue(ctx, to_str_fun);
					}
				}

				if (is_class) return L"Class";

				JSValue to_str_fun = JS_GetProperty(ctx, val, atom_toString);
				std::wstring func_type = L"Function";
				if (!JS_IsUndefined(to_str_fun) && !JS_IsNull(to_str_fun) && !JS_IsException(to_str_fun)) {
					JSValue str_val = JS_Call(ctx, to_str_fun, val, 0, nullptr);
					JS_FreeValue(ctx, to_str_fun);
					if (!JS_IsException(str_val)) {
						const char* fn_to_str = js_val_to_cstr(str_val);
						if (fn_to_str && strstr(fn_to_str, "[native code]")) {
							func_type = L"BuiltInFunction";
						}
						if (fn_to_str) JS_FreeCString(ctx, fn_to_str);
					}
					JS_FreeValue(ctx, str_val);
				}
				else {
					JS_FreeValue(ctx, to_str_fun);
				}

				JSValue name_val2 = JS_GetProperty(ctx, val, atom_name);
				const char* func_name2 = js_val_to_cstr(name_val2);
				if (func_name2 && strchr(func_name2, '.')) {
					func_type = L"Method";
				}
				if (func_name2) JS_FreeCString(ctx, func_name2);
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
					const char* prop_name = JS_AtomToCString(ctx, props[i].atom);
					if (!prop_name) {
						JS_FreeCString(ctx, prop_name);
						return false;
					}
					char* endptr = nullptr;
					uint32_t num_key = strtoul(prop_name, &endptr, 10);
					if (*endptr != '\0') {
						JS_FreeCString(ctx, prop_name);
						return false;
					}
					key_set.insert(num_key);
					if (num_key > max_key) max_key = num_key;
					JS_FreeCString(ctx, prop_name);
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
				if (is_private_value(val)) {
					return;
				}

				std::wstring indent_str = get_indent_str(indent);

				if (JS_IsFunction(ctx, val)) {
					std::wstring func_type = get_function_type(val);
					JSValue name_val = JS_GetProperty(ctx, val, atom_name);
					const char* func_name = js_val_to_cstr(name_val);
					std::string fn_name = func_name ? func_name : "";
					if (func_name) JS_FreeCString(ctx, func_name);
					JS_FreeValue(ctx, name_val);

					JSValue to_str_fun = JS_GetProperty(ctx, val, atom_toString);
					const char* fn_to_str = nullptr;
					if (!JS_IsUndefined(to_str_fun) && !JS_IsNull(to_str_fun) && !JS_IsException(to_str_fun)) {
						JSValue str_val = JS_Call(ctx, to_str_fun, val, 0, nullptr);
						JS_FreeValue(ctx, to_str_fun);
						if (!JS_IsException(str_val)) {
							fn_to_str = js_val_to_cstr(str_val);
						}
						JS_FreeValue(ctx, str_val);
					}
					else {
						JS_FreeValue(ctx, to_str_fun);
					}

					std::wstring func_str;
					if (fn_to_str && *fn_to_str != '\0') {
						func_str = stringToWstring(fn_to_str);
						std::wstring line_indent = get_indent_str(indent);
						size_t pos = 0;
						while ((pos = func_str.find(L'\n', pos)) != std::wstring::npos) {
							func_str.insert(pos + 1, line_indent);
							pos += line_indent.length() + 1;
						}
						JS_FreeCString(ctx, fn_to_str);
					}
					else {
						if (func_type == L"Class") {
							func_str = fn_name.empty() ? L"class { [native code] }"
								: L"class " + stringToWstring(fn_name) + L" { [native code] }";
						}
						else {
							func_str = fn_name.empty() ? L"function() { [native code] }"
								: L"function " + stringToWstring(fn_name) + L"() { [native code] }";
						}
					}
					CreateOutput(func_str, get_color_value(func_type));
					return;
				}

				if (JS_IsObject(val)) {
					const char* tag_cstr = get_to_string_tag(val);
					std::string tag_str;
					if (tag_cstr) {
						tag_str = tag_cstr;
						JS_FreeCString(ctx, tag_cstr);
					}

					std::wstring obj_color_key = L"Object";
					if (tag_str == "Promise") {
						obj_color_key = L"Promise";
						std::wstring promise_str = L"Promise { <pending> }";
						JSValue state_val = JS_GetProperty(ctx, val, atom_state);
						if (!JS_IsException(state_val) && !JS_IsUndefined(state_val) && !JS_IsNull(state_val)) {
							const char* state_cstr = js_val_to_cstr(state_val);
							if (state_cstr) {
								promise_str = L"Promise { <" + stringToWstring(state_cstr) + L"> }";
								JS_FreeCString(ctx, state_cstr);
							}
						}
						JS_FreeValue(ctx, state_val);
						CreateOutput(promise_str, get_color_value(obj_color_key));
						return;
					}

					if (tag_str == "Date") {
						obj_color_key = L"Date";
						std::wstring date_str = L"Date ";
						JSValue locale_str_val = JS_GetProperty(ctx, val, atom_toLocaleString);
						if (!JS_IsException(locale_str_val) && !JS_IsUndefined(locale_str_val)) {
							JSValue str_val = JS_Call(ctx, locale_str_val, val, 0, nullptr);
							JS_FreeValue(ctx, locale_str_val);
							const char* date_cstr = js_val_to_cstr(str_val);
							if (date_cstr) {
								date_str += L"[" + stringToWstring(date_cstr) + L"]";
								JS_FreeCString(ctx, date_cstr);
							}
							else {
								date_str += L"[Invalid Date]";
							}
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
						const char* regex_cstr = js_val_to_cstr(val);
						std::wstring regex_str = regex_cstr ? stringToWstring(regex_cstr) : L"RegExp [invalid]";
						if (regex_cstr) JS_FreeCString(ctx, regex_cstr);
						CreateOutput(regex_str, get_color_value(obj_color_key));
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

						CreateOutput(indent_str + stringToWstring(tag_str) + L" [", get_color_value(obj_color_key));

						for (uint32_t i = 0; i < arr_length; ++i) {
							JSValue elem_val = JS_GetPropertyUint32(ctx, val, i);
							if (i > 0)
								CreateOutput(L", ", get_color_value(obj_color_key));
							if (!is_private_value(elem_val) && !JS_IsException(elem_val)) {
								print_js_value(elem_val, indent + 1);
							}
							else if (is_private_value(elem_val)) {
							}
							else {
								CreateOutput(L"[invalid]", get_color_value(L"Comment"));
							}
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
					const char* cstr = JS_ToCString(ctx, val);
					if (cstr) {
						CreateOutput(L"\"" + stringToWstring(cstr) + L"\"", get_color_value(L"String"));
						JS_FreeCString(ctx, cstr);
					}
				}
				else if (JS_IsNumber(val)) {
					double num = 0.0;
					if (JS_ToFloat64(ctx, &num, val) == 0) {
						CreateOutput(RemoveSpaceAfterNumber(std::to_wstring(num)), get_color_value(L"Number"));
					}
					else {
						CreateOutput(L"[invalid number]", get_color_value(L"Comment"));
					}
				}
				else if (JS_IsBigInt(val)) {
					int64_t bnum_signed = 0;
					uint64_t bnum_unsigned = 0;
					if (JS_ToBigInt64(ctx, &bnum_signed, val) == 0) {
						CreateOutput(std::to_wstring(bnum_signed), get_color_value(L"Number"));
					}
					else if (JS_ToBigUint64(ctx, &bnum_unsigned, val) == 0) {
						CreateOutput(std::to_wstring(bnum_unsigned), get_color_value(L"Number"));
					}
					else {
						CreateOutput(L"[invalid bigint]", get_color_value(L"Comment"));
					}
				}
				else if (JS_IsBool(val)) {
					bool b = JS_ToBool(ctx, val);
					CreateOutput(b ? L"true" : L"false", get_color_value(L"Boolean"));
				}
				else if (JS_IsNull(val)) {
					CreateOutput(L"null", get_color_value(L"NullUndefined"));
				}
				else if (JS_IsUndefined(val)) {
					CreateOutput(L"undefined", get_color_value(L"NullUndefined"));
				}
				else if (JS_IsSymbol(val)) {
					const char* cstr = JS_ToCString(ctx, val);
					if (cstr) {
						CreateOutput(L"Symbol(" + stringToWstring(cstr) + L")", get_color_value(L"Symbol"));
						JS_FreeCString(ctx, cstr);
					}
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
					if (!obj_type_name.empty() && TextLightColorValue.count(obj_type_name)) {
						proto_color_key = obj_type_name;
					}

					if (!obj_type_name.empty() && obj_type_name != L"Object") {
						CreateOutput(obj_type_name + L" ", get_color_value(proto_color_key));
					}
					CreateOutput(L"{\n", get_color_value(L"Object"));

					JSPropertyEnum* props = nullptr;
					uint32_t prop_cnt = 0;
					std::vector<JSPropertyEnum> final_valid_props;
					if (JS_GetOwnPropertyNames(ctx, &props, &prop_cnt, val, JS_GPN_ALL) == 0) {
						for (uint32_t i = 0; i < prop_cnt; i++) {
							const char* prop_name = JS_AtomToCString(ctx, props[i].atom);
							bool is_private_prop = (prop_name && std::string(prop_name) == "_isPrivate");
							JSValue prop_val = JS_GetProperty(ctx, val, props[i].atom);
							bool is_private_val = is_private_value(prop_val);

							if (!is_private_prop && !is_private_val) {
								final_valid_props.push_back(props[i]);
							}

							if (prop_name) JS_FreeCString(ctx, prop_name);
							JS_FreeValue(ctx, prop_val);
						}
						JS_FreePropertyEnum(ctx, props, prop_cnt);
					}

					size_t final_prop_size = final_valid_props.size();
					for (size_t i = 0; i < final_prop_size; i++) {
						JSAtom prop_atom = final_valid_props[i].atom;
						const char* prop_name = JS_AtomToCString(ctx, prop_atom);

						if (prop_name && *prop_name != '\0') {
							CreateOutput(get_indent_str(indent + 1), get_color_value(L"Object"));
							CreateOutput(stringToWstring(prop_name) + L": ", get_color_value(L"Property"));

							JSValue prop_val = JS_GetProperty(ctx, val, prop_atom);
							if (!JS_IsException(prop_val)) {
								print_js_value(prop_val, indent + 1);
							}
							else {
								CreateOutput(L"[invalid value]", get_color_value(L"Comment"));
							}
							JS_FreeValue(ctx, prop_val);

							if (i < final_prop_size - 1) {
								CreateOutput(L",", get_color_value(L"Object"));
							}
						}

						if (prop_name) JS_FreeCString(ctx, prop_name);
						CreateOutput(L"\n", get_color_value(L"Object"));
					}

					CreateOutput(get_indent_str(indent) + L"}", get_color_value(L"Object"));
					visited_objs.erase(obj_id);
				}
				else {
					CreateOutput(L"[unknown type]", get_color_value(L"Comment"));
				}
				};

			for (int i = 0; i < argumentCount; i++) {
				if (JS_IsException(argumentValues[i])) {
					CreateOutput(L"[exception]", get_color_value(L"Comment"));
				}
				else {
					print_js_value(argumentValues[i], 0);
				}
				if (i < argumentCount - 1)
					CreateOutput(L" ", get_color_value(L"Object"));
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
			return JS_NewBigUint64(ctx, fc.remove());
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
			if (modeInt & filesystem_open_mode::FILE_MODE_WRITE || modeInt & filesystem_open_mode::FILE_MODE_RDWR) {
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
					if (!((modeInt & filesystem_open_mode::FILE_MODE_WRITE) || (modeInt & filesystem_open_mode::FILE_MODE_RDWR))) {
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

		static std::string GetCurrentWorkDirectory(JSContext* ctx) {
			JSV global = NewGlobalObject(ctx);
			JSV jsWorkDirectory = GetProperty(ctx, global, {
				{"network"},
				{"request"},
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
				return JSV().cset(1);
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
            JSValue ppt = JS_GetPropertyStr(ctx, targetObject.get(0), prop.c_str());
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
			JSValue go = JS_GetGlobalObject(ctx);
			JSV vgo = JSV(ctx, &go);
			vgo.set(1);
			//AppendRelease(ctx, vgo);
			return vgo;
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
		static JSV CreateObject(JSContext* ctx, OBJECT& object) {

			JSV returnObject = NewObject(ctx);

			for (const auto& [key, value] : object) {
				JSV attributeValue = JSV();
				if (value.isString()) {
					attributeValue = NewString(ctx, wstringToString(value.get<std::wstring>()));
				}
				else if (value.isBool()) {
					attributeValue = NewBool(ctx, value.get<bool>());
				}
				else if (value.isDouble()) {
					attributeValue = NewDouble(ctx, value.get<double>());
				}
				else if (value.isNull()) {
					attributeValue = JSV(JS_NULL);
				}
				else if (value.isInt()) {
					attributeValue = NewInt64(ctx, static_cast<int64_t>(value.get<int>()));
				}
				else if (value.isLong()) {
					attributeValue = NewInt64(ctx, static_cast<int64_t>(value.get<long>()));
				}
				else if (value.isLongLong()) {
					attributeValue = NewInt64(ctx, static_cast<int64_t>(value.get<long long>()));
				}
				else if (value.isUInt()) {
					attributeValue = NewUint64(ctx, static_cast<uint64_t>(value.get<unsigned int>()));
				}
				else if (value.isULong()) {
					attributeValue = NewUint64(ctx, static_cast<uint64_t>(value.get<unsigned long>()));
				}
				else if (value.isULongLong()) {
					attributeValue = NewUint64(ctx, static_cast<uint64_t>(value.get<unsigned long long>()));
				}
				else if (value.isObject()) {
					OBJECT nextObject = value.get<OBJECT>();
					attributeValue = CreateObject(ctx, nextObject);
				}
				else {
					attributeValue = JSV(JS_UNDEFINED);
				}
				SetAttribute(ctx, returnObject, wstringToString(key), attributeValue);
			}

			return returnObject;
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
		static bool RemoveAttribute(JSContext* ctx, JSV targetObject, JSV key) {
			JSAtom atom = JS_ValueToAtom(ctx, key.get(0));
			bool ret = JS_DeleteProperty(ctx, targetObject.get(0), atom, 0) ==1;
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
		static bool ReadJSValueAsString(JSContext* ctx, JSV jsVal, std::string& outString) {
			if (ctx == nullptr) return false;
			if (!JS_IsString(jsVal.get(0))) {
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
			*(property.getPtr()) = propVal;
			JS_FreeValue(ctx, propVal);
			return true;
		}
		static bool ReadBinaryAsFormData(JSContext* ctx, BYTEBUFFER_PTR binary, FILELIST& formData) {
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
				FILEDATA file;

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
				},-1);
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
			JSValue jsVal = JS_NewFloat64(ctx, num);
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
			JSValue typedArr = JS_CallConstructor(ctx, constructor, 1, buffer.getPtr());
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

			JSV u8a = JSV(ctx, uint8Arr);
			u8a.set(1);
			//AppendRelease(ctx, u8a);
			return u8a;
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
		static Promise NewPromise(JSContext* ctx) {
			JSValue func[2] = { JS_UNDEFINED,JS_UNDEFINED };
			JSV promise = JSV(ctx, JS_NewPromiseCapability(ctx, func)).cset(1);
			JSV resolve = JSV(ctx, &func[0]).cset(1);
			JSV reject = JSV(ctx, &func[1]).cset(1);

			JSV internal = NewObject(ctx);
			SetAttribute(ctx, internal, "_isPrivate", NewBool(ctx, true));
			SetAttribute(ctx, internal, "resolve", resolve);
			SetAttribute(ctx, internal, "reject", reject);
			SetAttribute(ctx, internal, "promise", promise);

			SetAttribute(ctx, promise, "internal", internal);

			AppendMethod(ctx, promise, "then", [](JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues)->JSValue {

				JSV internal = GetProperty(ctx, thisVal, "internal");
				if (JS_IsException(internal.get(0)) || JS_IsUndefined(internal.get(0))) {
					return JS_EXCEPTION;
				}

				SetAttribute(ctx, internal, "then_resolve", JS_UNDEFINED);
				SetAttribute(ctx, internal, "then_reject", JS_UNDEFINED);

				if (argumentCount >= 1 && JS_IsFunction(ctx, argumentValues[0])) {
					SetAttribute(ctx, internal, "then_resolve", JS_DupValue(ctx, argumentValues[0]));
				}

				if (argumentCount >= 2 && JS_IsFunction(ctx, argumentValues[1])) {
					SetAttribute(ctx, internal, "then_reject", JS_DupValue(ctx, argumentValues[1]));
				}

				CallFunction(ctx, GetProperty(ctx, GetPrototype(ctx, thisVal), "then"), thisVal, argumentCount, argumentValues);

				Promise newPromise = NewPromise(ctx);
				SetAttribute(ctx, internal, "then_return_promise", newPromise.promise);
				SetAttribute(ctx, internal, "then_return_resolve", newPromise.resolve);
				SetAttribute(ctx, internal, "then_return_reject", newPromise.reject);

				return newPromise.promise.get(1);
				});

			AppendMethod(ctx, promise, "catch", [](JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues)->JSValue {
				JSV internal = GetProperty(ctx, thisVal, "internal");
				if (JS_IsException(internal.get(0)) || JS_IsUndefined(internal.get(0))) {
					return JS_EXCEPTION;
				}
				SetAttribute(ctx, internal, "catch_reject", JS_UNDEFINED);
				if (argumentCount >= 1 && JS_IsFunction(ctx, argumentValues[0])) {
					SetAttribute(ctx, internal, "catch_reject", JS_DupValue(ctx, argumentValues[0]));
				}
				JSV originalCatch = GetProperty(ctx, GetPrototype(ctx, thisVal), "catch");
				CallFunction(ctx, originalCatch, thisVal, argumentCount, argumentValues);

				Promise newPromise = NewPromise(ctx);
				SetAttribute(ctx, internal, "catch_return_promise", newPromise.promise);
				SetAttribute(ctx, internal, "catch_return_resolve", newPromise.resolve);
				SetAttribute(ctx, internal, "catch_return_reject", newPromise.reject);

				return newPromise.promise.get(1);
				});

			AppendMethod(ctx, promise, "finally", [](JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues)->JSValue {
				JSV internal = GetProperty(ctx, thisVal, "internal");
				if (JS_IsException(internal.get(0)) || JS_IsUndefined(internal.get(0))) {
					return JS_EXCEPTION;
				}
				SetAttribute(ctx, internal, "finally_cb", JS_UNDEFINED);
				if (argumentCount >= 1 && JS_IsFunction(ctx, argumentValues[0])) {
					SetAttribute(ctx, internal, "finally_cb", JS_DupValue(ctx, argumentValues[0]));
				}
				JSV originalFinally = GetProperty(ctx, GetPrototype(ctx, thisVal), "finally");
				CallFunction(ctx, originalFinally, thisVal, argumentCount, argumentValues);

				Promise newPromise = NewPromise(ctx);
				SetAttribute(ctx, internal, "finally_return_promise", newPromise.promise);
				SetAttribute(ctx, internal, "finally_return_resolve", newPromise.resolve);
				SetAttribute(ctx, internal, "finally_return_reject", newPromise.reject);

				return newPromise.promise.get(1);
				});

			JSV newResolve = NewFunction(ctx, "resolve", [](JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues)->JSValue {

				JSV internal = GetProperty(ctx, thisVal, "internal");
				if (JS_IsException(internal.get(0)) || JS_IsUndefined(internal.get(0))) {
					return JS_EXCEPTION;
				}

				std::vector<JSV> result = {};
				for (int i = 0; i < argumentCount; i++) {
					result.push_back(JSV(ctx, &argumentValues[i]).cget(1).cset(1));
				}
				SetAttribute(ctx, internal, "result", NewArray(ctx, result));

				JSV originalResolve = GetProperty(ctx, internal, "resolve");
				if (JS_IsUndefined(originalResolve.get(0)) || JS_IsNull(originalResolve.get(0)) || !JS_IsFunction(ctx, originalResolve.get(0))) {
					return JS_ThrowReferenceError(ctx, "Promise internal resolve function not found");
				}

				JSV resolveCallResult = CallFunction(ctx, originalResolve, JSV(thisVal), argumentCount, argumentValues);
				if (JS_IsException(resolveCallResult.get(0))) {
					return JS_EXCEPTION;
				}

				JSV thenResolveCb = GetProperty(ctx, internal, "then_resolve");
				JSV thenResolveReturnValue = JS_UNDEFINED;
				if (!JS_IsUndefined(thenResolveCb.get(0)) && !JS_IsNull(thenResolveCb.get(0)) && JS_IsFunction(ctx, thenResolveCb.get(0))) {
					thenResolveReturnValue = CallFunction(ctx, thenResolveCb, JSV(thisVal), argumentCount, argumentValues);
				}

				JSV finallyCb = GetProperty(ctx, internal, "finally_cb");
				JSV finallyReturnValue = JS_UNDEFINED;
				if (!JS_IsUndefined(finallyCb.get(0)) && !JS_IsNull(finallyCb.get(0)) && JS_IsFunction(ctx, finallyCb.get(0))) {
					finallyReturnValue = CallFunction(ctx, finallyCb, JSV(thisVal), 0, nullptr);
				}

				JSV finallyReturnResolveCb = GetProperty(ctx, internal, "finally_return_resolve");
				JSV finallyReturnRejectCb = GetProperty(ctx, internal, "finally_return_reject");
				if (!JS_IsUndefined(finallyReturnResolveCb.get(0)) && !JS_IsNull(finallyReturnResolveCb.get(0)) && JS_IsFunction(ctx, finallyReturnResolveCb.get(0)) &&
					!JS_IsUndefined(finallyReturnRejectCb.get(0)) && !JS_IsNull(finallyReturnRejectCb.get(0)) && JS_IsFunction(ctx, finallyReturnRejectCb.get(0))) {

					JSV newPromise = GetProperty(ctx, internal, "finally_return_promise");
					if (JS_IsPromise(finallyReturnValue.get(0))) {
						std::thread([=]() {
							JSPromiseStateEnum finallyState = JS_PROMISE_PENDING;
							while (!isQuit) {
								JSPromiseStateEnum state = JS_PromiseState(ctx, finallyReturnValue.get(0));
								if (state != JS_PROMISE_PENDING) {
									finallyState = state;
									break;
								}
								AdvSleep(1.0);
							}
							JSValue result = JS_PromiseResult(ctx, finallyReturnValue.get(0));
							CallFunction(ctx, finallyReturnResolveCb, newPromise, { {thenResolveReturnValue} });
							JS_FreeValue(ctx, result);
							}).detach();
					}
					else {
						CallFunction(ctx, finallyReturnResolveCb, newPromise, { {thenResolveReturnValue} });
					}
				}

				return JS_UNDEFINED;
				});

			JSV newReject = NewFunction(ctx, "reject", [](JSContext* ctx, JSValueConst thisVal, int argumentCount, JSValueConst* argumentValues)->JSValue {
				JSV internal = GetProperty(ctx, thisVal, "internal");
				if (JS_IsException(internal.get(0)) || JS_IsUndefined(internal.get(0))) {
					return JS_EXCEPTION;
				}

				std::vector<JSV> result = {};
				for (int i = 0; i < argumentCount; i++) {
					result.push_back(JSV(ctx, &argumentValues[i]).cget(1).cset(1));
				}
				SetAttribute(ctx, internal, "result", NewArray(ctx, result));

				JSV originalReject = GetProperty(ctx, internal, "reject");
				if (JS_IsUndefined(originalReject.get(0)) || JS_IsNull(originalReject.get(0)) || !JS_IsFunction(ctx, originalReject.get(0))) {
					return JS_ThrowReferenceError(ctx, "Promise internal reject function not found");
				}

				JSV rejectCallResult = CallFunction(ctx, originalReject, JSV(thisVal), argumentCount, argumentValues);
				if (JS_IsException(rejectCallResult.get(0))) {
					return JS_EXCEPTION;
				}

				JSV catchRejectCb = GetProperty(ctx, internal, "catch_reject");
				JSV catchRejectReturnValue = JS_UNDEFINED;
				if (!JS_IsUndefined(catchRejectCb.get(0)) && !JS_IsNull(catchRejectCb.get(0)) && JS_IsFunction(ctx, catchRejectCb.get(0))) {
					catchRejectReturnValue = CallFunction(ctx, catchRejectCb, JSV(thisVal), argumentCount, argumentValues);
				}

				JSV finallyCb = GetProperty(ctx, internal, "finally_cb");
				JSV finallyReturnValue = JS_UNDEFINED;
				if (!JS_IsUndefined(finallyCb.get(0)) && !JS_IsNull(finallyCb.get(0)) && JS_IsFunction(ctx, finallyCb.get(0))) {
					finallyReturnValue = CallFunction(ctx, finallyCb, JSV(thisVal), 0, nullptr);
				}

				JSV finallyReturnResolveCb = GetProperty(ctx, internal, "finally_return_resolve");
				JSV finallyReturnRejectCb = GetProperty(ctx, internal, "finally_return_reject");
				if (!JS_IsUndefined(finallyReturnResolveCb.get(0)) && !JS_IsNull(finallyReturnResolveCb.get(0)) && JS_IsFunction(ctx, finallyReturnResolveCb.get(0)) &&
					!JS_IsUndefined(finallyReturnRejectCb.get(0)) && !JS_IsNull(finallyReturnRejectCb.get(0)) && JS_IsFunction(ctx, finallyReturnRejectCb.get(0))) {

					JSV newPromise = GetProperty(ctx, internal, "finally_return_promise");
					if (JS_IsPromise(finallyReturnValue.get(0))) {
						std::thread([=]() {
							JSPromiseStateEnum finallyState = JS_PROMISE_PENDING;
							while (!isQuit) {
								JSPromiseStateEnum state = JS_PromiseState(ctx, finallyReturnValue.get(0));
								if (state != JS_PROMISE_PENDING) {
									finallyState = state;
									break;
								}
								AdvSleep(1.0);
							}
							JSValue result = JS_PromiseResult(ctx, finallyReturnValue.get(0));
							CallFunction(ctx, finallyReturnRejectCb, newPromise, { {catchRejectReturnValue} });
							JS_FreeValue(ctx, result);
							}).detach();
					}
					else {
						CallFunction(ctx, finallyReturnRejectCb, newPromise, { {catchRejectReturnValue} });
					}
				}

				JSV catchReturnResolveCb = GetProperty(ctx, internal, "catch_return_resolve");
				JSV catchReturnRejectCb = GetProperty(ctx, internal, "catch_return_reject");
				if (!JS_IsUndefined(catchReturnResolveCb.get(0)) && !JS_IsNull(catchReturnResolveCb.get(0)) && JS_IsFunction(ctx, catchReturnResolveCb.get(0)) && !JS_IsUndefined(catchReturnRejectCb.get(0)) && !JS_IsNull(catchReturnRejectCb.get(0)) && JS_IsFunction(ctx, catchReturnRejectCb.get(0))) {

					JSV newPromise = GetProperty(ctx, internal, "then_return_promise");
					JSV newPromiseInternal = GetProperty(ctx, newPromise, "internal");

					if (JS_IsPromise(catchRejectCb.get(0))) {
						std::thread([=]() {

							JSPromiseStateEnum finallyState = JS_PROMISE_PENDING;
							while (!isQuit) {
								JSPromiseStateEnum state = JS_PromiseState(ctx, catchRejectReturnValue.get(0));
								if (state != JS_PROMISE_PENDING) {
									finallyState = state;
									break;
								}
								AdvSleep(1.0);
							}

							JSValue result = JS_PromiseResult(ctx, catchRejectReturnValue.get(0));
							if (finallyState == JS_PROMISE_FULFILLED) {
								CallFunction(ctx, catchReturnResolveCb, newPromise, { {result} });
								JS_FreeValue(ctx, result);
							}
							else {
								CallFunction(ctx, catchReturnRejectCb, newPromise, { {result} });
								JS_FreeValue(ctx, result);
							}


							}).detach();

					}
					else {
						CallFunction(ctx, catchReturnResolveCb, newPromise, { {catchRejectReturnValue} });
					}


				}

				JSV thenResolveCb = GetProperty(ctx, internal, "then_return_resolve");
				JSV thenRejectCb = GetProperty(ctx, internal, "then_return_reject");
				if (!JS_IsUndefined(thenResolveCb.get(0)) && !JS_IsNull(thenResolveCb.get(0)) && JS_IsFunction(ctx, thenResolveCb.get(0)) && !JS_IsUndefined(thenRejectCb.get(0)) && !JS_IsNull(thenRejectCb.get(0)) && JS_IsFunction(ctx, thenRejectCb.get(0))) {
					JSV newPromise = GetProperty(ctx, internal, "then_return_promise");
					JSV newPromiseInternal = GetProperty(ctx, newPromise, "internal");

					if (JS_IsPromise(catchRejectReturnValue.get(0))) {
						std::thread([=]() {

							JSPromiseStateEnum finallyState = JS_PROMISE_PENDING;
							while (!isQuit) {
								JSPromiseStateEnum state = JS_PromiseState(ctx, catchRejectReturnValue.get(0));
								if (state != JS_PROMISE_PENDING) {
									finallyState = state;
									break;
								}
								AdvSleep(1.0);
							}

							JSValue result = JS_PromiseResult(ctx, catchRejectReturnValue.get(0));
							if (finallyState == JS_PROMISE_FULFILLED) {
								CallFunction(ctx, thenResolveCb, newPromise, { {result} });
								JS_FreeValue(ctx, result);
							}
							else {
								CallFunction(ctx, thenRejectCb, newPromise, { {result} });
								JS_FreeValue(ctx, result);
							}

							}).detach();
					}
					else {
						CallFunction(ctx, thenRejectCb, newPromise, { {catchRejectReturnValue} });
					}


				}

				return JS_UNDEFINED;
				});


			SetAttribute(ctx, internal, "newResolve", newResolve);
			SetAttribute(ctx, internal, "newReject", newReject);
			Promise returnPromise = {};
			returnPromise.promise = promise;
			returnPromise.resolve = newResolve;
			returnPromise.reject = newReject;
			returnPromise.callResolve = [=](JSContext* ctx, std::vector<JSV> args) -> JSV {
				return CallFunction(ctx, newResolve, promise, args);
				};
			returnPromise.callReject = [=](JSContext* ctx, std::vector<JSV> args)-> JSV {
				return CallFunction(ctx, newReject, promise, args);
				};
			returnPromise.Resolve = [=](JSContext* ctx, JSV arg)-> JSV {
				JSValue jsArg = arg.get(0);
				return CallFunction(ctx, newResolve, promise, 1, &jsArg);
				};
			returnPromise.Reject = [=](JSContext* ctx, JSV arg)-> JSV {
				JSValue jsArg = arg.get(0);
				return CallFunction(ctx, newReject, promise, 1, &jsArg);
				};
			return returnPromise;
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

		static JSV CallFunction(JSContext* ctx, JSV func, JSV thisVal, std::vector<JSV> args) {
			std::vector<JSValue> jsArgs = {};
			jsArgs.reserve(args.size());
			for (const auto& jsv : args) jsArgs.push_back(jsv.get(0));
			return JSV(ctx, JS_Call(ctx, func.get(0), thisVal.get(0), static_cast<int>(jsArgs.size()), jsArgs.data())).cset(1);
		}
		static JSV CallFunction(JSContext* ctx, JSV func, JSV thisVal, int argc, JSValueConst* argv) {
			JSValue funcVal = func.get(0);
			if (JS_IsUndefined(funcVal) || JS_IsNull(funcVal) || !JS_IsFunction(ctx, funcVal)) {
				return JSV(JS_UNDEFINED);
			}
			return JSV(ctx, JS_Call(ctx, funcVal, thisVal.get(0), argc, argv)).cset(1);
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

		static bool ModifyJSValue(JSContext* ctx, JSV& originJsv, JSV& targetJsv) {
			JSValue targetBuffer = JS_UNDEFINED;
			JSValue originBuffer = JS_UNDEFINED;

			auto cleanup = [&]() {
				if (!JS_IsSameValue(ctx, targetBuffer, JS_UNDEFINED)) JS_FreeValue(ctx, targetBuffer);
				if (!JS_IsSameValue(ctx, originBuffer, JS_UNDEFINED)) JS_FreeValue(ctx, originBuffer);
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
				const size_t keySizeBytes = length / 8;
				if (keySizeBytes != 16 && keySizeBytes != 24 && keySizeBytes != 32) {
					return false;
				}

				outBinary->resize(keySizeBytes);
				rng.GenerateBlock(outBinary->data(), keySizeBytes);
				return !outBinary->empty() && outBinary->size() == keySizeBytes;
			}
			else if (algo.find("HMAC") != std::string::npos) {
				if (length < 8 || length > 1024) {
					return false;
				}
				const size_t keySizeBytes = length / 8;

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

					size_t pubSize = pubQueue.MaxRetrievable();
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
				if (length != 1024 && length != 2048 && length != 4096 && length != 8192) {
					return false;
				}
				if (publicExponent != 3 && publicExponent != 17 && publicExponent != 65537) {
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
					outBinary->resize(pubQueue.MaxRetrievable());
					pubQueue.Get(outBinary->data(), outBinary->size());

					if (privateKey != nullptr) {
						privateKey->clear();
						CryptoPP::ByteQueue privQueue;
						rsaPrivKey.Save(privQueue);
						privateKey->resize(privQueue.MaxRetrievable());
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
				if (!curveValid) {
					return false;
				}

				try {
					if (algo == "ECDSA") {
						bool hashValid = false;
						if (hashName == "SHA-1" || hashName == "SHA-256" || hashName == "SHA-384" ||
							hashName == "SHA-512" || hashName == "SHA-3-256" || hashName == "SHA-3-384" || hashName == "SHA-3-512") {
							hashValid = true;
						}
						if (!hashValid) {
							return false;
						}

						void* privKeyPtr = nullptr;
						void* pubKeyPtr = nullptr;

						if (hashName == "SHA-1") {
							auto priv = new CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA1>::PrivateKey();
							auto pub = new CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA1>::PublicKey();
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

						if (!privKeyPtr || !pubKeyPtr) {
							return false;
						}

						auto& eccPrivKey = *static_cast<CryptoPP::DL_PrivateKey_EC<CryptoPP::ECP>*>(privKeyPtr);
						auto& eccPubKey = *static_cast<CryptoPP::DL_PublicKey_EC<CryptoPP::ECP>*>(pubKeyPtr);

						eccPrivKey.Initialize(rng, ecParams);
						eccPrivKey.MakePublicKey(eccPubKey);

						CryptoPP::ByteQueue pubQueue;
						eccPubKey.Save(pubQueue);
						outBinary->resize(pubQueue.MaxRetrievable());
						pubQueue.Get(outBinary->data(), outBinary->size());

						if (privateKey != nullptr) {
							privateKey->clear();
							CryptoPP::ByteQueue privQueue;
							eccPrivKey.Save(privQueue);
							privateKey->resize(privQueue.MaxRetrievable());
							privQueue.Get(privateKey->data(), privateKey->size());
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

						outBinary->resize(pubQueue.MaxRetrievable());
						pubQueue.Get(outBinary->data(), outBinary->size());

						if (privateKey != nullptr) {
							privateKey->clear();
							CryptoPP::ByteQueue privQueue;
							CryptoPP::DL_PrivateKey_EC<CryptoPP::ECP> privKey;
							privKey.Initialize(ecParams, CryptoPP::Integer(ecdhPrivKey.data(), ecdhPrivKey.size()));
							privKey.Save(privQueue);
							privateKey->resize(privQueue.MaxRetrievable());
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
				if (length != 256) {
					return false;
				}
				outBinary->resize(32);
				rng.GenerateBlock(outBinary->data(), 32);
				return !outBinary->empty() && outBinary->size() == 32;
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
			uint64_t length = (nameCurve == "P-384") ? 384 : (nameCurve == "P-521") ? 521 : 256;
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

		static bool crypto_subtle_importKey_jwk_RSA(BYTEBUFFER_PTR e, BYTEBUFFER_PTR n, BYTEBUFFER_PTR outputBinary,
			BYTEBUFFER_PTR d = nullptr, BYTEBUFFER_PTR p = nullptr, BYTEBUFFER_PTR q = nullptr,
			BYTEBUFFER_PTR dp = nullptr, BYTEBUFFER_PTR dq = nullptr, BYTEBUFFER_PTR qi = nullptr)
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

					size_t privSize = privQueue.MaxRetrievable();
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

					size_t pubSize = pubQueue.MaxRetrievable();
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
					outBinary->resize(spkiQueue.MaxRetrievable());
					spkiQueue.Get(outBinary->data(), outBinary->size());
				}
				else if (d != nullptr && !d->empty() && x == nullptr && y == nullptr) {
					CryptoPP::DL_PrivateKey_EC<CryptoPP::ECP> privKey;
					privKey.Initialize(ecParams, CryptoPP::Integer(d->data(), d->size()));

					CryptoPP::ByteQueue pkcs8Queue;
					privKey.Save(pkcs8Queue);
					outBinary->resize(pkcs8Queue.MaxRetrievable());
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

		static ULL GetNewFileControllerId(JSContext* ctx) {
			JSMData* jsmdPtr = nullptr;
			if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) return 0;
			ULL newId = 1;
			while (jsmdPtr->fileControllerList.find(newId) != jsmdPtr->fileControllerList.end()) {
				if (newId == ULLONG_MAX) {
					return 0;
				}
				++newId;
			}
			return newId;
		}
		static ULL GetNewExecuteJsId(JSContext* ctx) {
			JSMData* jsmdPtr = nullptr;
			if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) return 0;
			ULL newId = 1;
			while (jsmdPtr->executeJsList.find(newId) != jsmdPtr->executeJsList.end()) {
				if (newId == ULLONG_MAX) {
					return 0;
				}
				++newId;
			}
			return newId;
		}
		static ULL GetNewFormDataId(JSContext* ctx) {
			JSMData* jsmdPtr = nullptr;
			if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) return 0;
			ULL newId = 1;
			while (jsmdPtr->formDataList.find(newId) != jsmdPtr->formDataList.end()) {
				if (newId == ULLONG_MAX) {
					return 0;
				}
				++newId;
			}
			return newId;
		}

		static bool AppendRelease(JSContext* ctx, JSV& jsv) {
			JSMData* jsmdPtr = nullptr;
			if (!GetData(ctx, &jsmdPtr) || jsmdPtr == nullptr) {
				return false;
			}
			for (const JSV& existing : jsmdPtr->releaseList) {
				if (existing == jsv) {
					return true;
				}
			}
			jsmdPtr->releaseList.emplace_back(jsv);
			return true;
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

			}catch(...){}

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
		JSINFO eval(const std::wstring& InCode, const std::wstring& fileName = L"typein") {
			if (!isInit()) return {};
			std::string code = wstringToString(InCode);
			JSValue result = JS_Eval(
				jsContext,
				code.c_str(),
				code.length(),
				wstringToString(fileName).c_str(),
				JS_EVAL_TYPE_GLOBAL
			);
			JSINFO jsif = {};
			jsif.isValid = true;
			jsif.result = JSV(jsContext, result).cset(1);

			if (JS_IsException(result)) {
				JSValue exception = JS_GetException(jsContext);
				const char* message = JS_ToCString(jsContext, exception);
				if (message == nullptr) {
					JS_FreeValue(jsContext, exception);
					goto EndProcess;
				}
				if (std::string(message) == "[native code] Quit the context") {
					JS_FreeCString(jsContext, message);
					JS_FreeValue(jsContext, exception);

					jsif.isSuccess = true;
					jsif.message = L"undefined";
					goto EndProcess;
				}

				jsif.isSuccess = false;
				jsif.message = (message != nullptr) ? stringToWstring(message) : L"Unknown Error";
				jsif.errorFront = GetErrorFront(jsContext, exception);
				jsif.errorStack = GetErrorFrontStack(jsContext, exception);

				JS_FreeCString(jsContext, message);
				JS_FreeValue(jsContext, exception);
			}
			else {
				const char* message = JS_ToCString(jsContext, result);
				if (message == nullptr) {
					jsif.isSuccess = true;
					jsif.message = L"undefined";
					goto EndProcess;
				}

				jsif.isSuccess = true;
				jsif.message = (message != nullptr) ? stringToWstring(message) : L"undefined";

				JS_FreeCString(jsContext, message);

                bool tempIsConsoleEnv = isConsoleEnv;
				isConsoleEnv = false;
				ClearOutput();
				JavaScriptMethod::CallFunction(jsContext, JavaScriptMethod::GetProperty(jsContext, JavaScriptMethod::NewGlobalObject(jsContext), { {"console"}, {"log"} }), JS_UNDEFINED, { {jsif.result} });
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

		std::vector<JSContext*> subContextList = {};
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
	static JSV CallFunction(JSContext* ctx, JSV func, JSV thisVal, std::vector<JSV> args) {
		return JavaScriptMethod::CallFunction(ctx, func, thisVal, args);
	}
	static JSV CallFunction(JSContext* ctx, JSV func, JSV thisVal, int argc, JSValueConst* argv) {
		return JavaScriptMethod::CallFunction(ctx, func, thisVal, argc, argv);
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

	RunInThread runInThread;
}

#endif