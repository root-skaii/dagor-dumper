#include "../include/logger.h"
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

HANDLE Logger::s_file  = INVALID_HANDLE_VALUE;
HANDLE Logger::s_mutex = nullptr;
char   Logger::s_path[MAX_PATH] = {};
bool   Logger::s_open  = false;

bool Logger::init(const char* path) {
    if (s_open) close();

    s_mutex = CreateMutexA(nullptr, FALSE, nullptr);

    // Write-through so the log survives a crash of the host process.
    s_file = CreateFileA(
        path,
        GENERIC_WRITE,
        FILE_SHARE_READ,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
        nullptr
    );

    if (s_file == INVALID_HANDLE_VALUE) {
        OutputDebugStringA("[DagorDumper] ERROR: Could not open log file\n");
        return false;
    }

    strncpy_s(s_path, path, MAX_PATH - 1);
    s_open = true;

    DWORD written = 0;
    const char bom[] = "\xEF\xBB\xBF";
    WriteFile(s_file, bom, 3, &written, nullptr);

    write(LogLevel::INFO, __FILE__, __LINE__,
          "DagorDumper log started — path: %s", path);
    write(LogLevel::INFO, __FILE__, __LINE__,
          "Process: PID=%u  Base=0x%016llX",
          GetCurrentProcessId(),
          (unsigned long long)GetModuleHandleA(nullptr));
    return true;
}

void Logger::write(LogLevel level, const char* file, int line, const char* fmt, ...) {
    if (!s_open) return;

    SYSTEMTIME st{};
    GetLocalTime(&st);

    const char* lvl_str = (level == LogLevel::INFO) ? "INFO" :
                          (level == LogLevel::WARN) ? "WARN" : "ERR ";

    const char* fname = file;
    for (const char* p = file; *p; p++)
        if (*p == '\\' || *p == '/') fname = p + 1;

    char msg_buf[2048] = {};
    va_list args;
    va_start(args, fmt);
    vsnprintf_s(msg_buf, sizeof(msg_buf), _TRUNCATE, fmt, args);
    va_end(args);

    char line_buf[2304] = {};
    int line_len = _snprintf_s(line_buf, sizeof(line_buf), _TRUNCATE,
        "[%02u:%02u:%02u.%03u] [%s] (%s:%d) %s\r\n",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
        lvl_str, fname, line, msg_buf);
    if (line_len < 0) line_len = (int)strlen(line_buf);

    if (s_mutex) WaitForSingleObject(s_mutex, INFINITE);

    if (s_open && s_file != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        WriteFile(s_file, line_buf, (DWORD)line_len, &written, nullptr);
    }

    char dbg_buf[2304] = {};
    _snprintf_s(dbg_buf, sizeof(dbg_buf), _TRUNCATE, "[DagorDumper][%s] %s\n", lvl_str, msg_buf);
    OutputDebugStringA(dbg_buf);

    if (s_mutex) ReleaseMutex(s_mutex);
}

void Logger::close() {
    if (!s_open) return;
    write(LogLevel::INFO, __FILE__, __LINE__, "Logger closing.");
    s_open = false;
    if (s_file != INVALID_HANDLE_VALUE) {
        CloseHandle(s_file);
        s_file = INVALID_HANDLE_VALUE;
    }
    if (s_mutex) {
        CloseHandle(s_mutex);
        s_mutex = nullptr;
    }
}

const char* Logger::path() { return s_path; }
