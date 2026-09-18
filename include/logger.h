// Thread-safe file logger, mirrored to OutputDebugString (visible in DebugView / x64dbg).
#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>

enum class LogLevel : int { INFO = 0, WARN = 1, ERR = 2 };

class Logger {
public:
    static bool init(const char* path);
    static void write(LogLevel level, const char* file, int line, const char* fmt, ...);
    static void close();
    static const char* path();

private:
    static HANDLE   s_file;
    static HANDLE   s_mutex;
    static char     s_path[MAX_PATH];
    static bool     s_open;
};

#define LOG_INFO(fmt, ...) Logger::write(LogLevel::INFO, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...) Logger::write(LogLevel::WARN, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_ERR( fmt, ...) Logger::write(LogLevel::ERR,  __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define LOG_SECTION(name) Logger::write(LogLevel::INFO, __FILE__, __LINE__, \
    "-------------------- %s --------------------", name)
