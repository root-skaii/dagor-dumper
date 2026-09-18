#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <thread>
#include <string>
#include <cstdio>

#include "../include/logger.h"

void write_dump(const char* output_path);

// Registration chains are complete before main(), but runtime layout discovery
// needs a populated EntityManager — inject in-match, or raise this if the
// runtime section comes back empty.
static constexpr DWORD DUMP_DELAY_MS = 5000;

static void dumper_thread() {
    char temp[MAX_PATH] = {};
    GetTempPathA(MAX_PATH, temp);

    std::string log_path  = std::string(temp) + "dagor_dumper.log";
    std::string dump_path = std::string(temp) + "dagor_ecs_dump.txt";

    if (!Logger::init(log_path.c_str())) {
        OutputDebugStringA("[DagorDumper] FATAL: Could not open log file\n");
    }

    LOG_INFO("=== DagorDumper started ===");
    LOG_INFO("Waiting %u ms for game static init to complete...", DUMP_DELAY_MS);
    Sleep(DUMP_DELAY_MS);
    LOG_INFO("Delay complete. Beginning chain walk.");

    LOG_INFO("Dump path: %s", dump_path.c_str());
    write_dump(dump_path.c_str());

    LOG_INFO("=== DagorDumper complete ===");
    LOG_INFO("Log:  %s", log_path.c_str());
    LOG_INFO("Dump: %s", dump_path.c_str());

    std::string msg =
        "DagorEngine ECS dump complete!\n\n"
        "Dump:  " + dump_path + "\n"
        "Log:   " + log_path;
    MessageBoxA(nullptr, msg.c_str(), "DagorDumper", MB_ICONINFORMATION | MB_TOPMOST);

    Logger::close();
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID /*reserved*/) {
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        std::thread(dumper_thread).detach();
        break;
    case DLL_PROCESS_DETACH:
        Logger::close();
        break;
    default:
        break;
    }
    return TRUE;
}
