#pragma once

// Cross-platform compatibility layer for qbscanner
// Abstracts OS-specific process monitoring and system calls

#include <string>
#include <vector>
#include <cstdint>

#ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN
    #include <windows.h>
    #include <psapi.h>
    #include <tlhelp32.h>
    #include <io.h>
    #include <process.h>
    typedef DWORD pid_t;
    typedef HANDLE process_handle_t;
    #define PATH_MAX MAX_PATH
#else
    #include <unistd.h>
    #include <sys/wait.h>
    #include <sys/ptrace.h>
    #include <sys/syscall.h>
    #include <sys/user.h>
    #include <sys/types.h>
    #include <signal.h>
    #include <errno.h>
    typedef pid_t process_handle_t;
    #include <limits.h>
#endif

// Cross-platform process monitoring interface
class ProcessMonitor {
public:
    struct ProcessInfo {
        pid_t pid;
        std::string command_line;
        std::string executable_path;
    };
    
    struct IOEvent {
        enum Type {
            READ_FILE,
            WRITE_FILE,
            NETWORK_SEND,
            NETWORK_RECV,
            PROCESS_CREATE,
            PROCESS_EXIT
        };
        
        Type type;
        pid_t pid;
        std::string target;      // File path or network endpoint
        std::vector<uint8_t> data;
        size_t size;
        uint64_t timestamp;
    };
    
    ProcessMonitor();
    ~ProcessMonitor();
    
    // Process lifecycle
    bool startProcess(const std::string& executable, const std::vector<std::string>& args, pid_t& out_pid);
    bool attachToProcess(pid_t pid);
    bool detachFromProcess(pid_t pid);
    bool waitForEvents(std::vector<IOEvent>& events, int timeout_ms = 1000);
    
    // Process information
    bool getProcessInfo(pid_t pid, ProcessInfo& info);
    std::vector<pid_t> getChildProcesses(pid_t parent_pid);
    
    // Memory and data access
    bool readProcessMemory(pid_t pid, uint64_t address, void* buffer, size_t size);
    std::string readProcessString(pid_t pid, uint64_t address, size_t max_length = 256);
    
    // Cross-platform utility functions
    static std::string getExecutablePath();
    static std::string getTempDirectory();
    static bool fileExists(const std::string& path);
    static std::vector<std::string> findSystemFonts();
    
private:
    class PlatformImpl;
    PlatformImpl* impl;
};