#include "platform.h"
#include <iostream>
#include <map>
#include <thread>
#include <chrono>
#include <sstream>

#ifdef _WIN32

class ProcessMonitor::PlatformImpl {
public:
    std::map<pid_t, HANDLE> debugged_processes;
    std::map<pid_t, ProcessInfo> process_info_cache;
    bool monitoring_active = false;
    std::thread monitoring_thread;
    std::vector<IOEvent> event_queue;
    mutable std::mutex event_mutex;
    
    PlatformImpl() {}
    
    ~PlatformImpl() {
        monitoring_active = false;
        if (monitoring_thread.joinable()) {
            monitoring_thread.join();
        }
        
        // Detach from all processes
        for (auto& [pid, handle] : debugged_processes) {
            DebugActiveProcessStop(pid);
            if (handle != INVALID_HANDLE_VALUE) {
                CloseHandle(handle);
            }
        }
    }
    
    bool startProcess(const std::string& executable, const std::vector<std::string>& args, pid_t& out_pid) {
        // Build command line
        std::string cmdline = "\"" + executable + "\"";
        for (const auto& arg : args) {
            cmdline += " \"" + arg + "\"";
        }
        
        STARTUPINFOA si = {0};
        PROCESS_INFORMATION pi = {0};
        si.cb = sizeof(si);
        
        // Create process with debugging enabled
        BOOL result = CreateProcessA(
            executable.c_str(),
            const_cast<char*>(cmdline.c_str()),
            nullptr, nullptr, FALSE,
            DEBUG_PROCESS | CREATE_NEW_CONSOLE,
            nullptr, nullptr, &si, &pi
        );
        
        if (!result) {
            std::cerr << "CreateProcess failed: " << GetLastError() << std::endl;
            return false;
        }
        
        out_pid = pi.dwProcessId;
        debugged_processes[out_pid] = pi.hProcess;
        
        // Cache process info
        ProcessInfo info;
        info.pid = out_pid;
        info.command_line = cmdline;
        info.executable_path = executable;
        process_info_cache[out_pid] = info;
        
        CloseHandle(pi.hThread);
        
        if (!monitoring_active) {
            startMonitoring();
        }
        
        return true;
    }
    
    bool attachToProcess(pid_t pid) {
        if (!DebugActiveProcess(pid)) {
            std::cerr << "DebugActiveProcess failed: " << GetLastError() << std::endl;
            return false;
        }
        
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (hProcess == nullptr) {
            std::cerr << "OpenProcess failed: " << GetLastError() << std::endl;
            DebugActiveProcessStop(pid);
            return false;
        }
        
        debugged_processes[pid] = hProcess;
        
        if (!monitoring_active) {
            startMonitoring();
        }
        
        return true;
    }
    
    bool detachFromProcess(pid_t pid) {
        auto it = debugged_processes.find(pid);
        if (it == debugged_processes.end()) {
            return false;
        }
        
        DebugActiveProcessStop(pid);
        if (it->second != INVALID_HANDLE_VALUE) {
            CloseHandle(it->second);
        }
        
        debugged_processes.erase(it);
        process_info_cache.erase(pid);
        
        return true;
    }
    
    void startMonitoring() {
        monitoring_active = true;
        monitoring_thread = std::thread([this]() {
            monitoringLoop();
        });
    }
    
    void monitoringLoop() {
        while (monitoring_active && !debugged_processes.empty()) {
            DEBUG_EVENT debug_event;
            
            if (WaitForDebugEvent(&debug_event, 100)) {
                handleDebugEvent(debug_event);
                ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, DBG_CONTINUE);
            }
        }
    }
    
    void handleDebugEvent(const DEBUG_EVENT& debug_event) {
        std::lock_guard<std::mutex> lock(event_mutex);
        
        IOEvent event;
        event.pid = debug_event.dwProcessId;
        event.timestamp = GetTickCount64();
        
        switch (debug_event.dwDebugEventCode) {
            case CREATE_PROCESS_DEBUG_EVENT: {
                event.type = IOEvent::PROCESS_CREATE;
                event.target = "process_create";
                
                // Extract executable name
                char exe_path[MAX_PATH];
                HANDLE hProcess = debugged_processes[debug_event.dwProcessId];
                if (GetModuleFileNameExA(hProcess, nullptr, exe_path, MAX_PATH)) {
                    event.target = exe_path;
                }
                
                event_queue.push_back(event);
                break;
            }
            
            case EXIT_PROCESS_DEBUG_EVENT: {
                event.type = IOEvent::PROCESS_EXIT;
                event.target = "exit_code_" + std::to_string(debug_event.u.ExitProcess.dwExitCode);
                event_queue.push_back(event);
                
                // Clean up
                detachFromProcess(debug_event.dwProcessId);
                break;
            }
            
            case LOAD_DLL_DEBUG_EVENT: {
                // Track DLL loads as file access
                event.type = IOEvent::READ_FILE;
                
                char dll_path[MAX_PATH];
                HANDLE hProcess = debugged_processes[debug_event.dwProcessId];
                if (GetModuleFileNameExA(hProcess, (HMODULE)debug_event.u.LoadDll.hFile, dll_path, MAX_PATH)) {
                    event.target = dll_path;
                    event_queue.push_back(event);
                }
                
                if (debug_event.u.LoadDll.hFile) {
                    CloseHandle(debug_event.u.LoadDll.hFile);
                }
                break;
            }
            
            case OUTPUT_DEBUG_STRING_EVENT: {
                // Capture debug output as write event
                event.type = IOEvent::WRITE_FILE;
                event.target = "debug_output";
                
                auto& debug_str = debug_event.u.DebugString;
                if (debug_str.nDebugStringLength > 0) {
                    event.data.resize(debug_str.nDebugStringLength);
                    SIZE_T bytes_read;
                    
                    HANDLE hProcess = debugged_processes[debug_event.dwProcessId];
                    if (ReadProcessMemory(hProcess, debug_str.lpDebugStringData, 
                                        event.data.data(), debug_str.nDebugStringLength, &bytes_read)) {
                        event.size = bytes_read;
                        event_queue.push_back(event);
                    }
                }
                break;
            }
        }
    }
    
    bool waitForEvents(std::vector<IOEvent>& events, int timeout_ms) {
        std::lock_guard<std::mutex> lock(event_mutex);
        
        if (!event_queue.empty()) {
            events = std::move(event_queue);
            event_queue.clear();
            return true;
        }
        
        return false;
    }
    
    bool getProcessInfo(pid_t pid, ProcessInfo& info) {
        auto it = process_info_cache.find(pid);
        if (it != process_info_cache.end()) {
            info = it->second;
            return true;
        }
        
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (hProcess == nullptr) {
            return false;
        }
        
        char exe_path[MAX_PATH];
        if (GetModuleFileNameExA(hProcess, nullptr, exe_path, MAX_PATH)) {
            info.pid = pid;
            info.executable_path = exe_path;
            info.command_line = exe_path; // Simplified
            
            process_info_cache[pid] = info;
            CloseHandle(hProcess);
            return true;
        }
        
        CloseHandle(hProcess);
        return false;
    }
    
    std::vector<pid_t> getChildProcesses(pid_t parent_pid) {
        std::vector<pid_t> children;
        
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            return children;
        }
        
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(pe);
        
        if (Process32First(hSnapshot, &pe)) {
            do {
                if (pe.th32ParentProcessID == parent_pid) {
                    children.push_back(pe.th32ProcessID);
                }
            } while (Process32Next(hSnapshot, &pe));
        }
        
        CloseHandle(hSnapshot);
        return children;
    }
    
    bool readProcessMemory(pid_t pid, uint64_t address, void* buffer, size_t size) {
        auto it = debugged_processes.find(pid);
        if (it == debugged_processes.end()) {
            return false;
        }
        
        SIZE_T bytes_read;
        return ReadProcessMemory(it->second, (LPCVOID)address, buffer, size, &bytes_read) && bytes_read == size;
    }
    
    std::string readProcessString(pid_t pid, uint64_t address, size_t max_length) {
        std::string result;
        std::vector<char> buffer(max_length);
        
        if (readProcessMemory(pid, address, buffer.data(), max_length)) {
            for (size_t i = 0; i < max_length; i++) {
                if (buffer[i] == '\0') break;
                if (isprint(buffer[i])) {
                    result += buffer[i];
                }
            }
        }
        
        return result;
    }
};

// ProcessMonitor implementation
ProcessMonitor::ProcessMonitor() : impl(new PlatformImpl()) {}
ProcessMonitor::~ProcessMonitor() { delete impl; }

bool ProcessMonitor::startProcess(const std::string& executable, const std::vector<std::string>& args, pid_t& out_pid) {
    return impl->startProcess(executable, args, out_pid);
}

bool ProcessMonitor::attachToProcess(pid_t pid) {
    return impl->attachToProcess(pid);
}

bool ProcessMonitor::detachFromProcess(pid_t pid) {
    return impl->detachFromProcess(pid);
}

bool ProcessMonitor::waitForEvents(std::vector<IOEvent>& events, int timeout_ms) {
    return impl->waitForEvents(events, timeout_ms);
}

bool ProcessMonitor::getProcessInfo(pid_t pid, ProcessInfo& info) {
    return impl->getProcessInfo(pid, info);
}

std::vector<pid_t> ProcessMonitor::getChildProcesses(pid_t parent_pid) {
    return impl->getChildProcesses(parent_pid);
}

bool ProcessMonitor::readProcessMemory(pid_t pid, uint64_t address, void* buffer, size_t size) {
    return impl->readProcessMemory(pid, address, buffer, size);
}

std::string ProcessMonitor::readProcessString(pid_t pid, uint64_t address, size_t max_length) {
    return impl->readProcessString(pid, address, max_length);
}

// Static utility functions
std::string ProcessMonitor::getExecutablePath() {
    char path[MAX_PATH];
    GetModuleFileNameA(nullptr, path, MAX_PATH);
    return std::string(path);
}

std::string ProcessMonitor::getTempDirectory() {
    char temp_path[MAX_PATH];
    GetTempPathA(MAX_PATH, temp_path);
    return std::string(temp_path);
}

bool ProcessMonitor::fileExists(const std::string& path) {
    return GetFileAttributesA(path.c_str()) != INVALID_FILE_ATTRIBUTES;
}

std::vector<std::string> ProcessMonitor::findSystemFonts() {
    std::vector<std::string> fonts;
    
    // Windows system font directories
    std::vector<std::string> font_dirs = {
        "C:\\Windows\\Fonts\\",
        "C:\\Windows\\System32\\fonts\\",
    };
    
    // Common font filenames
    std::vector<std::string> font_files = {
        "arial.ttf",
        "calibri.ttf",
        "segoeui.ttf",
        "tahoma.ttf",
        "verdana.ttf"
    };
    
    for (const auto& dir : font_dirs) {
        for (const auto& font : font_files) {
            std::string full_path = dir + font;
            if (fileExists(full_path)) {
                fonts.push_back(full_path);
            }
        }
    }
    
    return fonts;
}

#endif // _WIN32