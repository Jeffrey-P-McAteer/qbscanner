#include "platform.h"
#include <iostream>
#include <map>
#include <thread>
#include <chrono>
#include <sstream>
#include <fstream>
#include <dirent.h>
#include <sys/stat.h>
#include <mutex>
#include <cstring>

#ifndef _WIN32

class ProcessMonitor::PlatformImpl {
public:
    std::map<pid_t, bool> monitored_processes;
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
        for (auto& [pid, _] : monitored_processes) {
            ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        }
    }
    
    bool startProcess(const std::string& executable, const std::vector<std::string>& args, pid_t& out_pid) {
        pid_t pid = fork();
        if (pid == 0) {
            // Child process
            ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
            raise(SIGSTOP);
            
            // Convert args to char* array
            std::vector<char*> argv_ptrs;
            argv_ptrs.push_back(const_cast<char*>(executable.c_str()));
            for (const auto& arg : args) {
                argv_ptrs.push_back(const_cast<char*>(arg.c_str()));
            }
            argv_ptrs.push_back(nullptr);
            
            execvp(executable.c_str(), argv_ptrs.data());
            std::cerr << "Failed to execute " << executable << ": " << strerror(errno) << std::endl;
            _exit(1);
        } else if (pid > 0) {
            // Parent process
            int status;
            waitpid(pid, &status, 0);
            
            if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP) {
                std::cerr << "Child process didn't stop as expected" << std::endl;
                return false;
            }
            
            out_pid = pid;
            monitored_processes[pid] = true;
            
            // Cache process info
            ProcessInfo info;
            info.pid = pid;
            info.executable_path = executable;
            info.command_line = executable;
            for (const auto& arg : args) {
                info.command_line += " " + arg;
            }
            process_info_cache[pid] = info;
            
            // Set ptrace options
            ptrace(PTRACE_SETOPTIONS, pid, 0, 
                   PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK | 
                   PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC);
            
            ptrace(PTRACE_SYSCALL, pid, nullptr, nullptr);
            
            if (!monitoring_active) {
                startMonitoring();
            }
            
            return true;
        } else {
            std::cerr << "Failed to fork: " << strerror(errno) << std::endl;
            return false;
        }
    }
    
    bool attachToProcess(pid_t pid) {
        if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) == -1) {
            std::cerr << "ptrace attach failed: " << strerror(errno) << std::endl;
            return false;
        }
        
        int status;
        waitpid(pid, &status, 0);
        
        monitored_processes[pid] = true;
        
        ptrace(PTRACE_SETOPTIONS, pid, 0, 
               PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK | 
               PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC);
        
        ptrace(PTRACE_SYSCALL, pid, nullptr, nullptr);
        
        if (!monitoring_active) {
            startMonitoring();
        }
        
        return true;
    }
    
    bool detachFromProcess(pid_t pid) {
        auto it = monitored_processes.find(pid);
        if (it == monitored_processes.end()) {
            return false;
        }
        
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        monitored_processes.erase(it);
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
        std::map<pid_t, bool> in_syscall;
        
        while (monitoring_active && !monitored_processes.empty()) {
            int status;
            pid_t waited_pid = waitpid(-1, &status, WNOHANG);
            
            if (waited_pid == -1) {
                if (errno == ECHILD) {
                    break;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                continue;
            }
            
            if (waited_pid == 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                continue;
            }
            
            if (monitored_processes.find(waited_pid) == monitored_processes.end()) {
                continue;
            }
            
            handleProcessEvent(waited_pid, status, in_syscall);
        }
    }
    
    void handleProcessEvent(pid_t pid, int status, std::map<pid_t, bool>& in_syscall) {
        std::lock_guard<std::mutex> lock(event_mutex);
        
        if (WIFEXITED(status)) {
            IOEvent event;
            event.type = IOEvent::PROCESS_EXIT;
            event.pid = pid;
            event.target = "exit_code_" + std::to_string(WEXITSTATUS(status));
            event.timestamp = getCurrentTimestamp();
            event_queue.push_back(event);
            
            monitored_processes.erase(pid);
            in_syscall.erase(pid);
            process_info_cache.erase(pid);
            return;
        }
        
        if (WIFSIGNALED(status)) {
            IOEvent event;
            event.type = IOEvent::PROCESS_EXIT;
            event.pid = pid;
            event.target = "signal_" + std::to_string(WTERMSIG(status));
            event.timestamp = getCurrentTimestamp();
            event_queue.push_back(event);
            
            monitored_processes.erase(pid);
            in_syscall.erase(pid);
            process_info_cache.erase(pid);
            return;
        }
        
        if (WIFSTOPPED(status)) {
            int sig = WSTOPSIG(status);
            
            if (sig == (SIGTRAP | 0x80)) {
                // Syscall entry/exit
                struct user_regs_struct regs;
                ptrace(PTRACE_GETREGS, pid, nullptr, &regs);
                
                if (!in_syscall[pid]) {
                    // Entering syscall
                    handleSyscallEntry(pid, regs);
                    in_syscall[pid] = true;
                } else {
                    // Exiting syscall
                    handleSyscallExit(pid, regs);
                    in_syscall[pid] = false;
                }
            } else if (sig == SIGTRAP) {
                // Handle fork/clone/exec events
                if (status >> 16 == PTRACE_EVENT_FORK || status >> 16 == PTRACE_EVENT_CLONE) {
                    unsigned long new_pid;
                    ptrace(PTRACE_GETEVENTMSG, pid, nullptr, &new_pid);
                    
                    IOEvent event;
                    event.type = IOEvent::PROCESS_CREATE;
                    event.pid = pid;
                    event.target = "child_pid_" + std::to_string(new_pid);
                    event.timestamp = getCurrentTimestamp();
                    event_queue.push_back(event);
                    
                    monitored_processes[(pid_t)new_pid] = true;
                    in_syscall[(pid_t)new_pid] = false;
                    
                    ptrace(PTRACE_SETOPTIONS, (pid_t)new_pid, 0, 
                           PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK | 
                           PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC);
                }
            }
        }
        
        ptrace(PTRACE_SYSCALL, pid, nullptr, nullptr);
    }
    
    void handleSyscallEntry(pid_t pid, const struct user_regs_struct& regs) {
        long syscall_num = regs.orig_rax;
        
        // Focus on file and network I/O syscalls
        if (syscall_num == SYS_openat || syscall_num == SYS_open) {
            IOEvent event;
            event.type = IOEvent::READ_FILE;
            event.pid = pid;
            event.target = readProcessString(pid, regs.rsi, 256);
            event.timestamp = getCurrentTimestamp();
            event_queue.push_back(event);
        }
    }
    
    void handleSyscallExit(pid_t pid, const struct user_regs_struct& regs) {
        long syscall_num = regs.orig_rax;
        long retval = regs.rax;
        
        if (syscall_num == SYS_write && retval > 0) {
            IOEvent event;
            event.type = IOEvent::WRITE_FILE;
            event.pid = pid;
            event.target = "fd_" + std::to_string(regs.rdi);
            event.size = retval;
            event.timestamp = getCurrentTimestamp();
            
            // Read data if reasonable size
            if (retval <= 1024) {
                event.data = readProcessData(pid, regs.rsi, retval);
            }
            
            event_queue.push_back(event);
        } else if (syscall_num == SYS_read && retval > 0) {
            IOEvent event;
            event.type = IOEvent::READ_FILE;
            event.pid = pid;
            event.target = "fd_" + std::to_string(regs.rdi);
            event.size = retval;
            event.timestamp = getCurrentTimestamp();
            
            // Read data if reasonable size
            if (retval <= 1024) {
                event.data = readProcessData(pid, regs.rsi, retval);
            }
            
            event_queue.push_back(event);
        }
    }
    
    uint64_t getCurrentTimestamp() {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }
    
    std::vector<uint8_t> readProcessData(pid_t pid, uint64_t address, size_t size) {
        std::vector<uint8_t> data;
        if (size == 0 || size > 4096) return data;
        
        data.resize(size);
        for (size_t i = 0; i < size; i += sizeof(long)) {
            errno = 0;
            long word = ptrace(PTRACE_PEEKDATA, pid, address + i, nullptr);
            if (errno != 0) break;
            
            size_t copy_size = std::min(sizeof(long), size - i);
            memcpy(data.data() + i, &word, copy_size);
        }
        
        return data;
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
        
        // Read from /proc/pid/cmdline
        std::string proc_path = "/proc/" + std::to_string(pid) + "/cmdline";
        std::ifstream file(proc_path);
        if (file.is_open()) {
            std::string cmdline;
            std::getline(file, cmdline);
            
            info.pid = pid;
            info.command_line = cmdline;
            
            // Replace null bytes with spaces
            for (char& c : info.command_line) {
                if (c == '\0') c = ' ';
            }
            
            // Extract executable path
            size_t space_pos = info.command_line.find(' ');
            if (space_pos != std::string::npos) {
                info.executable_path = info.command_line.substr(0, space_pos);
            } else {
                info.executable_path = info.command_line;
            }
            
            process_info_cache[pid] = info;
            return true;
        }
        
        return false;
    }
    
    std::vector<pid_t> getChildProcesses(pid_t parent_pid) {
        std::vector<pid_t> children;
        
        DIR* proc_dir = opendir("/proc");
        if (!proc_dir) return children;
        
        struct dirent* entry;
        while ((entry = readdir(proc_dir)) != nullptr) {
            if (!isdigit(entry->d_name[0])) continue;
            
            pid_t pid = atoi(entry->d_name);
            std::string stat_path = "/proc/" + std::string(entry->d_name) + "/stat";
            
            std::ifstream stat_file(stat_path);
            if (stat_file.is_open()) {
                std::string line;
                std::getline(stat_file, line);
                
                // Parse stat file to get parent PID (4th field)
                std::istringstream ss(line);
                std::string token;
                for (int i = 0; i < 4 && std::getline(ss, token, ' '); i++) {
                    if (i == 3 && atoi(token.c_str()) == parent_pid) {
                        children.push_back(pid);
                        break;
                    }
                }
            }
        }
        
        closedir(proc_dir);
        return children;
    }
    
    bool readProcessMemory(pid_t pid, uint64_t address, void* buffer, size_t size) {
        for (size_t i = 0; i < size; i += sizeof(long)) {
            errno = 0;
            long data = ptrace(PTRACE_PEEKDATA, pid, address + i, nullptr);
            if (errno != 0) return false;
            
            size_t copy_size = std::min(sizeof(long), size - i);
            memcpy(static_cast<char*>(buffer) + i, &data, copy_size);
        }
        return true;
    }
    
    std::string readProcessString(pid_t pid, uint64_t address, size_t max_length) {
        std::string result;
        if (address == 0) return result;
        
        for (size_t i = 0; i < max_length; i += sizeof(long)) {
            errno = 0;
            long data = ptrace(PTRACE_PEEKDATA, pid, address + i, nullptr);
            if (errno != 0) break;
            
            char* bytes = reinterpret_cast<char*>(&data);
            for (size_t j = 0; j < sizeof(long) && (i + j) < max_length; j++) {
                if (bytes[j] == '\0') return result;
                if (isprint(bytes[j])) {
                    result += bytes[j];
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
    char path[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", path, sizeof(path) - 1);
    if (len != -1) {
        path[len] = '\0';
        return std::string(path);
    }
    return "";
}

std::string ProcessMonitor::getTempDirectory() {
    const char* temp_env = getenv("TMPDIR");
    if (temp_env) return std::string(temp_env);
    
    temp_env = getenv("TMP");
    if (temp_env) return std::string(temp_env);
    
    return "/tmp";
}

bool ProcessMonitor::fileExists(const std::string& path) {
    struct stat buffer;
    return (stat(path.c_str(), &buffer) == 0);
}

std::vector<std::string> ProcessMonitor::findSystemFonts() {
    std::vector<std::string> fonts;
    
    // Linux system font directories
    std::vector<std::string> font_dirs = {
        "/usr/share/fonts/TTF/",
        "/usr/share/fonts/truetype/dejavu/",
        "/usr/share/fonts/truetype/liberation/",
        "/usr/share/fonts/truetype/",
        "/System/Library/Fonts/",
        "/Library/Fonts/"
    };
    
    // Common font filenames
    std::vector<std::string> font_files = {
        "DejaVuSans.ttf",
        "LiberationSans-Regular.ttf",
        "arial.ttf",
        "Arial.ttf"
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

#endif // !_WIN32