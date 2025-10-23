#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/types.h>
#include <signal.h>
#include <errno.h>
#include <cstring>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <set>
#include <map>
#include <sys/mman.h>
#include <asm/prctl.h>
#include <sys/prctl.h>
#include <linux/futex.h>
#include <sys/resource.h>

#ifdef ENABLE_VISUALIZATION
#include "visualizer.h"
#endif

class BehaviorLogger {
private:
    std::ofstream logFile;
    
    std::string getCurrentTime() {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()) % 1000;
        
        std::stringstream ss;
        ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
        ss << '.' << std::setfill('0') << std::setw(3) << ms.count();
        return ss.str();
    }
    
public:
    BehaviorLogger() : logFile("behavior.log") {
        if (!logFile.is_open()) {
            std::cerr << "Failed to open behavior.log" << std::endl;
            exit(1);
        }
        logFile << "=== QBScanner Behavior Log Started at " << getCurrentTime() << " ===" << std::endl;
    }
    
    ~BehaviorLogger() {
        if (logFile.is_open()) {
            logFile << "=== QBScanner Behavior Log Ended at " << getCurrentTime() << " ===" << std::endl;
            logFile.close();
        }
    }
    
    void generateVisualization() {
        #ifdef ENABLE_VISUALIZATION
        std::cout << "Generating behavior visualization..." << std::endl;
        BehaviorVisualizer visualizer;
        visualizer.generateVisualization("behavior.log", "behavior.png");
        #endif
    }
    
    void logSyscall(pid_t pid, const std::string& syscall, const std::string& details = "") {
        logFile << "[" << getCurrentTime() << "] PID:" << pid << " SYSCALL:" << syscall;
        if (!details.empty()) {
            logFile << " " << details;
        }
        logFile << std::endl;
        logFile.flush();
    }
    
    void logIO(pid_t pid, const std::string& type, const std::string& details) {
        logFile << "[" << getCurrentTime() << "] PID:" << pid << " " << type << ": " << details << std::endl;
        logFile.flush();
    }
    
    void logFileAccess(pid_t pid, const std::string& operation, const std::string& path, int fd = -1) {
        std::string details = operation + " path=" + path;
        if (fd >= 0) {
            details += " fd=" + std::to_string(fd);
        }
        logIO(pid, "FILE_ACCESS", details);
    }
    
    void logNetworkActivity(pid_t pid, const std::string& operation, const std::string& details) {
        logIO(pid, "NETWORK", operation + " " + details);
    }
    
    void logProcessActivity(pid_t pid, const std::string& operation, const std::string& command = "") {
        std::string details = operation;
        if (!command.empty()) {
            details += " cmd=" + command;
        }
        logIO(pid, "PROCESS", details);
    }
    
    void logDataIO(pid_t pid, const std::string& operation, int fd, const std::vector<unsigned char>& data, long retval);
};

std::string getSyscallName(long syscall_num) {
    switch(syscall_num) {
        case SYS_read: return "read";
        case SYS_write: return "write";
        case SYS_open: return "open";
        case SYS_openat: return "openat";
        case SYS_close: return "close";
        case SYS_socket: return "socket";
        case SYS_connect: return "connect";
        case SYS_bind: return "bind";
        case SYS_listen: return "listen";
        case SYS_accept: return "accept";
        case SYS_accept4: return "accept4";
        case SYS_sendto: return "sendto";
        case SYS_recvfrom: return "recvfrom";
        case SYS_sendmsg: return "sendmsg";
        case SYS_recvmsg: return "recvmsg";
        case SYS_execve: return "execve";
        case SYS_fork: return "fork";
        case SYS_clone: return "clone";
        case SYS_creat: return "creat";
        case SYS_unlink: return "unlink";
        case SYS_rename: return "rename";
        case SYS_mkdir: return "mkdir";
        case SYS_rmdir: return "rmdir";
        case SYS_stat: return "stat";
        case SYS_lstat: return "lstat";
        case SYS_fstat: return "fstat";
        case SYS_access: return "access";
        case SYS_chmod: return "chmod";
        case SYS_chown: return "chown";
        case SYS_dup: return "dup";
        case SYS_dup2: return "dup2";
        case SYS_pipe: return "pipe";
        case SYS_pipe2: return "pipe2";
        // Add more common Linux syscalls with their numbers
        case 8: return "lseek";
        case 9: return "mmap";
        case 10: return "mprotect";
        case 11: return "munmap";
        case 12: return "brk";
        case 17: return "pread64";
        case 158: return "arch_prctl";
        case 218: return "set_tid_address";
        case 231: return "exit_group";
        case 273: return "set_robust_list";
        case 302: return "prlimit64";
        case 318: return "getrandom";
        case 334: return "rseq";
        default: return "syscall_" + std::to_string(syscall_num);
    }
}

// Helper functions to decode syscall arguments into meaningful names
std::string decodeArchPrctlCode(unsigned long code) {
    switch(code) {
        case ARCH_SET_GS: return "ARCH_SET_GS";
        case ARCH_SET_FS: return "ARCH_SET_FS";
        case ARCH_GET_FS: return "ARCH_GET_FS";
        case ARCH_GET_GS: return "ARCH_GET_GS";
        case ARCH_SET_CPUID: return "ARCH_SET_CPUID";
        case ARCH_GET_CPUID: return "ARCH_GET_CPUID";
        default: return std::to_string(code);
    }
}

std::string decodeMmapProt(unsigned long prot) {
    std::vector<std::string> flags;
    if (prot & PROT_READ) flags.push_back("PROT_READ");
    if (prot & PROT_WRITE) flags.push_back("PROT_WRITE");
    if (prot & PROT_EXEC) flags.push_back("PROT_EXEC");
    if (prot == PROT_NONE) flags.push_back("PROT_NONE");
    
    if (flags.empty()) return std::to_string(prot);
    
    std::string result;
    for (size_t i = 0; i < flags.size(); i++) {
        if (i > 0) result += "|";
        result += flags[i];
    }
    return result;
}

std::string decodeMmapFlags(unsigned long flags) {
    std::vector<std::string> flag_names;
    if (flags & MAP_PRIVATE) flag_names.push_back("MAP_PRIVATE");
    if (flags & MAP_SHARED) flag_names.push_back("MAP_SHARED");
    if (flags & MAP_ANONYMOUS) flag_names.push_back("MAP_ANONYMOUS");
    if (flags & MAP_FIXED) flag_names.push_back("MAP_FIXED");
    if (flags & MAP_GROWSDOWN) flag_names.push_back("MAP_GROWSDOWN");
    if (flags & MAP_LOCKED) flag_names.push_back("MAP_LOCKED");
    if (flags & MAP_NORESERVE) flag_names.push_back("MAP_NORESERVE");
    if (flags & MAP_POPULATE) flag_names.push_back("MAP_POPULATE");
    if (flags & MAP_NONBLOCK) flag_names.push_back("MAP_NONBLOCK");
    if (flags & MAP_STACK) flag_names.push_back("MAP_STACK");
    
    if (flag_names.empty()) return std::to_string(flags);
    
    std::string result;
    for (size_t i = 0; i < flag_names.size(); i++) {
        if (i > 0) result += "|";
        result += flag_names[i];
    }
    return result;
}

std::string decodeOpenFlags(unsigned long flags) {
    std::vector<std::string> flag_names;
    
    // File access modes
    int access_mode = flags & O_ACCMODE;
    switch(access_mode) {
        case O_RDONLY: flag_names.push_back("O_RDONLY"); break;
        case O_WRONLY: flag_names.push_back("O_WRONLY"); break;
        case O_RDWR: flag_names.push_back("O_RDWR"); break;
    }
    
    // Additional flags
    if (flags & O_CREAT) flag_names.push_back("O_CREAT");
    if (flags & O_EXCL) flag_names.push_back("O_EXCL");
    if (flags & O_NOCTTY) flag_names.push_back("O_NOCTTY");
    if (flags & O_TRUNC) flag_names.push_back("O_TRUNC");
    if (flags & O_APPEND) flag_names.push_back("O_APPEND");
    if (flags & O_NONBLOCK) flag_names.push_back("O_NONBLOCK");
    if (flags & O_SYNC) flag_names.push_back("O_SYNC");
    if (flags & O_CLOEXEC) flag_names.push_back("O_CLOEXEC");
    
    if (flag_names.empty()) return std::to_string(flags);
    
    std::string result;
    for (size_t i = 0; i < flag_names.size(); i++) {
        if (i > 0) result += "|";
        result += flag_names[i];
    }
    return result;
}

std::string decodeSocketDomain(unsigned long domain) {
    switch(domain) {
        case AF_UNIX: return "AF_UNIX";
        case AF_INET: return "AF_INET";
        case AF_INET6: return "AF_INET6";
        case AF_NETLINK: return "AF_NETLINK";
        case AF_PACKET: return "AF_PACKET";
        default: return std::to_string(domain);
    }
}

std::string decodeSocketType(unsigned long type) {
    // Extract base type (remove flags)
    unsigned long base_type = type & 0xFF;
    std::vector<std::string> parts;
    
    switch(base_type) {
        case SOCK_STREAM: parts.push_back("SOCK_STREAM"); break;
        case SOCK_DGRAM: parts.push_back("SOCK_DGRAM"); break;
        case SOCK_RAW: parts.push_back("SOCK_RAW"); break;
        case SOCK_SEQPACKET: parts.push_back("SOCK_SEQPACKET"); break;
        default: parts.push_back(std::to_string(base_type)); break;
    }
    
    // Add flags
    if (type & SOCK_NONBLOCK) parts.push_back("SOCK_NONBLOCK");
    if (type & SOCK_CLOEXEC) parts.push_back("SOCK_CLOEXEC");
    
    std::string result;
    for (size_t i = 0; i < parts.size(); i++) {
        if (i > 0) result += "|";
        result += parts[i];
    }
    return result;
}

std::string readStringFromProcess(pid_t pid, unsigned long addr, size_t max_len = 256) {
    std::string result;
    if (addr == 0) return "[null]";
    
    for (size_t i = 0; i < max_len; i += sizeof(long)) {
        errno = 0;
        long data = ptrace(PTRACE_PEEKDATA, pid, addr + i, nullptr);
        if (errno != 0) break;
        
        char* bytes = (char*)&data;
        for (size_t j = 0; j < sizeof(long) && (i + j) < max_len; j++) {
            if (bytes[j] == '\0') {
                return result;
            }
            if (isprint(bytes[j]) || bytes[j] == '/' || bytes[j] == '.') {
                result += bytes[j];
            } else {
                result += "\\x" + std::to_string((unsigned char)bytes[j]);
            }
        }
    }
    return result;
}

std::vector<unsigned char> readDataFromProcess(pid_t pid, unsigned long addr, size_t len) {
    std::vector<unsigned char> data;
    if (addr == 0 || len == 0) return data;
    
    for (size_t i = 0; i < len; i += sizeof(long)) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, pid, addr + i, nullptr);
        if (errno != 0) break;
        
        unsigned char* bytes = (unsigned char*)&word;
        for (size_t j = 0; j < sizeof(long) && (i + j) < len; j++) {
            data.push_back(bytes[j]);
        }
    }
    return data;
}

std::string bytesToHex(const std::vector<unsigned char>& data, size_t max_display = 256) {
    std::stringstream ss;
    size_t display_len = std::min(data.size(), max_display);
    
    for (size_t i = 0; i < display_len; i++) {
        ss << std::hex << std::setfill('0') << std::setw(2) << (unsigned)data[i];
        if (i < display_len - 1) ss << " ";
    }
    
    if (data.size() > max_display) {
        ss << "... (" << data.size() << " bytes total)";
    }
    
    return ss.str();
}

bool isValidUtf8(const std::vector<unsigned char>& data) {
    for (size_t i = 0; i < data.size(); ) {
        unsigned char c = data[i];
        
        if (c <= 0x7F) {
            i++;
        } else if ((c & 0xE0) == 0xC0) {
            if (i + 1 >= data.size() || (data[i + 1] & 0xC0) != 0x80) return false;
            i += 2;
        } else if ((c & 0xF0) == 0xE0) {
            if (i + 2 >= data.size() || (data[i + 1] & 0xC0) != 0x80 || (data[i + 2] & 0xC0) != 0x80) return false;
            i += 3;
        } else if ((c & 0xF8) == 0xF0) {
            if (i + 3 >= data.size() || (data[i + 1] & 0xC0) != 0x80 || (data[i + 2] & 0xC0) != 0x80 || (data[i + 3] & 0xC0) != 0x80) return false;
            i += 4;
        } else {
            return false;
        }
    }
    return true;
}

std::string bytesToString(const std::vector<unsigned char>& data, size_t max_display = 256) {
    std::string result;
    size_t display_len = std::min(data.size(), max_display);
    
    for (size_t i = 0; i < display_len; i++) {
        unsigned char c = data[i];
        if (c >= 32 && c <= 126) {
            result += (char)c;
        } else if (c == '\n') {
            result += "\\n";
        } else if (c == '\r') {
            result += "\\r";
        } else if (c == '\t') {
            result += "\\t";
        } else if (c == '\0') {
            result += "\\0";
        } else {
            result += "\\x" + std::to_string(c);
        }
    }
    
    if (data.size() > max_display) {
        result += "... (" + std::to_string(data.size()) + " bytes total)";
    }
    
    return result;
}

void BehaviorLogger::logDataIO(pid_t pid, const std::string& operation, int fd, const std::vector<unsigned char>& data, long retval) {
    std::string hex_data = bytesToHex(data);
    std::string str_data = bytesToString(data);
    bool is_utf8 = isValidUtf8(data);
    
    logFile << "[" << getCurrentTime() << "] PID:" << pid << " " << operation 
            << " fd=" << fd << " size=" << retval << " hex=[" << hex_data << "]";
    
    if (is_utf8 && !data.empty()) {
        logFile << " utf8=\"" << str_data << "\"";
    } else if (!data.empty()) {
        logFile << " ascii=\"" << str_data << "\"";
    }
    
    logFile << std::endl;
    logFile.flush();
}

struct SyscallData {
    unsigned long buffer_addr;
    size_t buffer_size;
    int fd;
};

std::map<pid_t, SyscallData> pending_io_calls;

void logDetailedSyscall(pid_t pid, long syscall_num, struct user_regs_struct& regs, 
                       BehaviorLogger& logger, bool entering) {
    std::string syscall_name = getSyscallName(syscall_num);
    
    if (entering) {
        std::string details;
        
        switch (syscall_num) {
            case SYS_read: {
                int fd = regs.rdi;
                unsigned long buffer = regs.rsi;
                size_t count = regs.rdx;
                details = "fd=" + std::to_string(fd) + " count=" + std::to_string(count);
                
                pending_io_calls[pid] = {buffer, count, fd};
                break;
            }
            case SYS_write: {
                int fd = regs.rdi;
                unsigned long buffer = regs.rsi;
                size_t count = regs.rdx;
                details = "fd=" + std::to_string(fd) + " count=" + std::to_string(count);
                
                std::vector<unsigned char> data = readDataFromProcess(pid, buffer, count);
                logger.logDataIO(pid, "WRITE_DATA", fd, data, count);
                break;
            }
            case SYS_openat: {
                int dirfd = regs.rdi;
                std::string path = readStringFromProcess(pid, regs.rsi);
                unsigned long flags = regs.rdx;
                details = "dirfd=" + std::to_string(dirfd) + " path=" + path + 
                         " flags=" + decodeOpenFlags(flags);
                logger.logFileAccess(pid, "OPEN", path);
                break;
            }
            case SYS_open: {
                std::string path = readStringFromProcess(pid, regs.rdi);
                unsigned long flags = regs.rsi;
                details = "path=" + path + " flags=" + decodeOpenFlags(flags);
                logger.logFileAccess(pid, "OPEN", path);
                break;
            }
            case SYS_close: {
                int fd = regs.rdi;
                details = "fd=" + std::to_string(fd);
                break;
            }
            case SYS_socket: {
                unsigned long domain = regs.rdi;
                unsigned long type = regs.rsi;
                unsigned long protocol = regs.rdx;
                details = "domain=" + decodeSocketDomain(domain) + " type=" + decodeSocketType(type) + 
                         " protocol=" + std::to_string(protocol);
                logger.logNetworkActivity(pid, "SOCKET_CREATE", details);
                break;
            }
            case SYS_connect: {
                int sockfd = regs.rdi;
                details = "sockfd=" + std::to_string(sockfd);
                logger.logNetworkActivity(pid, "CONNECT", details);
                break;
            }
            case SYS_bind: {
                int sockfd = regs.rdi;
                details = "sockfd=" + std::to_string(sockfd);
                logger.logNetworkActivity(pid, "BIND", details);
                break;
            }
            case SYS_sendto:
            case SYS_recvfrom: {
                int sockfd = regs.rdi;
                size_t len = regs.rdx;
                details = "sockfd=" + std::to_string(sockfd) + " len=" + std::to_string(len);
                logger.logNetworkActivity(pid, syscall_name == "sendto" ? "SEND" : "RECV", details);
                break;
            }
            case SYS_execve: {
                std::string path = readStringFromProcess(pid, regs.rdi);
                details = "path=" + path;
                logger.logProcessActivity(pid, "EXEC", path);
                break;
            }
            case SYS_fork:
            case SYS_clone: {
                logger.logProcessActivity(pid, "FORK");
                break;
            }
            // Additional syscalls with detailed argument decoding
            case 158: { // arch_prctl
                unsigned long code = regs.rdi;
                unsigned long addr = regs.rsi;
                details = "code=" + decodeArchPrctlCode(code) + " addr=0x" + 
                         std::to_string(addr);
                break;
            }
            case 9: { // mmap
                unsigned long addr = regs.rdi;
                unsigned long length = regs.rsi;
                unsigned long prot = regs.rdx;
                unsigned long flags = regs.r10;
                int fd = regs.r8;
                unsigned long offset = regs.r9;
                details = "addr=0x" + std::to_string(addr) + " length=" + std::to_string(length) +
                         " prot=" + decodeMmapProt(prot) + " flags=" + decodeMmapFlags(flags) +
                         " fd=" + std::to_string(fd) + " offset=" + std::to_string(offset);
                break;
            }
            case 10: { // mprotect
                unsigned long addr = regs.rdi;
                unsigned long len = regs.rsi;
                unsigned long prot = regs.rdx;
                details = "addr=0x" + std::to_string(addr) + " len=" + std::to_string(len) +
                         " prot=" + decodeMmapProt(prot);
                break;
            }
            case 11: { // munmap
                unsigned long addr = regs.rdi;
                unsigned long length = regs.rsi;
                details = "addr=0x" + std::to_string(addr) + " length=" + std::to_string(length);
                break;
            }
            case 12: { // brk
                unsigned long brk = regs.rdi;
                details = "brk=0x" + std::to_string(brk);
                break;
            }
            case 17: { // pread64
                int fd = regs.rdi;
                unsigned long count = regs.rdx;
                unsigned long offset = regs.r10;
                details = "fd=" + std::to_string(fd) + " count=" + std::to_string(count) +
                         " offset=" + std::to_string(offset);
                break;
            }
            case 218: { // set_tid_address
                unsigned long tidptr = regs.rdi;
                details = "tidptr=0x" + std::to_string(tidptr);
                break;
            }
            case 273: { // set_robust_list
                unsigned long head = regs.rdi;
                unsigned long len = regs.rsi;
                details = "head=0x" + std::to_string(head) + " len=" + std::to_string(len);
                break;
            }
            case 302: { // prlimit64
                int pid_arg = regs.rdi;
                unsigned long resource = regs.rsi;
                unsigned long new_limit = regs.rdx;
                unsigned long old_limit = regs.r10;
                details = "pid=" + std::to_string(pid_arg) + " resource=" + std::to_string(resource) +
                         " new_limit=0x" + std::to_string(new_limit) + " old_limit=0x" + std::to_string(old_limit);
                break;
            }
            case 318: { // getrandom
                unsigned long buf = regs.rdi;
                unsigned long buflen = regs.rsi;
                unsigned long flags = regs.rdx;
                details = "buf=0x" + std::to_string(buf) + " buflen=" + std::to_string(buflen) +
                         " flags=0x" + std::to_string(flags);
                break;
            }
            case 334: { // rseq
                unsigned long rseq_abi = regs.rdi;
                unsigned long rseq_len = regs.rsi;
                unsigned long flags = regs.rdx;
                unsigned long sig = regs.r10;
                details = "rseq=0x" + std::to_string(rseq_abi) + " rseq_len=" + std::to_string(rseq_len) +
                         " flags=0x" + std::to_string(flags) + " sig=0x" + std::to_string(sig);
                break;
            }
        }
        
        std::string enter_label = syscall_name + "_enter";
        logger.logSyscall(pid, enter_label, details);
    } else {
        long retval = regs.rax;
        std::string details = "retval=" + std::to_string(retval);
        
        if (retval < 0) {
            details += " errno=" + std::to_string(-retval);
        }
        
        if (syscall_num == SYS_read && retval > 0 && pending_io_calls.find(pid) != pending_io_calls.end()) {
            SyscallData& call_data = pending_io_calls[pid];
            std::vector<unsigned char> data = readDataFromProcess(pid, call_data.buffer_addr, retval);
            logger.logDataIO(pid, "READ_DATA", call_data.fd, data, retval);
            pending_io_calls.erase(pid);
        }
        
        std::string exit_label = syscall_name + "_exit";
        logger.logSyscall(pid, exit_label, details);
    }
}

void traceProcess(pid_t child_pid, BehaviorLogger& logger) {
    std::set<pid_t> tracked_processes;
    std::map<pid_t, bool> in_syscall;
    
    tracked_processes.insert(child_pid);
    in_syscall[child_pid] = false;
    
    while (!tracked_processes.empty()) {
        int status;
        pid_t waited_pid = waitpid(-1, &status, 0);
        
        if (waited_pid == -1) {
            if (errno == ECHILD) {
                break;
            }
            continue;
        }
        
        if (tracked_processes.find(waited_pid) == tracked_processes.end()) {
            continue;
        }
        
        if (WIFEXITED(status)) {
            logger.logProcessActivity(waited_pid, "EXIT", "code=" + std::to_string(WEXITSTATUS(status)));
            tracked_processes.erase(waited_pid);
            in_syscall.erase(waited_pid);
            pending_io_calls.erase(waited_pid);
            continue;
        }
        
        if (WIFSIGNALED(status)) {
            logger.logProcessActivity(waited_pid, "KILLED", "signal=" + std::to_string(WTERMSIG(status)));
            tracked_processes.erase(waited_pid);
            in_syscall.erase(waited_pid);
            pending_io_calls.erase(waited_pid);
            continue;
        }
        
        if (WIFSTOPPED(status)) {
            int sig = WSTOPSIG(status);
            
            if (sig == (SIGTRAP | 0x80)) {
                struct user_regs_struct regs;
                ptrace(PTRACE_GETREGS, waited_pid, nullptr, &regs);
                
                if (!in_syscall[waited_pid]) {
                    long syscall_num = regs.orig_rax;
                    logDetailedSyscall(waited_pid, syscall_num, regs, logger, true);
                    in_syscall[waited_pid] = true;
                } else {
                    long syscall_num = regs.orig_rax;
                    logDetailedSyscall(waited_pid, syscall_num, regs, logger, false);
                    in_syscall[waited_pid] = false;
                }
            } else if (sig == SIGTRAP) {
                if (status >> 16 == PTRACE_EVENT_FORK || status >> 16 == PTRACE_EVENT_CLONE) {
                    unsigned long new_pid;
                    ptrace(PTRACE_GETEVENTMSG, waited_pid, nullptr, &new_pid);
                    logger.logProcessActivity(waited_pid, "CHILD_CREATED", "child_pid=" + std::to_string(new_pid));
                    
                    tracked_processes.insert((pid_t)new_pid);
                    in_syscall[(pid_t)new_pid] = false;
                    
                    ptrace(PTRACE_SETOPTIONS, (pid_t)new_pid, 0, 
                           PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK | PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC);
                } else if (status >> 16 == PTRACE_EVENT_EXEC) {
                    logger.logProcessActivity(waited_pid, "EXEC_COMPLETE", "");
                }
            } else if (sig == SIGSTOP) {
                logger.logProcessActivity(waited_pid, "STOPPED", "signal=SIGSTOP");
            } else {
                logger.logProcessActivity(waited_pid, "SIGNAL", "signal=" + std::to_string(sig));
            }
        }
        
        ptrace(PTRACE_SYSCALL, waited_pid, nullptr, nullptr);
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <command> [args...]" << std::endl;
        std::cerr << "QBScanner - QEMU-based behavior monitoring tool" << std::endl;
        return 1;
    }
    
    BehaviorLogger logger;
    
    pid_t pid = fork();
    if (pid == 0) {
        ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
        raise(SIGSTOP);
        execvp(argv[1], &argv[1]);
        std::cerr << "Failed to execute " << argv[1] << ": " << strerror(errno) << std::endl;
        return 1;
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
        
        if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP) {
            std::cerr << "Child process didn't stop as expected" << std::endl;
            return 1;
        }
        
        std::string command_line = argv[1];
        for (int i = 2; i < argc; i++) {
            command_line += " " + std::string(argv[i]);
        }
        
        logger.logProcessActivity(pid, "START", command_line);
        
        ptrace(PTRACE_SETOPTIONS, pid, 0, 
               PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK | PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC);
        
        ptrace(PTRACE_SYSCALL, pid, nullptr, nullptr);
        
        traceProcess(pid, logger);
        logger.logProcessActivity(pid, "COMPLETE", "");
        
        // Generate visualization after tracing is complete
        logger.generateVisualization();
    } else {
        std::cerr << "Failed to fork: " << strerror(errno) << std::endl;
        return 1;
    }
    
    return 0;
}