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
        default: return "syscall_" + std::to_string(syscall_num);
    }
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
                int flags = regs.rdx;
                details = "dirfd=" + std::to_string(dirfd) + " path=" + path + " flags=0x" + 
                         std::to_string(flags);
                logger.logFileAccess(pid, "OPEN", path);
                break;
            }
            case SYS_open: {
                std::string path = readStringFromProcess(pid, regs.rdi);
                int flags = regs.rsi;
                details = "path=" + path + " flags=0x" + std::to_string(flags);
                logger.logFileAccess(pid, "OPEN", path);
                break;
            }
            case SYS_close: {
                int fd = regs.rdi;
                details = "fd=" + std::to_string(fd);
                break;
            }
            case SYS_socket: {
                int domain = regs.rdi;
                int type = regs.rsi;
                int protocol = regs.rdx;
                details = "domain=" + std::to_string(domain) + " type=" + std::to_string(type) + 
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
        }
        
        logger.logSyscall(pid, syscall_name + "_enter", details);
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
        
        logger.logSyscall(pid, syscall_name + "_exit", details);
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
    } else {
        std::cerr << "Failed to fork: " << strerror(errno) << std::endl;
        return 1;
    }
    
    return 0;
}