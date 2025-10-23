#pragma once

#include <string>
#include <vector>
#include <map>
#include <set>
#include <memory>
#include <fstream>
#include <sstream>
#include <cmath>
#include <algorithm>
#include "bitmap_renderer.h"

struct IOEvent {
    std::string timestamp;
    int pid;
    std::string type;  // PROCESS, FILE_ACCESS, NETWORK, READ_DATA, WRITE_DATA
    std::string operation;
    std::string details;
    size_t data_size = 0;
    int fd = -1;
    std::string path;
    std::string data_preview;
};

struct ProcessNode {
    int pid;
    std::string command;
    double x, y;
    std::vector<int> children;
    std::vector<std::string> files_accessed;
    std::vector<std::string> network_connections;
    size_t total_read_bytes = 0;
    size_t total_write_bytes = 0;
};

struct FileNode {
    std::string path;
    double x, y;
    std::set<int> accessing_pids;
    size_t total_read_bytes = 0;
    size_t total_write_bytes = 0;
    bool is_special_fd = false; // stdout, stderr, stdin
};

struct NetworkNode {
    std::string connection_info;
    double x, y;
    std::set<int> connecting_pids;
    size_t total_bytes = 0;
};

class BehaviorVisualizer {
private:
    std::vector<IOEvent> events;
    std::map<int, ProcessNode> processes;
    std::map<std::string, FileNode> files;
    std::map<std::string, NetworkNode> networks;
    
    // Layout parameters
    static constexpr double CANVAS_WIDTH = 1200.0;
    static constexpr double CANVAS_HEIGHT = 800.0;
    static constexpr double NODE_RADIUS = 15.0;
    static constexpr double MIN_NODE_RADIUS = 8.0;
    static constexpr double MAX_NODE_RADIUS = 30.0;
    
    // Colors
    static constexpr const char* PROCESS_COLOR = "#4CAF50";
    static constexpr const char* FILE_COLOR = "#2196F3";
    static constexpr const char* NETWORK_COLOR = "#FF9800";
    static constexpr const char* STDIO_COLOR = "#9C27B0";
    static constexpr const char* READ_COLOR = "#F44336";
    static constexpr const char* WRITE_COLOR = "#03A9F4";
    
public:
    bool parseLogFile(const std::string& log_path);
    void analyzeDataFlow();
    void layoutNodes();
    void renderVisualization(BitmapRenderer& renderer);
    bool savePNG(const std::string& png_path);
    void generateVisualization(const std::string& log_path, const std::string& output_path);
    
private:
    IOEvent parseLogLine(const std::string& line);
    double calculateNodeSize(size_t total_bytes);
    std::string escapeXML(const std::string& str);
    void positionProcessNodes();
    void positionFileNodes();
    void positionNetworkNodes();
    std::string formatBytes(size_t bytes);
    std::string generateNodeTooltip(const std::string& type, const std::string& label, size_t read_bytes, size_t write_bytes);
};