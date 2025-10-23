#include "visualizer.h"
#include <iostream>
#include <regex>
#include <chrono>
#include <random>

bool BehaviorVisualizer::parseLogFile(const std::string& log_path) {
    std::ifstream file(log_path);
    if (!file.is_open()) {
        std::cerr << "Failed to open log file: " << log_path << std::endl;
        return false;
    }
    
    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '=') continue;
        
        IOEvent event = parseLogLine(line);
        if (!event.type.empty()) {
            events.push_back(event);
        }
    }
    
    std::cout << "Parsed " << events.size() << " events from log file" << std::endl;
    return true;
}

IOEvent BehaviorVisualizer::parseLogLine(const std::string& line) {
    IOEvent event;
    
    // Parse timestamp: [2025-10-23 11:04:21.821]
    std::regex timestamp_regex(R"(\[([^\]]+)\])");
    std::smatch timestamp_match;
    if (std::regex_search(line, timestamp_match, timestamp_regex)) {
        event.timestamp = timestamp_match[1].str();
    }
    
    // Parse PID: PID:100204
    std::regex pid_regex(R"(PID:(\d+))");
    std::smatch pid_match;
    if (std::regex_search(line, pid_match, pid_regex)) {
        event.pid = std::stoi(pid_match[1].str());
    }
    
    // Parse different event types
    if (line.find("PROCESS:") != std::string::npos) {
        event.type = "PROCESS";
        if (line.find("START") != std::string::npos) {
            event.operation = "START";
            // Extract command: cmd=...
            std::regex cmd_regex(R"(cmd=([^\s]+(?:\s+[^\s]+)*))");
            std::smatch cmd_match;
            if (std::regex_search(line, cmd_match, cmd_regex)) {
                event.details = cmd_match[1].str();
            }
        } else if (line.find("EXEC") != std::string::npos) {
            event.operation = "EXEC";
        } else if (line.find("EXIT") != std::string::npos) {
            event.operation = "EXIT";
        } else if (line.find("FORK") != std::string::npos) {
            event.operation = "FORK";
        }
    }
    else if (line.find("FILE_ACCESS:") != std::string::npos) {
        event.type = "FILE_ACCESS";
        if (line.find("OPEN") != std::string::npos) {
            event.operation = "OPEN";
            // Extract path: path=...
            std::regex path_regex(R"(path=([^\s]+))");
            std::smatch path_match;
            if (std::regex_search(line, path_match, path_regex)) {
                event.path = path_match[1].str();
            }
        }
    }
    else if (line.find("NETWORK:") != std::string::npos) {
        event.type = "NETWORK";
        if (line.find("SOCKET_CREATE") != std::string::npos) {
            event.operation = "SOCKET_CREATE";
        } else if (line.find("CONNECT") != std::string::npos) {
            event.operation = "CONNECT";
        } else if (line.find("BIND") != std::string::npos) {
            event.operation = "BIND";
        } else if (line.find("SEND") != std::string::npos) {
            event.operation = "SEND";
        } else if (line.find("RECV") != std::string::npos) {
            event.operation = "RECV";
        }
        event.details = line.substr(line.find("NETWORK:") + 8);
    }
    else if (line.find("READ_DATA") != std::string::npos || line.find("WRITE_DATA") != std::string::npos) {
        event.type = line.find("READ_DATA") != std::string::npos ? "READ_DATA" : "WRITE_DATA";
        
        // Extract fd: fd=...
        std::regex fd_regex(R"(fd=(\d+))");
        std::smatch fd_match;
        if (std::regex_search(line, fd_match, fd_regex)) {
            event.fd = std::stoi(fd_match[1].str());
        }
        
        // Extract size: size=...
        std::regex size_regex(R"(size=(\d+))");
        std::smatch size_match;
        if (std::regex_search(line, size_match, size_regex)) {
            event.data_size = std::stoull(size_match[1].str());
        }
        
        // Extract data preview from utf8 or ascii field
        std::regex data_regex(R"((?:utf8|ascii)=\"([^\"]*)\")");
        std::smatch data_match;
        if (std::regex_search(line, data_match, data_regex)) {
            event.data_preview = data_match[1].str();
            if (event.data_preview.length() > 50) {
                event.data_preview = event.data_preview.substr(0, 47) + "...";
            }
        }
    }
    
    return event;
}

void BehaviorVisualizer::analyzeDataFlow() {
    for (const auto& event : events) {
        // Track processes
        if (processes.find(event.pid) == processes.end()) {
            ProcessNode proc;
            proc.pid = event.pid;
            processes[event.pid] = proc;
        }
        
        ProcessNode& process = processes[event.pid];
        
        if (event.type == "PROCESS" && event.operation == "START") {
            process.command = event.details;
        }
        
        // Track file access
        if (event.type == "FILE_ACCESS" && !event.path.empty()) {
            if (files.find(event.path) == files.end()) {
                FileNode file;
                file.path = event.path;
                file.is_special_fd = (event.path == "stdin" || event.path == "stdout" || event.path == "stderr");
                files[event.path] = file;
            }
            
            files[event.path].accessing_pids.insert(event.pid);
            process.files_accessed.push_back(event.path);
        }
        
        // Track data I/O
        if (event.type == "READ_DATA" || event.type == "WRITE_DATA") {
            if (event.type == "READ_DATA") {
                process.total_read_bytes += event.data_size;
            } else {
                process.total_write_bytes += event.data_size;
            }
            
            // Map FD to file if possible (simplified heuristic)
            std::string fd_path;
            if (event.fd == 0) fd_path = "stdin";
            else if (event.fd == 1) fd_path = "stdout";
            else if (event.fd == 2) fd_path = "stderr";
            else fd_path = "fd_" + std::to_string(event.fd);
            
            if (files.find(fd_path) == files.end()) {
                FileNode file;
                file.path = fd_path;
                file.is_special_fd = (event.fd <= 2);
                files[fd_path] = file;
            }
            
            if (event.type == "READ_DATA") {
                files[fd_path].total_read_bytes += event.data_size;
            } else {
                files[fd_path].total_write_bytes += event.data_size;
            }
            
            files[fd_path].accessing_pids.insert(event.pid);
        }
        
        // Track network activity
        if (event.type == "NETWORK") {
            std::string net_key = event.operation + "_" + std::to_string(event.pid);
            if (networks.find(net_key) == networks.end()) {
                NetworkNode net;
                net.connection_info = event.operation + " (" + event.details + ")";
                networks[net_key] = net;
            }
            networks[net_key].connecting_pids.insert(event.pid);
            process.network_connections.push_back(net_key);
        }
    }
    
    std::cout << "Analysis complete: " << processes.size() << " processes, " 
              << files.size() << " files, " << networks.size() << " network connections" << std::endl;
}

void BehaviorVisualizer::layoutNodes() {
    positionProcessNodes();
    positionFileNodes();
    positionNetworkNodes();
}

void BehaviorVisualizer::positionProcessNodes() {
    // Position processes in the center-left area
    double start_x = CANVAS_WIDTH * 0.2;
    double start_y = CANVAS_HEIGHT * 0.1;
    double spacing_y = (CANVAS_HEIGHT * 0.8) / std::max(1.0, (double)processes.size());
    
    int index = 0;
    for (auto& [pid, process] : processes) {
        process.x = start_x;
        process.y = start_y + index * spacing_y;
        index++;
    }
}

void BehaviorVisualizer::positionFileNodes() {
    // Position files on the left side
    double start_x = CANVAS_WIDTH * 0.05;
    double start_y = CANVAS_HEIGHT * 0.1;
    double spacing_y = (CANVAS_HEIGHT * 0.8) / std::max(1.0, (double)files.size());
    
    int index = 0;
    for (auto& [path, file] : files) {
        file.x = start_x;
        file.y = start_y + index * spacing_y;
        
        // Special positioning for stdio
        if (file.is_special_fd) {
            if (path == "stdin") file.y = CANVAS_HEIGHT * 0.2;
            else if (path == "stdout") file.y = CANVAS_HEIGHT * 0.5;
            else if (path == "stderr") file.y = CANVAS_HEIGHT * 0.8;
        }
        
        index++;
    }
}

void BehaviorVisualizer::positionNetworkNodes() {
    // Position network nodes on the right side
    double start_x = CANVAS_WIDTH * 0.9;
    double start_y = CANVAS_HEIGHT * 0.1;
    double spacing_y = (CANVAS_HEIGHT * 0.8) / std::max(1.0, (double)networks.size());
    
    int index = 0;
    for (auto& [key, network] : networks) {
        network.x = start_x;
        network.y = start_y + index * spacing_y;
        index++;
    }
}

double BehaviorVisualizer::calculateNodeSize(size_t total_bytes) {
    if (total_bytes == 0) return MIN_NODE_RADIUS;
    
    double log_bytes = std::log10(total_bytes + 1);
    double normalized = log_bytes / 10.0; // Normalize to 0-1 range roughly
    normalized = std::min(1.0, std::max(0.0, normalized));
    
    return MIN_NODE_RADIUS + (MAX_NODE_RADIUS - MIN_NODE_RADIUS) * normalized;
}

std::string BehaviorVisualizer::escapeXML(const std::string& str) {
    std::string result;
    for (char c : str) {
        switch (c) {
            case '<': result += "&lt;"; break;
            case '>': result += "&gt;"; break;
            case '&': result += "&amp;"; break;
            case '"': result += "&quot;"; break;
            case '\'': result += "&apos;"; break;
            default: result += c; break;
        }
    }
    return result;
}

std::string BehaviorVisualizer::formatBytes(size_t bytes) {
    if (bytes < 1024) return std::to_string(bytes) + "B";
    if (bytes < 1024 * 1024) return std::to_string(bytes / 1024) + "KB";
    return std::to_string(bytes / (1024 * 1024)) + "MB";
}

std::string BehaviorVisualizer::generateNodeTooltip(const std::string& type, const std::string& label, size_t read_bytes, size_t write_bytes) {
    std::stringstream tooltip;
    tooltip << type << ": " << label;
    if (read_bytes > 0 || write_bytes > 0) {
        tooltip << "\\nRead: " << formatBytes(read_bytes);
        tooltip << "\\nWrite: " << formatBytes(write_bytes);
    }
    return tooltip.str();
}

void BehaviorVisualizer::renderVisualization(BitmapRenderer& renderer) {
    // Clear with white background
    renderer.clear(Color::white());
    
    // Title
    Point title_pos(CANVAS_WIDTH/2 - 150, 30);
    renderer.drawText("QBScanner I/O Behavior Visualization", title_pos, 18, Color::darkGray(), true);
    
    // Draw connections first (so they appear behind nodes)
    for (const auto& [pid, process] : processes) {
        // Draw connections to files
        for (const std::string& file_path : process.files_accessed) {
            if (files.find(file_path) != files.end()) {
                const FileNode& file = files.at(file_path);
                double mid_x = (process.x + file.x) / 2;
                double mid_y = (process.y + file.y) / 2;
                
                // Connection line
                renderer.drawLine(Point(process.x, process.y), Point(file.x, file.y), Color::gray(), 2.0f);
                
                // Edge label with data transfer info
                size_t total_bytes = file.total_read_bytes + file.total_write_bytes;
                if (total_bytes > 0) {
                    std::string bytes_str = formatBytes(total_bytes);
                    Point text_size = renderer.measureText(bytes_str, 9);
                    renderer.drawText(bytes_str, Point(mid_x - text_size.x/2, mid_y - 5), 9, Color::darkGray(), true);
                }
            }
        }
        
        // Draw connections to network
        for (const std::string& net_key : process.network_connections) {
            if (networks.find(net_key) != networks.end()) {
                const NetworkNode& network = networks.at(net_key);
                double mid_x = (process.x + network.x) / 2;
                double mid_y = (process.y + network.y) / 2;
                
                // Connection line
                renderer.drawLine(Point(process.x, process.y), Point(network.x, network.y), Color::orange(), 3.0f);
                
                // Edge label
                Point text_size = renderer.measureText("NETWORK", 9);
                renderer.drawText("NETWORK", Point(mid_x - text_size.x/2, mid_y - 5), 9, Color::orange(), true);
            }
        }
    }
    
    // Draw file nodes
    for (const auto& [path, file] : files) {
        double radius = calculateNodeSize(file.total_read_bytes + file.total_write_bytes);
        Color node_color = file.is_special_fd ? Color::purple() : Color::blue();
        
        // Node circle
        renderer.drawCircle(Point(file.x, file.y), radius, node_color, Color::darkGray(), 2.0f);
        
        // File label with better visibility
        std::string display_name = path;
        if (display_name.length() > 15) {
            display_name = "..." + display_name.substr(display_name.length() - 12);
        }
        
        // White background for text
        Point text_size = renderer.measureText(display_name, 10);
        Rect text_bg(file.x - text_size.x/2 - 5, file.y + radius + 5, text_size.x + 10, 16);
        renderer.drawRect(text_bg, Color::white(), Color::gray(), 1.0f);
        
        renderer.drawText(display_name, Point(file.x - text_size.x/2, file.y + radius + 17), 10, Color::darkGray(), true);
        
        // Data transfer info on the node
        size_t total_bytes = file.total_read_bytes + file.total_write_bytes;
        if (total_bytes > 0) {
            std::string bytes_str = formatBytes(total_bytes);
            Point bytes_size = renderer.measureText(bytes_str, 8);
            renderer.drawText(bytes_str, Point(file.x - bytes_size.x/2, file.y + 4), 8, Color::white(), true);
        }
    }
    
    // Draw process nodes
    for (const auto& [pid, process] : processes) {
        double radius = calculateNodeSize(process.total_read_bytes + process.total_write_bytes);
        
        // Node circle
        renderer.drawCircle(Point(process.x, process.y), radius, Color::green(), Color::green(), 3.0f);
        
        // Process ID on node
        std::string pid_str = std::to_string(pid);
        Point pid_size = renderer.measureText(pid_str, 10);
        renderer.drawText(pid_str, Point(process.x - pid_size.x/2, process.y + 4), 10, Color::white(), true);
        
        // Process label with white background
        std::string cmd_display = process.command;
        if (cmd_display.length() > 20) {
            cmd_display = cmd_display.substr(0, 17) + "...";
        }
        
        std::string label = "PID " + std::to_string(pid) + " (" + cmd_display + ")";
        Point label_size = renderer.measureText(label, 10);
        Rect label_bg(process.x - label_size.x/2 - 5, process.y + radius + 5, label_size.x + 10, 16);
        renderer.drawRect(label_bg, Color::white(), Color::green(), 1.0f);
        
        renderer.drawText(label, Point(process.x - label_size.x/2, process.y + radius + 17), 10, Color::green(), true);
        
        // Data transfer info
        size_t total_bytes = process.total_read_bytes + process.total_write_bytes;
        if (total_bytes > 0) {
            std::string io_str = "I/O: " + formatBytes(total_bytes);
            Point io_size = renderer.measureText(io_str, 9);
            renderer.drawText(io_str, Point(process.x - io_size.x/2, process.y - radius - 5), 9, Color::green(), true);
        }
    }
    
    // Draw network nodes
    for (const auto& [key, network] : networks) {
        double radius = calculateNodeSize(network.total_bytes);
        
        // Node circle
        renderer.drawCircle(Point(network.x, network.y), radius, Color::orange(), Color::orange(), 3.0f);
        
        // Network icon/text on node
        Point net_size = renderer.measureText("NET", 9);
        renderer.drawText("NET", Point(network.x - net_size.x/2, network.y + 4), 9, Color::white(), true);
        
        // Network label with white background
        std::string net_display = network.connection_info;
        if (net_display.length() > 18) {
            net_display = net_display.substr(0, 15) + "...";
        }
        
        Point label_size = renderer.measureText(net_display, 10);
        Rect label_bg(network.x - label_size.x/2 - 5, network.y + radius + 5, label_size.x + 10, 16);
        renderer.drawRect(label_bg, Color::white(), Color::orange(), 1.0f);
        
        renderer.drawText(net_display, Point(network.x - label_size.x/2, network.y + radius + 17), 10, Color::orange(), true);
    }
    
    // Legend with white background
    double legend_x = CANVAS_WIDTH - 200;
    double legend_y = 50;
    
    // Legend background
    Rect legend_bg(legend_x - 10, legend_y - 20, 180, 140);
    renderer.drawRect(legend_bg, Color::white(), Color::gray(), 2.0f);
    
    renderer.drawText("Legend:", Point(legend_x, legend_y), 14, Color::darkGray(), true);
    
    legend_y += 25;
    renderer.drawCircle(Point(legend_x + 10, legend_y), 8, Color::green(), Color::green(), 2.0f);
    renderer.drawText("Process (with PID)", Point(legend_x + 25, legend_y + 4), 12, Color::darkGray(), true);
    
    legend_y += 20;
    renderer.drawCircle(Point(legend_x + 10, legend_y), 8, Color::blue(), Color::darkGray(), 2.0f);
    renderer.drawText("File (with size)", Point(legend_x + 25, legend_y + 4), 12, Color::darkGray(), true);
    
    legend_y += 20;
    renderer.drawCircle(Point(legend_x + 10, legend_y), 8, Color::purple(), Color::darkGray(), 2.0f);
    renderer.drawText("Standard I/O", Point(legend_x + 25, legend_y + 4), 12, Color::darkGray(), true);
    
    legend_y += 20;
    renderer.drawCircle(Point(legend_x + 10, legend_y), 8, Color::orange(), Color::orange(), 2.0f);
    renderer.drawText("Network Connection", Point(legend_x + 25, legend_y + 4), 12, Color::darkGray(), true);
    
    legend_y += 25;
    renderer.drawText("Node size = I/O volume", Point(legend_x, legend_y), 11, Color::gray());
}

bool BehaviorVisualizer::savePNG(const std::string& png_path) {
#ifdef ENABLE_VISUALIZATION
    // Create bitmap renderer
    BitmapRenderer renderer(static_cast<int>(CANVAS_WIDTH), static_cast<int>(CANVAS_HEIGHT));
    
    // Render the visualization
    renderVisualization(renderer);
    
    // Save as PNG
    return renderer.savePNG(png_path);
#else
    std::cerr << "PNG rendering not available - visualization libraries not included" << std::endl;
    return false;
#endif
}

void BehaviorVisualizer::generateVisualization(const std::string& log_path, const std::string& output_path) {
    std::cout << "Generating visualization from: " << log_path << std::endl;
    
    if (!parseLogFile(log_path)) {
        std::cerr << "Failed to parse log file" << std::endl;
        return;
    }
    
    analyzeDataFlow();
    layoutNodes();
    
    if (savePNG(output_path)) {
        std::cout << "Visualization saved to: " << output_path << std::endl;
    } else {
        std::cerr << "Failed to save visualization" << std::endl;
    }
}