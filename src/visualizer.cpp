#include "visualizer.h"
#include <iostream>
#include <regex>
#include <chrono>
#include <random>

// Header-only library includes will be added by build system
#ifdef HAS_STB_IMAGE_WRITE
#define STB_IMAGE_WRITE_IMPLEMENTATION
#include "stb_image_write.h"
#endif

#ifdef HAS_NANOSVG
#define NANOSVG_IMPLEMENTATION
#define NANOSVGRAST_IMPLEMENTATION
#include "nanosvg.h"
#include "nanosvgrast.h"
#endif

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

std::string BehaviorVisualizer::generateSVG() {
    std::stringstream svg;
    
    // SVG header
    svg << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" << std::endl;
    svg << "<svg width=\"" << CANVAS_WIDTH << "\" height=\"" << CANVAS_HEIGHT << "\" "
        << "xmlns=\"http://www.w3.org/2000/svg\">" << std::endl;
    
    // Background
    svg << "<rect width=\"100%\" height=\"100%\" fill=\"#f8f9fa\"/>" << std::endl;
    
    // Title
    svg << "<text x=\"" << CANVAS_WIDTH/2 << "\" y=\"30\" text-anchor=\"middle\" "
        << "font-family=\"Arial, sans-serif\" font-size=\"18\" font-weight=\"bold\" fill=\"#333\">"
        << "QBScanner I/O Behavior Visualization</text>" << std::endl;
    
    // Draw connections first (so they appear behind nodes)
    for (const auto& [pid, process] : processes) {
        // Draw connections to files
        for (const std::string& file_path : process.files_accessed) {
            if (files.find(file_path) != files.end()) {
                const FileNode& file = files.at(file_path);
                svg << "<line x1=\"" << process.x << "\" y1=\"" << process.y 
                    << "\" x2=\"" << file.x << "\" y2=\"" << file.y 
                    << "\" stroke=\"#bdc3c7\" stroke-width=\"1\" opacity=\"0.6\"/>" << std::endl;
            }
        }
        
        // Draw connections to network
        for (const std::string& net_key : process.network_connections) {
            if (networks.find(net_key) != networks.end()) {
                const NetworkNode& network = networks.at(net_key);
                svg << "<line x1=\"" << process.x << "\" y1=\"" << process.y 
                    << "\" x2=\"" << network.x << "\" y2=\"" << network.y 
                    << "\" stroke=\"#f39c12\" stroke-width=\"2\" opacity=\"0.7\"/>" << std::endl;
            }
        }
    }
    
    // Draw file nodes
    for (const auto& [path, file] : files) {
        double radius = calculateNodeSize(file.total_read_bytes + file.total_write_bytes);
        const char* color = file.is_special_fd ? STDIO_COLOR : FILE_COLOR;
        
        svg << "<circle cx=\"" << file.x << "\" cy=\"" << file.y 
            << "\" r=\"" << radius << "\" fill=\"" << color << "\" "
            << "stroke=\"#2c3e50\" stroke-width=\"1\">" << std::endl;
        svg << "<title>" << escapeXML(generateNodeTooltip("File", path, file.total_read_bytes, file.total_write_bytes)) << "</title>" << std::endl;
        svg << "</circle>" << std::endl;
        
        // File label
        std::string display_name = path;
        if (display_name.length() > 15) {
            display_name = "..." + display_name.substr(display_name.length() - 12);
        }
        svg << "<text x=\"" << file.x << "\" y=\"" << file.y + radius + 15 
            << "\" text-anchor=\"middle\" font-family=\"Arial, sans-serif\" font-size=\"10\" fill=\"#2c3e50\">"
            << escapeXML(display_name) << "</text>" << std::endl;
    }
    
    // Draw process nodes
    for (const auto& [pid, process] : processes) {
        double radius = calculateNodeSize(process.total_read_bytes + process.total_write_bytes);
        
        svg << "<circle cx=\"" << process.x << "\" cy=\"" << process.y 
            << "\" r=\"" << radius << "\" fill=\"" << PROCESS_COLOR << "\" "
            << "stroke=\"#27ae60\" stroke-width=\"2\">" << std::endl;
        svg << "<title>" << escapeXML(generateNodeTooltip("Process", std::to_string(pid) + " (" + process.command + ")", 
                                                         process.total_read_bytes, process.total_write_bytes)) << "</title>" << std::endl;
        svg << "</circle>" << std::endl;
        
        // Process label
        svg << "<text x=\"" << process.x << "\" y=\"" << process.y + radius + 15 
            << "\" text-anchor=\"middle\" font-family=\"Arial, sans-serif\" font-size=\"10\" font-weight=\"bold\" fill=\"#27ae60\">"
            << "PID " << pid << "</text>" << std::endl;
    }
    
    // Draw network nodes
    for (const auto& [key, network] : networks) {
        double radius = calculateNodeSize(network.total_bytes);
        
        svg << "<circle cx=\"" << network.x << "\" cy=\"" << network.y 
            << "\" r=\"" << radius << "\" fill=\"" << NETWORK_COLOR << "\" "
            << "stroke=\"#e67e22\" stroke-width=\"2\">" << std::endl;
        svg << "<title>" << escapeXML(generateNodeTooltip("Network", network.connection_info, 0, network.total_bytes)) << "</title>" << std::endl;
        svg << "</circle>" << std::endl;
        
        // Network label
        svg << "<text x=\"" << network.x << "\" y=\"" << network.y + radius + 15 
            << "\" text-anchor=\"middle\" font-family=\"Arial, sans-serif\" font-size=\"10\" fill=\"#e67e22\">"
            << "Network</text>" << std::endl;
    }
    
    // Legend
    double legend_x = CANVAS_WIDTH - 200;
    double legend_y = 50;
    svg << "<text x=\"" << legend_x << "\" y=\"" << legend_y 
        << "\" font-family=\"Arial, sans-serif\" font-size=\"14\" font-weight=\"bold\" fill=\"#333\">"
        << "Legend:</text>" << std::endl;
    
    legend_y += 25;
    svg << "<circle cx=\"" << legend_x + 10 << "\" cy=\"" << legend_y 
        << "\" r=\"8\" fill=\"" << PROCESS_COLOR << "\"/>" << std::endl;
    svg << "<text x=\"" << legend_x + 25 << "\" y=\"" << legend_y + 4 
        << "\" font-family=\"Arial, sans-serif\" font-size=\"12\" fill=\"#333\">"
        << "Process</text>" << std::endl;
    
    legend_y += 20;
    svg << "<circle cx=\"" << legend_x + 10 << "\" cy=\"" << legend_y 
        << "\" r=\"8\" fill=\"" << FILE_COLOR << "\"/>" << std::endl;
    svg << "<text x=\"" << legend_x + 25 << "\" y=\"" << legend_y + 4 
        << "\" font-family=\"Arial, sans-serif\" font-size=\"12\" fill=\"#333\">"
        << "File</text>" << std::endl;
    
    legend_y += 20;
    svg << "<circle cx=\"" << legend_x + 10 << "\" cy=\"" << legend_y 
        << "\" r=\"8\" fill=\"" << STDIO_COLOR << "\"/>" << std::endl;
    svg << "<text x=\"" << legend_x + 25 << "\" y=\"" << legend_y + 4 
        << "\" font-family=\"Arial, sans-serif\" font-size=\"12\" fill=\"#333\">"
        << "stdio</text>" << std::endl;
    
    legend_y += 20;
    svg << "<circle cx=\"" << legend_x + 10 << "\" cy=\"" << legend_y 
        << "\" r=\"8\" fill=\"" << NETWORK_COLOR << "\"/>" << std::endl;
    svg << "<text x=\"" << legend_x + 25 << "\" y=\"" << legend_y + 4 
        << "\" font-family=\"Arial, sans-serif\" font-size=\"12\" fill=\"#333\">"
        << "Network</text>" << std::endl;
    
    svg << "</svg>" << std::endl;
    
    return svg.str();
}

bool BehaviorVisualizer::savePNG(const std::string& png_path) {
#ifdef HAS_NANOSVG
    std::string svg_content = generateSVG();
    
    // Parse SVG
    NSVGimage* image = nsvgParse(const_cast<char*>(svg_content.c_str()), "px", 96.0f);
    if (!image) {
        std::cerr << "Failed to parse SVG" << std::endl;
        return false;
    }
    
    // Create rasterizer
    NSVGrasterizer* rast = nsvgCreateRasterizer();
    if (!rast) {
        std::cerr << "Failed to create SVG rasterizer" << std::endl;
        nsvgDelete(image);
        return false;
    }
    
    // Render to bitmap
    int width = (int)CANVAS_WIDTH;
    int height = (int)CANVAS_HEIGHT;
    std::vector<unsigned char> img_data(width * height * 4);
    
    nsvgRasterize(rast, image, 0, 0, 1.0f, img_data.data(), width, height, width * 4);
    
    // Save as PNG
#ifdef HAS_STB_IMAGE_WRITE
    int result = stbi_write_png(png_path.c_str(), width, height, 4, img_data.data(), width * 4);
    
    nsvgDeleteRasterizer(rast);
    nsvgDelete(image);
    
    return result != 0;
#else
    std::cerr << "PNG saving not available - stb_image_write not included" << std::endl;
    nsvgDeleteRasterizer(rast);
    nsvgDelete(image);
    return false;
#endif

#else
    std::cerr << "SVG rendering not available - nanoSVG not included" << std::endl;
    
    // Fallback: save SVG instead
    std::string svg_content = generateSVG();
    std::string svg_path = png_path;
    size_t dot_pos = svg_path.find_last_of('.');
    if (dot_pos != std::string::npos) {
        svg_path = svg_path.substr(0, dot_pos) + ".svg";
    } else {
        svg_path += ".svg";
    }
    
    std::ofstream svg_file(svg_path);
    if (svg_file.is_open()) {
        svg_file << svg_content;
        svg_file.close();
        std::cout << "Saved SVG visualization to: " << svg_path << std::endl;
        return true;
    }
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