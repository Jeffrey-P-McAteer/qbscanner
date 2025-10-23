#!/usr/bin/env python3

"""
QBScanner Cross-Platform Build System

This script builds the QBScanner behavior monitoring tool with support for:
- Windows (Visual Studio, MinGW)
- Linux (GCC, Clang)
- macOS (Clang, GCC)

Usage:
    python build.py
    python3 build.py
    uv run build.py
"""

import os
import sys
import subprocess
import urllib.request
import tarfile
import shutil
import platform
import zipfile
from pathlib import Path

QEMU_VERSION = "8.2.0"
QEMU_URL = f"https://download.qemu.org/qemu-{QEMU_VERSION}.tar.xz"
BUILD_DIR = "build"
QEMU_DIR = f"qemu-{QEMU_VERSION}"

# Header-only libraries for visualization
HEADER_LIBS = {
    "stb_image_write.h": "https://raw.githubusercontent.com/nothings/stb/master/stb_image_write.h",
    "stb_truetype.h": "https://raw.githubusercontent.com/nothings/stb/master/stb_truetype.h",
    "nanosvg.h": "https://raw.githubusercontent.com/memononen/nanosvg/master/src/nanosvg.h",
    "nanosvgrast.h": "https://raw.githubusercontent.com/memononen/nanosvg/master/src/nanosvgrast.h"
}

def run_command(cmd, cwd=None, check=True):
    """Run a command and print output"""
    print(f"Running: {' '.join(cmd) if isinstance(cmd, list) else cmd}")
    result = subprocess.run(cmd, shell=isinstance(cmd, str), cwd=cwd, 
                          capture_output=False, check=check)
    return result

def download_qemu():
    """Download and extract QEMU source"""
    print(f"Downloading QEMU {QEMU_VERSION}...")
    
    if os.path.exists(QEMU_DIR):
        print(f"QEMU directory {QEMU_DIR} already exists, skipping download")
        return
    
    qemu_file = f"qemu-{QEMU_VERSION}.tar.xz"
    
    if not os.path.exists(qemu_file):
        urllib.request.urlretrieve(QEMU_URL, qemu_file)
        print(f"Downloaded {qemu_file}")
    
    print("Extracting QEMU...")
    with tarfile.open(qemu_file, 'r:xz') as tar:
        tar.extractall()
    
    print(f"QEMU extracted to {QEMU_DIR}")

def download_header_libraries():
    """Download header-only libraries for visualization"""
    print("Downloading header-only libraries for visualization...")
    
    os.makedirs(BUILD_DIR, exist_ok=True)
    
    for filename, url in HEADER_LIBS.items():
        target_path = os.path.join(BUILD_DIR, filename)
        
        if os.path.exists(target_path):
            print(f"Header library {filename} already exists, skipping download")
            continue
        
        try:
            print(f"Downloading {filename} from {url}")
            urllib.request.urlretrieve(url, target_path)
            print(f"Downloaded {filename}")
        except Exception as e:
            print(f"Warning: Failed to download {filename}: {e}")
            print("Visualization features may not be available")
    
    print("Header library download completed")

def check_qbscanner_source():
    """Check if qbscanner source exists"""
    if not os.path.exists("src/qbscanner.cpp"):
        print("Error: src/qbscanner.cpp not found!")
        print("Please ensure the source file exists in the src/ directory.")
        sys.exit(1)
    print("Found qbscanner source at src/qbscanner.cpp")

def configure_qemu():
    """Configure QEMU build (optional - for reference)"""
    print("Configuring QEMU (optional step for reference)...")
    
    os.makedirs(BUILD_DIR, exist_ok=True)
    
    # Check if we have required dependencies
    try:
        subprocess.run(["python3", "-c", "import distlib"], check=True, capture_output=True)
    except subprocess.CalledProcessError:
        print("Warning: distlib not available, skipping QEMU configuration")
        print("This is optional - qbscanner will be built with standalone ptrace functionality")
        return False
    
    configure_cmd = [
        f"../{QEMU_DIR}/configure",
        "--target-list=x86_64-linux-user",
        "--disable-system",
        "--enable-linux-user",
        "--disable-docs",
        "--disable-gtk",
        "--disable-sdl",
        "--disable-vnc"
    ]
    
    try:
        run_command(configure_cmd, cwd=BUILD_DIR)
        return True
    except subprocess.CalledProcessError:
        print("Warning: QEMU configuration failed, continuing with standalone build")
        return False

def build_qemu():
    """Build QEMU components we need (optional)"""
    print("Building QEMU components...")
    try:
        run_command(["make", "-j", str(os.cpu_count() or 4)], cwd=BUILD_DIR)
        return True
    except subprocess.CalledProcessError:
        print("Warning: QEMU build failed, continuing with standalone build")
        return False

def detect_compiler():
    """Detect available compiler and return configuration"""
    system = platform.system().lower()
    
    if system == "windows":
        # Check for Visual Studio compiler
        try:
            result = subprocess.run(["cl"], capture_output=True, text=True, shell=True)
            if "Microsoft" in result.stderr:
                return "msvc"
        except:
            pass
        
        # Check for MinGW-w64
        try:
            result = subprocess.run(["g++", "--version"], capture_output=True, text=True)
            if result.returncode == 0:
                return "mingw"
        except:
            pass
            
        print("Error: No suitable compiler found on Windows.")
        print("Please install Visual Studio with C++ tools or MinGW-w64.")
        return None
    else:
        # Unix-like systems
        try:
            result = subprocess.run(["g++", "--version"], capture_output=True, text=True)
            if result.returncode == 0:
                return "gcc"
        except:
            pass
            
        try:
            result = subprocess.run(["clang++", "--version"], capture_output=True, text=True)
            if result.returncode == 0:
                return "clang"
        except:
            pass
            
        print("Error: No suitable compiler found.")
        print("Please install g++ or clang++.")
        return None

def build_qbscanner(qemu_available=False):
    """Build the qbscanner tool"""
    print("Building qbscanner...")
    
    # Detect compiler
    compiler = detect_compiler()
    if not compiler:
        sys.exit(1)
    
    print(f"Using compiler: {compiler}")
    
    # Check for visualization libraries
    has_stb_write = os.path.exists(os.path.join(BUILD_DIR, "stb_image_write.h"))
    has_stb_truetype = os.path.exists(os.path.join(BUILD_DIR, "stb_truetype.h"))
    has_nanosvg = os.path.exists(os.path.join(BUILD_DIR, "nanosvg.h")) and os.path.exists(os.path.join(BUILD_DIR, "nanosvgrast.h"))
    
    visualization_flags = []
    if has_stb_write:
        if compiler == "msvc":
            visualization_flags.extend(["/DHAS_STB_IMAGE_WRITE", f"/I{BUILD_DIR}"])
        else:
            visualization_flags.extend(["-DHAS_STB_IMAGE_WRITE", f"-I{BUILD_DIR}"])
    if has_stb_truetype:
        if compiler == "msvc":
            visualization_flags.extend(["/DHAS_STB_TRUETYPE", f"/I{BUILD_DIR}"])
        else:
            visualization_flags.extend(["-DHAS_STB_TRUETYPE", f"-I{BUILD_DIR}"])
    if has_nanosvg:
        if compiler == "msvc":
            visualization_flags.extend(["/DHAS_NANOSVG", f"/I{BUILD_DIR}"])
        else:
            visualization_flags.extend(["-DHAS_NANOSVG", f"-I{BUILD_DIR}"])
    
    if has_stb_write and has_stb_truetype:
        if compiler == "msvc":
            visualization_flags.append("/DENABLE_VISUALIZATION")
        else:
            visualization_flags.append("-DENABLE_VISUALIZATION")
        print("Building with full visualization support (PNG output with text rendering)")
    elif has_stb_write or has_nanosvg:
        print("Building with partial visualization support (SVG output)")
    else:
        print("Building without visualization support")
    
    # Determine output executable name
    exe_name = "qbscanner.exe" if platform.system().lower() == "windows" else "qbscanner"
    
    # Build compile command based on compiler and platform
    source_files = [
        "src/qbscanner.cpp",
        "src/visualizer.cpp",
        "src/bitmap_renderer.cpp"
    ]
    
    if platform.system().lower() == "windows":
        source_files.append("src/platform_windows.cpp")
    else:
        source_files.append("src/platform_linux.cpp")
    
    if compiler == "msvc":
        # Visual Studio compiler
        compile_cmd = [
            "cl",
            "/std:c++17",
            "/O2",
            "/EHsc",
            "/W3"
        ] + visualization_flags + [
            f"/Fe:{exe_name}"
        ] + source_files + [
            "user32.lib", "kernel32.lib", "psapi.lib", "advapi32.lib"
        ]
        
        if qemu_available and platform.system().lower() != "windows":
            print("Note: QEMU integration not supported with MSVC on Windows")
            
    else:
        # GCC/Clang/MinGW compiler
        base_flags = [
            "-std=c++17",
            "-O2",
            "-Wall",
            "-Wextra"
        ]
        
        if compiler == "gcc":
            compile_cmd = ["g++"] + base_flags
        elif compiler == "clang":
            compile_cmd = ["clang++"] + base_flags
        elif compiler == "mingw":
            compile_cmd = ["g++"] + base_flags
            
        if qemu_available and platform.system().lower() != "windows":
            print("Building with QEMU integration...")
            # Get QEMU build include paths and library paths
            qemu_include_paths = [
                f"-I{QEMU_DIR}/include",
                f"-I{BUILD_DIR}",
                f"-I{QEMU_DIR}/linux-user",
                f"-I{QEMU_DIR}/linux-user/x86_64",
                f"-I{QEMU_DIR}/tcg",
                f"-I{QEMU_DIR}/tcg/i386"
            ]
            
            qemu_lib_paths = [
                f"-L{BUILD_DIR}",
                f"-L{BUILD_DIR}/linux-user"
            ]
            
            extra_libs = ["-lglib-2.0", "-lpthread", "-lrt", "-ldl"]
            
            # Add pkg-config for glib
            try:
                glib_flags = subprocess.check_output(["pkg-config", "--cflags", "--libs", "glib-2.0"], 
                                                   universal_newlines=True).strip().split()
            except subprocess.CalledProcessError:
                print("Warning: pkg-config for glib-2.0 failed, using fallback flags")
                glib_flags = []
                
            compile_cmd += glib_flags + qemu_include_paths + visualization_flags + [
                "-o", exe_name
            ] + source_files + extra_libs + qemu_lib_paths
        else:
            print("Building standalone cross-platform scanner...")
            
            # Platform-specific libraries
            platform_libs = []
            if platform.system().lower() == "windows":
                platform_libs = ["-luser32", "-lkernel32", "-lpsapi", "-ladvapi32"]
            else:
                platform_libs = ["-lpthread"]
                
            compile_cmd += visualization_flags + [
                "-o", exe_name
            ] + source_files + platform_libs
    
    run_command(compile_cmd)
    print(f"{exe_name} built successfully!")

def main():
    """Main build process"""
    print("Building QBScanner - QEMU-based behavior monitoring tool")
    print("=" * 60)
    
    try:
        # Download and setup QEMU
        download_qemu()
        
        # Download header-only libraries for visualization
        download_header_libraries()
        
        # Check qbscanner source exists
        check_qbscanner_source()
        
        # Try to configure and build QEMU (optional)
        qemu_configured = configure_qemu()
        qemu_built = False
        if qemu_configured:
            qemu_built = build_qemu()
        
        # Build qbscanner (with or without QEMU integration)
        build_qbscanner(qemu_built)
        
        # Determine executable name for output
        exe_name = "qbscanner.exe" if platform.system().lower() == "windows" else "qbscanner"
        
        print("\n" + "=" * 60)
        print("Build completed successfully!")
        print(f"Binary created: {os.path.abspath(exe_name)}")
        
        if platform.system().lower() == "windows":
            print(f"\nUsage: {exe_name} <command> [args...]")
        else:
            print(f"\nUsage: ./{exe_name} <command> [args...]")
        print("Output: behavior.log will contain all I/O monitoring data")
        print("Output: behavior.png will contain visualization (if libraries available)")
        print("\nCross-platform build successful!")
        
    except subprocess.CalledProcessError as e:
        print(f"Build failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()