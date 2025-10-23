#!/usr/bin/env python3

import os
import sys
import subprocess
import urllib.request
import tarfile
import shutil
from pathlib import Path

QEMU_VERSION = "8.2.0"
QEMU_URL = f"https://download.qemu.org/qemu-{QEMU_VERSION}.tar.xz"
BUILD_DIR = "build"
QEMU_DIR = f"qemu-{QEMU_VERSION}"

# Header-only libraries for visualization
HEADER_LIBS = {
    "stb_image_write.h": "https://raw.githubusercontent.com/nothings/stb/master/stb_image_write.h",
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

def build_qbscanner(qemu_available=False):
    """Build the qbscanner tool"""
    print("Building qbscanner...")
    
    # Check for visualization libraries
    has_stb = os.path.exists(os.path.join(BUILD_DIR, "stb_image_write.h"))
    has_nanosvg = os.path.exists(os.path.join(BUILD_DIR, "nanosvg.h")) and os.path.exists(os.path.join(BUILD_DIR, "nanosvgrast.h"))
    
    visualization_flags = []
    if has_stb:
        visualization_flags.extend(["-DHAS_STB_IMAGE_WRITE", f"-I{BUILD_DIR}"])
    if has_nanosvg:
        visualization_flags.extend(["-DHAS_NANOSVG", f"-I{BUILD_DIR}"])
    
    if has_stb and has_nanosvg:
        visualization_flags.append("-DENABLE_VISUALIZATION")
        print("Building with full visualization support (PNG output)")
    elif has_stb or has_nanosvg:
        print("Building with partial visualization support (SVG output)")
    else:
        print("Building without visualization support")
    
    if qemu_available:
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
            
        compile_cmd = [
            "g++",
            "-std=c++17",
            "-O2",
            "-Wall",
            "-Wextra"
        ] + glib_flags + qemu_include_paths + visualization_flags + [
            "-o", "qbscanner",
            "src/qbscanner.cpp",
            "src/visualizer.cpp"
        ] + extra_libs + qemu_lib_paths
    else:
        print("Building standalone ptrace-based scanner...")
        compile_cmd = [
            "g++",
            "-std=c++17",
            "-O2",
            "-Wall",
            "-Wextra"
        ] + visualization_flags + [
            "-o", "qbscanner",
            "src/qbscanner.cpp",
            "src/visualizer.cpp"
        ]
    
    run_command(compile_cmd)
    print("qbscanner built successfully!")

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
        
        print("\n" + "=" * 60)
        print("Build completed successfully!")
        print(f"qbscanner binary created: {os.path.abspath('qbscanner')}")
        print("\nUsage: ./qbscanner <command> [args...]")
        print("Output: behavior.log will contain all I/O monitoring data")
        print("Output: behavior.png will contain visualization (if libraries available)")
        
    except subprocess.CalledProcessError as e:
        print(f"Build failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()