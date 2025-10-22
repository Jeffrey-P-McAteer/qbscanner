#!/usr/bin/env python3

import os
import sys
import subprocess
import argparse
import shutil
from pathlib import Path
import glob

class QBScannerTester:
    def __init__(self):
        self.base_dir = Path(__file__).parent
        self.test_programs_dir = self.base_dir / "test-programs"
        self.build_dir = self.base_dir / "build"
        self.build_script = self.base_dir / "build.py"
        
        # Discover available tests dynamically
        self.available_tests = self._discover_tests()
    
    def _discover_tests(self):
        """Dynamically discover test programs in test-programs directory"""
        tests = {}
        
        if not self.test_programs_dir.exists():
            return tests
        
        # Find all source files
        c_files = list(self.test_programs_dir.glob("*.c"))
        shell_files = list(self.test_programs_dir.glob("*.sh"))
        
        # Add C programs
        for c_file in c_files:
            test_name = c_file.stem
            tests[test_name] = {
                'source': c_file.name,
                'type': 'c',
                'description': f'C program: {test_name}'
            }
        
        # Add shell scripts
        for sh_file in shell_files:
            test_name = sh_file.stem
            tests[test_name] = {
                'source': sh_file.name,
                'type': 'shell',
                'description': f'Shell script: {test_name}'
            }
        
        return tests
    
    def run_command(self, cmd, description=None, cwd=None):
        """Run a command and return its result"""
        if description:
            print(f"[INFO] {description}")
        
        print(f"[RUN] {' '.join(cmd) if isinstance(cmd, list) else cmd}")
        
        try:
            result = subprocess.run(
                cmd, 
                shell=isinstance(cmd, str),
                cwd=cwd or self.base_dir,
                capture_output=False,
                check=True
            )
            return result.returncode == 0
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Command failed with exit code {e.returncode}")
            return False
        except Exception as e:
            print(f"[ERROR] Error running command: {e}")
            return False
    
    def build_qbscanner(self):
        """Build qbscanner using the existing build.py script"""
        print("[BUILD] Building QBScanner using build.py...")
        
        if not self.build_script.exists():
            print(f"[ERROR] Build script not found: {self.build_script}")
            return False
        
        return self.run_command([sys.executable, str(self.build_script)], "Running build.py")
    
    def build_test_program(self, test_name):
        """Build a specific test program"""
        if test_name not in self.available_tests:
            print(f"[ERROR] Unknown test: {test_name}")
            return False
        
        test_info = self.available_tests[test_name]
        source_file = self.test_programs_dir / test_info['source']
        
        if not source_file.exists():
            print(f"[ERROR] Test source not found: {source_file}")
            return False
        
        # Ensure build directory exists
        self.build_dir.mkdir(exist_ok=True)
        
        build_path = self.build_dir / test_name
        
        if test_info['type'] == 'shell':
            # Copy shell script and make executable
            shutil.copy2(source_file, build_path)
            os.chmod(build_path, 0o755)
            print(f"[SUCCESS] Copied {test_name} to build directory")
            return True
        elif test_info['type'] == 'c':
            # Compile C program
            cmd = ["gcc", "-o", str(build_path), str(source_file)]
            return self.run_command(cmd, f"Compiling {test_name}")
        else:
            print(f"[ERROR] Unknown test type: {test_info['type']}")
            return False
    
    def run_test(self, test_name, extra_args=None):
        """Run a test program with qbscanner"""
        if test_name not in self.available_tests:
            print(f"[ERROR] Unknown test: {test_name}")
            return False
        
        test_info = self.available_tests[test_name]
        binary_path = self.build_dir / test_name
        
        if not binary_path.exists():
            print(f"[ERROR] Test binary not found: {binary_path}")
            return False
        
        # Check if qbscanner exists
        qbscanner_path = self.base_dir / "qbscanner"
        if not qbscanner_path.exists():
            print(f"[ERROR] qbscanner binary not found: {qbscanner_path}")
            return False
        
        # Prepare command
        cmd = [str(qbscanner_path), str(binary_path)]
        
        # Add extra arguments if provided
        if extra_args:
            cmd.extend(extra_args)
        
        print(f"[TEST] Running test: {test_name}")
        print(f"[DESC] Description: {test_info['description']}")
        if extra_args:
            print(f"[ARGS] Extra args: {' '.join(extra_args)}")
        print()
        
        success = self.run_command(cmd, f"Executing {test_name} with qbscanner")
        
        # Show behavior log location
        behavior_log = self.base_dir / "behavior.log"
        if behavior_log.exists():
            print()
            print(f"[LOG] Behavior log written to: {behavior_log}")
            print(f"[VIEW] View with: cat {behavior_log}")
        
        return success
    
    def list_tests(self):
        """List all available tests"""
        print("[LIST] Available tests:")
        print()
        if not self.available_tests:
            print("  No tests found in test-programs directory")
            return
        
        for name, info in self.available_tests.items():
            print(f"  {name:15} - {info['description']}")
            print(f"                  Source: {info['source']}")
        print()
    
    def clean(self):
        """Clean build artifacts"""
        print("[CLEAN] Cleaning build artifacts...")
        
        # Remove qbscanner binary
        qbscanner_bin = self.base_dir / "qbscanner"
        if qbscanner_bin.exists():
            qbscanner_bin.unlink()
            print("   Removed qbscanner")
        
        # Remove build directory contents
        if self.build_dir.exists():
            for item in self.build_dir.iterdir():
                if item.is_file():
                    item.unlink()
                    print(f"   Removed {item.name}")
        
        # Remove behavior log
        behavior_log = self.base_dir / "behavior.log"
        if behavior_log.exists():
            behavior_log.unlink()
            print("   Removed behavior.log")
        
        # Remove other build artifacts that might be created by build.py
        build_artifacts = [
            "config.log", 
            "qemu-8.2.0.tar.xz.tmp",
        ]
        
        for artifact in build_artifacts:
            artifact_path = self.base_dir / artifact
            if artifact_path.exists():
                artifact_path.unlink()
                print(f"   Removed {artifact}")
        
        print("[SUCCESS] Cleanup complete")
    
    def run_all_tests(self, extra_args=None):
        """Run all available tests"""
        print("[BATCH] Running all tests...")
        if extra_args:
            print(f"[ARGS] Extra args for all tests: {' '.join(extra_args)}")
        print()
        
        if not self.available_tests:
            print("[ERROR] No tests found to run")
            return False
        
        success_count = 0
        total_count = len(self.available_tests)
        
        for test_name in sorted(self.available_tests.keys()):
            print(f"{'='*60}")
            print(f"Test: {test_name}")
            print(f"{'='*60}")
            
            # Build and run test
            if self.build_test_program(test_name):
                if self.run_test(test_name, extra_args):
                    success_count += 1
                    print("[SUCCESS] Test completed successfully")
                else:
                    print("[ERROR] Test failed")
            else:
                print("[ERROR] Test build failed")
            
            print()
        
        print(f"[RESULTS] {success_count}/{total_count} tests completed successfully")
        return success_count == total_count

def main():
    parser = argparse.ArgumentParser(
        description="QBScanner Test Runner",
        epilog="Examples:\n"
               "  python test.py hello                    # Run hello test\n"
               "  python test.py fileio /path/to/file     # Run fileio test with file arg\n"
               "  python test.py --list                   # List all tests\n"
               "  python test.py --all                    # Run all tests\n"
               "  python test.py --clean                  # Clean build artifacts\n"
               "  python test.py hello --no-build-qbscanner  # Skip qbscanner rebuild",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('test_name', nargs='?', help='Name of the test to run')
    parser.add_argument('--list', action='store_true', help='List available tests')
    parser.add_argument('--all', action='store_true', help='Run all tests')
    parser.add_argument('--clean', action='store_true', help='Clean build artifacts')
    parser.add_argument('--no-build-qbscanner', action='store_true', 
                        help='Skip building qbscanner (use existing binary)')
    
    # Parse known args to separate test runner args from test program args
    args, extra_args = parser.parse_known_args()
    
    tester = QBScannerTester()
    
    # Handle special commands
    if args.clean:
        tester.clean()
        return 0
    
    if args.list:
        tester.list_tests()
        return 0
    
    # Build qbscanner unless skipped
    if not args.no_build_qbscanner:
        if not tester.build_qbscanner():
            print("[ERROR] Failed to build qbscanner")
            return 1
        print("[SUCCESS] QBScanner built successfully")
        print()
    
    # Run tests
    if args.all:
        success = tester.run_all_tests(extra_args if extra_args else None)
        return 0 if success else 1
    elif args.test_name:
        # Build and run specific test
        if not tester.build_test_program(args.test_name):
            return 1
        
        if not tester.run_test(args.test_name, extra_args if extra_args else None):
            return 1
        
        print("[SUCCESS] Test completed successfully")
        return 0
    else:
        # No test specified, show help
        tester.list_tests()
        print("Usage: python test.py <test_name> [test_args...]")
        print("Use --help for more options")
        return 1

if __name__ == "__main__":
    sys.exit(main())