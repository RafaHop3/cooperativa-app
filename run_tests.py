"""Test runner for the Cooperativa App

This script runs both the backend and frontend tests to verify system functionality.
"""

import os
import sys
import subprocess
import webbrowser
import time
from pathlib import Path

def print_header(title):
    """
    Print a formatted header
    """
    print("\n" + "=" * 70)
    print(f"\t{title}")
    print("=" * 70)

def run_backend_tests():
    """
    Run the backend pytest tests
    """
    print_header("Running Backend Tests")
    
    # Check if pytest is installed
    try:
        import pytest
    except ImportError:
        print("pytest not found. Installing...")
        subprocess.run([sys.executable, "-m", "pip", "install", "pytest"], check=True)
        print("pytest installed successfully.")
    
    # Check if TestClient is available
    try:
        from fastapi.testclient import TestClient
    except ImportError:
        print("fastapi TestClient not found. Installing...")
        subprocess.run([sys.executable, "-m", "pip", "install", "fastapi"], check=True)
        print("fastapi installed successfully.")
    
    # Change directory to backend
    os.chdir(Path(__file__).parent / "backend")
    
    # Run pytest
    print("\nExecuting pytest...")
    result = subprocess.run([sys.executable, "-m", "pytest", "test_main.py", "-v"], capture_output=True, text=True)
    
    # Print results
    print(result.stdout)
    if result.stderr:
        print("Errors:")
        print(result.stderr)
    
    return result.returncode

def start_backend_server():
    """
    Start the backend FastAPI server
    """
    print_header("Starting Backend Server")
    
    # Check if uvicorn is installed
    try:
        import uvicorn
    except ImportError:
        print("uvicorn not found. Installing...")
        subprocess.run([sys.executable, "-m", "pip", "install", "uvicorn"], check=True)
        print("uvicorn installed successfully.")
    
    # Change directory to backend
    os.chdir(Path(__file__).parent / "backend")
    
    # Start the server in a subprocess
    print("Starting FastAPI server...")
    process = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "main:app", "--reload", "--port", "8000"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    # Give it a moment to start
    time.sleep(2)
    
    # Check if server started correctly
    if process.poll() is None:
        print("FastAPI server started successfully!")
        return process
    else:
        print("Failed to start FastAPI server!")
        print(process.stderr.read())
        return None

def run_frontend_tests():
    """
    Open the frontend test page in a browser
    """
    print_header("Running Frontend Tests")
    
    test_page_path = Path(__file__).parent / "frontend" / "test-activity-logger.html"
    
    if not test_page_path.exists():
        print(f"Error: Test page not found at {test_page_path}")
        return 1
    
    print(f"Opening test page in browser: {test_page_path}")
    webbrowser.open(f"file://{test_page_path.absolute()}")
    
    print("\nFrontend test page opened. Please perform the following steps:")
    print("1. Log in using your credentials")
    print("2. Run the automated tests by clicking 'Execute All Tests'")
    print("3. Test manual logging with different activity types")
    print("4. Fetch recent logs (requires admin privileges)")
    print("\nNote: The backend server must be running for the tests to work correctly.")
    
    return 0

def main():
    """
    Main function to run tests
    """
    print_header("Cooperativa App System Test")
    print("This script will run tests to verify system functionality.")
    
    # Ask what tests to run
    print("\nWhich tests would you like to run?")
    print("1. Backend tests only")
    print("2. Frontend tests only")
    print("3. Both backend and frontend tests")
    print("4. Start server only")
    
    choice = input("Enter your choice (1-4): ")
    
    if choice == "1" or choice == "3":
        # Run backend tests
        backend_result = run_backend_tests()
        if backend_result != 0:
            print("\nBackend tests failed.")
            return 1
        else:
            print("\nBackend tests passed!")
    
    server_process = None
    if choice == "2" or choice == "3" or choice == "4":
        # Start backend server
        server_process = start_backend_server()
        if not server_process:
            print("Cannot run frontend tests without the backend server.")
            return 1
    
    if choice == "2" or choice == "3":
        # Run frontend tests
        frontend_result = run_frontend_tests()
    
        if server_process and choice != "4":
            # Ask if user wants to keep server running
            keep_running = input("\nKeep backend server running? (y/n): ").lower() == "y"
            if not keep_running:
                print("Stopping backend server...")
                server_process.terminate()
                server_process.wait()
                print("Backend server stopped.")
    
    if choice == "4" and server_process:
        print("\nServer is running. Press Ctrl+C to stop.")
        try:
            # Keep script running
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nStopping backend server...")
            server_process.terminate()
            server_process.wait()
            print("Backend server stopped.")
    
    print("\nSystem testing complete.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
