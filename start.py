import subprocess
import sys
import os
import time
import signal
import webbrowser
import psutil
from pathlib import Path
import shutil

def check_dependencies():
    """Check if required dependencies are installed"""
    # Check for Node.js/npm
    if not shutil.which('npm'):
        print("Error: npm not found. Please install Node.js from https://nodejs.org/")
        print("After installation, you may need to restart your computer.")
        return False
    return True

def is_port_in_use(port):
    """Check if a port is in use"""
    for conn in psutil.net_connections():
        if conn.laddr.port == port:
            return True
    return False

def kill_process_on_port(port):
    """Kill any process using the specified port"""
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            # Get connections separately since it's not a basic process info attribute
            connections = proc.connections()
            for conn in connections:
                if hasattr(conn, 'laddr') and conn.laddr.port == port:
                    print(f"Killing process {proc.info['pid']} ({proc.info['name']}) using port {port}")
                    proc.kill()
                    time.sleep(1)  # Wait for the process to terminate
                    return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.Error):
            continue
    return False

def start_services():
    """Start both frontend and backend services"""
    # Check dependencies first
    if not check_dependencies():
        sys.exit(1)
        
    # Get the root directory
    root_dir = Path(__file__).parent.absolute()
    frontend_dir = root_dir / 'frontend'
    backend_dir = root_dir / 'backend'
    
    # Kill any processes using our ports
    if is_port_in_use(8000):
        print("Cleaning up backend port 8000...")
        kill_process_on_port(8000)
    if is_port_in_use(3000):
        print("Cleaning up frontend port 3000...")
        kill_process_on_port(3000)
    
    # Start backend
    print("Starting backend server...")
    backend_cmd = [sys.executable, "main.py"]
    backend_process = subprocess.Popen(
        backend_cmd,
        cwd=backend_dir,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == 'nt' else 0
    )
    
    # Wait for backend to start
    time.sleep(2)
    
    # Start frontend
    print("Starting frontend server...")
    try:
        # First, ensure all dependencies are installed
        print("Installing frontend dependencies...")
        subprocess.run(
            ["npm", "install"],
            cwd=frontend_dir,
            check=True,
            capture_output=True,
            text=True
        )
        
        frontend_cmd = ["npm", "run", "dev"]
        frontend_process = subprocess.Popen(
            frontend_cmd,
            cwd=frontend_dir,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == 'nt' else 0
        )
    except subprocess.CalledProcessError as e:
        print(f"Error installing frontend dependencies: {e.stdout}\n{e.stderr}")
        backend_process.terminate()
        sys.exit(1)
    except Exception as e:
        print(f"Error starting frontend server: {e}")
        backend_process.terminate()
        sys.exit(1)
    
    # Wait for frontend to start
    time.sleep(3)
    
    # Open the application in the default browser
    webbrowser.open('http://localhost:3000')
    
    print("\nNetSentinel is running!")
    print("Frontend: http://localhost:3000")
    print("Backend: http://localhost:8000")
    print("\nPress Ctrl+C to stop all services...")
    
    try:
        # Keep the script running and monitor child processes
        while True:
            # Check if processes are still running
            if backend_process.poll() is not None:
                print("Backend process terminated. Restarting...")
                backend_process = subprocess.Popen(
                    backend_cmd,
                    cwd=backend_dir,
                    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == 'nt' else 0
                )
            
            if frontend_process.poll() is not None:
                print("Frontend process terminated. Restarting...")
                frontend_process = subprocess.Popen(
                    frontend_cmd,
                    cwd=frontend_dir,
                    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == 'nt' else 0
                )
            
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nShutting down services...")
        # Kill processes
        if os.name == 'nt':
            backend_process.send_signal(signal.CTRL_BREAK_EVENT)
            frontend_process.send_signal(signal.CTRL_BREAK_EVENT)
        else:
            backend_process.terminate()
            frontend_process.terminate()
        
        # Wait for processes to terminate
        backend_process.wait()
        frontend_process.wait()
        print("Services stopped successfully!")

if __name__ == "__main__":
    start_services() 