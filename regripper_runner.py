import argparse
import subprocess
import os
import sys

def run_regripper(hive_path, plugin, rip_path="tools/regripper/rip.exe"):
    rip_path = os.environ.get('REGRIPPER_PATH', rip_path)
    if not os.path.exists(hive_path):
        raise FileNotFoundError(f"Registry hive not found: {hive_path}")
    
    if not os.path.exists(rip_path):
        raise FileNotFoundError(f"RegRipper executable not found: {rip_path}")

    cmd = [rip_path, "-r", hive_path, "-p", plugin]
    
    try:
        # Run RegRipper and capture output
        result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='replace', check=False)
        
        # rip.exe might return non-zero exit codes even on success depending on the plugin, 
        # but we should check if there's any critical error output.
        if result.returncode != 0 and not result.stdout.strip():
            raise RuntimeError(f"RegRipper failed with exit code {result.returncode}.\nStderr: {result.stderr}")
            
        return result.stdout
    except subprocess.SubprocessError as e:
        raise RuntimeError(f"Error executing RegRipper: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run RegRipper plugins on a registry hive.")
    parser.add_argument("-r", "--hive", required=True, help="Path to the registry hive")
    parser.add_argument("-p", "--plugin", required=True, help="RegRipper plugin name (e.g., usbstor)")
    
    args = parser.parse_args()
    
    try:
        output = run_regripper(args.hive, args.plugin)
        print(output)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
