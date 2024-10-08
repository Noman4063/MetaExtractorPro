import os
import time
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from PIL import Image
from PIL.ExifTags import TAGS
import subprocess
import json
import shutil

# File to store scan data
SCAN_DATA_FILE = 'file_scan_data.json'

# Dictionary to track file hashes and scan counts
file_scan_data = {}

# Load scan data from the file
def load_scan_data():
    global file_scan_data
    if os.path.exists(SCAN_DATA_FILE):
        try:
            with open(SCAN_DATA_FILE, 'r') as f:
                file_scan_data = json.load(f)
            # Load the scan history for previously scanned files
            for file_path, data in file_scan_data.items():
                update_scan_history(file_path, data['scan_count'])
        except Exception as e:
            print(f"Error loading scan data: {e}")
            file_scan_data = {}

# Save scan data to the file
def save_scan_data():
    try:
        with open(SCAN_DATA_FILE, 'w') as f:
            json.dump(file_scan_data, f, indent=4)
    except Exception as e:
        print(f"Error saving scan data: {e}")

# Helper to calculate the hash of a file
def calculate_hash(file_path, hash_algorithm='sha256'):
    try:
        hash_algo = hashlib.new(hash_algorithm)
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                hash_algo.update(chunk)
        return hash_algo.hexdigest()
    except Exception as e:
        return f"Error calculating hash: {str(e)}"

# Basic file metadata extraction
def file_metadata(file_path):
    try:
        file_stats = os.stat(file_path)
        metadata = {
            'File Name': os.path.basename(file_path),
            'File Size': f"{file_stats.st_size / (1024 * 1024):.2f} MB",
            'File Type': os.path.splitext(file_path)[1][1:].upper(),
            'Creation Time': time.ctime(file_stats.st_ctime),
            'Modification Time': time.ctime(file_stats.st_mtime),
            'Access Time': time.ctime(file_stats.st_atime),
            'Owner': os.getuid()  # Get Owner UID
        }
        return metadata
    except Exception as e:
        return {"Error": str(e)}

# Extract EXIF data for images
def extract_exif_image(file_path):
    try:
        image = Image.open(file_path)
        exif_data = image.getexif()
        exif = {}
        for tag, value in exif_data.items():
            tag_name = TAGS.get(tag, tag)
            exif[tag_name] = value
        exif['Resolution'] = f"{image.size[0]} x {image.size[1]} pixels"
        return exif if exif else {"Info": "No EXIF metadata found."}
    except Exception as e:
        return {"Error": str(e)}

# Use exiftool for additional metadata
def exiftool_metadata(file_path):
    try:
        result = subprocess.run(['exiftool', file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode != 0:
            return {"Error": result.stderr.strip()}
        
        metadata = {}
        for line in result.stdout.strip().splitlines():
            if ": " in line:
                key, value = line.split(": ", 1)
                metadata[key.strip()] = value.strip()
        return metadata
    except Exception as e:
        return {"Error": str(e)}

# Extract metadata for video files using ffprobe (from ffmpeg)
def extract_video_metadata(file_path):
    try:
        if shutil.which('ffprobe') is None:
            return {"Error": "'ffprobe' not found. Ensure ffmpeg is installed and added to PATH."}
        
        result = subprocess.run(['ffprobe', '-v', 'error', '-show_format', '-show_streams', file_path],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode != 0:
            return {"Error": result.stderr.strip()}
        
        return {"Video Metadata": result.stdout.strip()}
    except Exception as e:
        return {"Error": str(e)}

# Extract metadata for text files
def extract_text_metadata(file_path):
    try:
        with open(file_path, 'r', encoding="utf-8") as f:
            content = f.read()
    except UnicodeDecodeError:
        with open(file_path, 'r', encoding="ISO-8859-1") as f:
            content = f.read()

    return {
        'Lines': len(content.splitlines()),
        'Characters': len(content)
    }

# Function to detect if the file or its metadata has changed since last scan
def detect_file_modification(file_path, old_hash, old_metadata):
    new_hash = calculate_hash(file_path)
    new_metadata = file_metadata(file_path)

    file_changed = (new_hash != old_hash)
    metadata_changed = (new_metadata != old_metadata)

    changes = {}
    if metadata_changed:
        for key, new_value in new_metadata.items():
            old_value = old_metadata.get(key)
            if old_value != new_value:
                changes[key] = (old_value, new_value)

    return file_changed or metadata_changed, new_hash, new_metadata, changes

# Function to handle file selection and metadata extraction
def select_file_and_extract_metadata():
    file_path = filedialog.askopenfilename()
    if not file_path:
        return

    output_text.delete(1.0, tk.END)

    basic_metadata = file_metadata(file_path)
    print_metadata(basic_metadata, "Basic Metadata")

    selected_algo = hash_algorithm.get()
    file_hash = calculate_hash(file_path, selected_algo)
    
    output_text.insert(tk.END, f"\n[+] File Hash ({selected_algo.upper()}):\n")
    output_text.insert(tk.END, f"File Hash: {file_hash}\n")

    # Check for modifications
    if file_path in file_scan_data:
        old_hash = file_scan_data[file_path]['hash']
        old_metadata = file_scan_data[file_path]['metadata']
        
        modified, new_hash, new_metadata, changes = detect_file_modification(file_path, old_hash, old_metadata)
        
        if modified:
            output_text.insert(tk.END, f"\n[!] The file or its metadata has been modified since the last scan.\n")
            messagebox.showwarning("File Modified", f"The file or its metadata has been modified since the last scan.")
            highlight_changes(changes)
        else:
            output_text.insert(tk.END, f"\n[!] The file and its metadata have not changed since the last scan.\n")
            messagebox.showinfo("File Not Modified", f"The file and its metadata have not changed.")
        
        file_scan_data[file_path]['hash'] = new_hash
        file_scan_data[file_path]['metadata'] = new_metadata
        file_scan_data[file_path]['scan_count'] += 1
        scan_count = file_scan_data[file_path]['scan_count']
    else:
        # First-time scan or renamed file
        file_scan_data[file_path] = {
            'hash': file_hash,
            'metadata': basic_metadata,
            'scan_count': 1
        }
        scan_count = 1
        output_text.insert(tk.END, f"\n[+] First-Time Scan: Metadata has been detected.\n")
        messagebox.showinfo("First-Time Scan", f"This is the first time the file has been scanned.")

    save_scan_data()
    output_text.insert(tk.END, f"\n[+] This file has been scanned {scan_count} time(s).\n")

    # Handle specific file types
    if file_path.lower().endswith(('.png', '.jpg', '.jpeg', '.tiff')):
        exif_data = extract_exif_image(file_path)
        print_metadata(exif_data, "Image EXIF Metadata")
    elif file_path.lower().endswith(('.mp4', '.mkv', '.avi', '.mov')):
        video_metadata = extract_video_metadata(file_path)
        print_metadata(video_metadata, "Video Metadata")
    elif file_path.lower().endswith(('.txt', '.log', '.md')):
        text_metadata = extract_text_metadata(file_path)
        print_metadata(text_metadata, "Text Metadata")
    
    exif_metadata = exiftool_metadata(file_path)
    print_metadata(exif_metadata, "EXIF Tool Metadata")

    # Update scan history
    update_scan_history(file_path, scan_count)

# Function to print metadata in the GUI
def print_metadata(metadata, title="Metadata"):
    output_text.insert(tk.END, f"\n[+] {title}:\n")
    for key, value in metadata.items():
        output_text.insert(tk.END, f"{key}: {value}\n")

# Function to highlight changes in metadata
def highlight_changes(changes):
    output_text.insert(tk.END, "\n[!] Changes Detected:\n")
    for key, (old_value, new_value) in changes.items():
        output_text.insert(tk.END, f"{key}: {old_value} -> {new_value}\n", "highlight")

    # Add tag for highlighting
    output_text.tag_configure("highlight", foreground="red", font=("Arial", 10, "italic"))

# Function to update the scan history in the history box
def update_scan_history(file_path, scan_count):
    history_box.insert(tk.END, f"{file_path} - Scanned {scan_count} time(s)\n")

# Function to download the current scan report
def download_current_report():
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", title="Save Current Scan Report")
    if file_path:
        with open(file_path, 'w') as f:
            f.write(output_text.get(1.0, tk.END))
            messagebox.showinfo("Report Downloaded", f"Current scan report saved as {file_path}.")

# Function to download reports for previous scans
def download_previous_reports():
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", title="Save Previous Scan Reports")
    if file_path:
        with open(file_path, 'w') as f:
            for file, data in file_scan_data.items():
                f.write(f"File: {file}\nScan Count: {data['scan_count']}\n")
                f.write(f"Last Hash: {data['hash']}\n")
                for key, value in data['metadata'].items():
                    f.write(f"{key}: {value}\n")
                f.write("\n")
            messagebox.showinfo("Reports Downloaded", f"Previous scan reports saved as {file_path}.")

# Initialize the GUI
root = tk.Tk()
root.title("MetaExtractorPro")
root.geometry("800x600")

# Left frame for options
left_frame = tk.Frame(root, bg="lightblue", padx=10, pady=10)
left_frame.pack(side=tk.LEFT, fill=tk.Y)

# Download report buttons
download_current_button = tk.Button(left_frame, text="Download Report for Current Scan", command=download_current_report, bg="orange")
download_current_button.pack(fill=tk.X)

download_previous_button = tk.Button(left_frame, text="Download Report for Previous Scans", command=download_previous_reports, bg="orange")
download_previous_button.pack(fill=tk.X)

# Hash algorithm selection
hash_algorithm = ttk.Combobox(left_frame, values=["md5", "sha1", "sha224", "sha256", "sha384", "sha512", "blake2b", "blake2s", "sha3_256"], state="readonly")
hash_algorithm.set("sha256")  # Default value
hash_algorithm.pack(pady=5)

# Button to select a file
select_file_button = tk.Button(left_frame, text="Select File", command=select_file_and_extract_metadata, bg="lightgreen")
select_file_button.pack(fill=tk.X)

# Text output area for metadata
output_text = tk.Text(root, wrap=tk.WORD, bg="white", font=("Arial", 10))
output_text.pack(expand=True, fill=tk.BOTH, padx=(10, 0))

# History box
history_box = tk.Text(left_frame, wrap=tk.WORD, bg="lightyellow", width=30, height=20)
history_box.pack(pady=10)

# Load existing scan data on startup
load_scan_data()

# Start the GUI main loop
root.mainloop()
