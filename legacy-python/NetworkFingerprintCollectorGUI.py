# Enhanced Computer and Network Fingerprint Collector - GUI Version
# This script gathers various system and network details from the machine
# it is executed on, creating a "fingerprint" of the system.
# The collected data is then displayed in a GUI and saved to a CSV file.

import platform
import os
import socket
import datetime
import csv
import uuid

import tkinter as tk
from tkinter import ttk
from tkinter import scrolledtext
from tkinter import messagebox

# --- Core Data Collection Functions (from original script) ---

def getIPAddress():
    """Gets a primary local IP address."""
    socketHandle = None
    try:
        socketHandle = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        socketHandle.settimeout(0.1)
        socketHandle.connect(('10.255.255.255', 1))
        ipAddress = socketHandle.getsockname()[0]
    except Exception:
        try:
            ipAddress = socket.gethostbyname(socket.gethostname())
        except Exception as e:
            return f'N/A: {e}'
    finally:
        if socketHandle:
            socketHandle.close()
    return ipAddress


def getMACAddress():
    """Gets a primary MAC address."""
    try:
        macNum = uuid.getnode()
        mac = ':'.join(('%012X' % macNum)[i:i+2] for i in range(0, 12, 2))
        if mac == '00:00:00:00:00:00':
            return 'N/A (uuid.getnode() returned null MAC)'
        return mac
    except Exception as e:
        return f'N/A: {e}'


def getProcessorModel():
    """Gets processor model information."""
    model = platform.processor()
    return model if model else 'N/A'


def collectComputerFingerprint():
    """Collects basic system and network information."""
    fingerprintData = {}
    fingerprintData['os'] = f'{platform.system()} {platform.release()} ({platform.version()})'
    fingerprintData['computer_name'] = platform.node()
    fingerprintData['processor_architecture'] = platform.machine()
    fingerprintData['processor_model'] = getProcessorModel()
    fingerprintData['ip_address'] = getIPAddress()
    fingerprintData['mac_address'] = getMACAddress()
    fingerprintData['system_time'] = datetime.datetime.now().isoformat()
    return fingerprintData


def saveToCSV(fingerprintData, filename='network_fingerprints.csv'):
    """Saves the fingerprint data to a CSV file.
    Returns a status message (success or error).
    """
    fieldnames = [
        'computer_name', 'os', 'processor_architecture', 'processor_model',
        'ip_address', 'mac_address', 'system_time'
    ]
    scriptDir = os.path.dirname(os.path.abspath(__file__))
    absoluteFilename = os.path.join(scriptDir, filename)
    fileExists = os.path.isfile(absoluteFilename)

    try:
        with open(absoluteFilename, 'a', newline='', encoding='utf-8') as csvFile:
            writer = csv.DictWriter(csvFile, fieldnames=fieldnames)
            if not fileExists:
                writer.writeheader()
            writer.writerow(fingerprintData)
        return f'Fingerprint data appended to {absoluteFilename}'
    except IOError as e:
        return f'Error: Could not write to CSV file {absoluteFilename}: {e}'

# --- GUI Application ---

class FingerprintApp:
    def __init__(self, master):
        self.master = master
        master.title('Network Fingerprint Collector')
        master.geometry('600x450') # Adjusted size

        # Style
        self.style = ttk.Style()
        self.style.theme_use('clam') # Or 'alt', 'default', 'classic'

        # Main frame
        mainFrame = ttk.Frame(master, padding='10 10 10 10')
        mainFrame.pack(fill=tk.BOTH, expand=True)

        # Button to collect data
        self.collectButton = ttk.Button(mainFrame, text='Collect Fingerprint', command=self.runCollection)
        self.collectButton.pack(pady=10)

        # Scrolled text area for results
        self.resultsText = scrolledtext.ScrolledText(mainFrame, wrap=tk.WORD, height=15, width=70)
        self.resultsText.pack(pady=5, fill=tk.BOTH, expand=True)
        self.resultsText.config(state=tk.DISABLED) # Make it read-only initially

        # Status bar
        self.statusVar = tk.StringVar()
        self.statusBar = ttk.Label(mainFrame, textvariable=self.statusVar, relief=tk.SUNKEN, anchor=tk.W)
        self.statusBar.pack(side=tk.BOTTOM, fill=tk.X, pady=(5,0))
        self.statusVar.set('Ready. Click "Collect Fingerprint" to start.')

    def runCollection(self):
        self.statusVar.set('Collecting local machine fingerprint...')
        self.master.update_idletasks() # Ensure status update is visible

        # Clear previous results
        self.resultsText.config(state=tk.NORMAL)
        self.resultsText.delete('1.0', tk.END)

        try:
            computerInfo = collectComputerFingerprint()

            # Display fingerprint in the text area
            display_string = f"--- Computer Fingerprint: {computerInfo.get('computer_name', 'N/A')} ---\n"
            for key, value in computerInfo.items():
                displayKey = key.replace('_', ' ').title()
                display_string += f"{displayKey}: {value}\n"
            display_string += "--------------------------\n"
            
            self.resultsText.insert(tk.END, display_string)
            self.resultsText.config(state=tk.DISABLED)

            # Save to CSV and update status
            save_status = saveToCSV(computerInfo)
            self.statusVar.set(save_status)
            if "Error" in save_status:
                messagebox.showerror("Save Error", save_status)
            else:
                messagebox.showinfo("Success", "Fingerprint collected and saved.")

        except Exception as e:
            error_message = f"An unexpected error occurred: {e}"
            self.resultsText.insert(tk.END, error_message)
            self.resultsText.config(state=tk.DISABLED)
            self.statusVar.set("Error during collection.")
            messagebox.showerror("Collection Error", error_message)


if __name__ == '__main__':
    root = tk.Tk()
    app = FingerprintApp(root)
    root.mainloop()