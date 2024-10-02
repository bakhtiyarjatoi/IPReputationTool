import tkinter as tk
from tkinter import ttk
from tkinter import Scrollbar
from tkinter import filedialog, messagebox, simpledialog, PhotoImage, scrolledtext
import os
import json
import pandas as pd
import threading
import time
from scanning import virustotal_scan, abuseipdb_scan

class IPReputationToolUI:
    def __init__(self, root):
        self.root = root
        self.pause_flag = False
        self.stop_flag = False
        self.root.title("IP Reputation Tool")
        self.root.geometry("900x800")
        self.root.configure(bg="#f0f0f0")

        self.setup_logging()
        self.load_logo()
        self.load_configuration()

        self.input_file = None
        self.output_file = None
        self.scan_running = False
        self.scan_results = []
        self.total_ips = 0
        self.scanned_ips = 0

        self.create_widgets()

    def setup_logging(self):
        import logging
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger()
        self.logs_text = None

    def log_message(self, message):
        self.logger.info(message)
        self.logs_text.configure(state='normal')
        self.logs_text.insert(tk.END, f"{message}\n")
        self.logs_text.configure(state='disabled')
        self.logs_text.yview(tk.END)  # Scroll to the end

    def load_logo(self):
        try:
            logo_path = os.path.join(os.path.dirname(__file__), 'assets', 'scan_logo.ico')
            self.root.iconbitmap(logo_path)
            logo_image_path = os.path.join(os.path.dirname(__file__), 'assets', 'scan_logo.png')
            self.logo_img = PhotoImage(file=logo_image_path)
            logo_label = tk.Label(self.root, image=self.logo_img, bg="#f0f0f0")
            logo_label.pack(pady=10)
        except Exception as e:
            self.log_message(f"Error loading logo: {e}")

    def load_configuration(self):
        try:
            # Check if the config file exists in the current directory
            if not os.path.exists("config.json"):
                raise FileNotFoundError("config.json not found in the current directory.")

            with open("config.json", "r") as config_file:
                config_data = json.load(config_file)
                # Load your configuration data here
        except FileNotFoundError as e:
            self.log_message(f"Error loading configuration: {e}")
            # Optionally, initialize with default settings here
            # self.initialize_default_settings()
        except json.JSONDecodeError:
            self.log_message("Error: Invalid JSON format in config.json.")
        except Exception as e:
            self.log_message(f"Unexpected error: {e}")

    def create_widgets(self):
        title_frame = tk.Frame(self.root, bg="#4a90e2", pady=10)
        title_frame.pack(fill=tk.X)
        tk.Label(title_frame, text="IP Reputation Tool", font=("Arial", 20, "bold"), fg="white", bg="#4a90e2").pack()

        api_key_frame = self.create_api_key_frame()
        api_key_frame.pack(fill=tk.X, padx=20, pady=5)

        scan_controls_frame = self.create_scan_controls_frame()
        scan_controls_frame.pack(fill=tk.X, padx=20, pady=5)

        file_controls_frame = self.create_file_controls_frame()
        file_controls_frame.pack(fill=tk.X, padx=20, pady=5)

        self.progress = tk.ttk.Progressbar(self.root, length=800, mode='determinate')
        self.progress.pack(pady=10)

        self.scan_info_label = tk.Label(self.root, text="Scanned IPs: 0 / 0 | Remaining IPs: 0 | 0% completed", font=("Arial", 12), bg="#f0f0f0")
        self.scan_info_label.pack(pady=5)

        self.logs_text = scrolledtext.ScrolledText(self.root, height=15, width=100, bg="#f8f8f8", wrap=tk.WORD, font=("Consolas", 10))
        self.logs_text.pack(pady=10, padx=20)
        self.logs_text.configure(state='disabled')

        footer = tk.Label(self.root, text="Tool made with ❤️. All rights reserved.", font=("Arial", 10, "italic"), bg="#f0f0f0")
        footer.pack(side=tk.BOTTOM, pady=10)

    def create_api_key_frame(self):
        api_key_frame = tk.LabelFrame(self.root, text="API Keys", font=("Arial", 14), bg="#ffffff", padx=20, pady=10)
        
        tk.Button(api_key_frame, text="Set VirusTotal API Key", command=self.set_virustotal_api_key, bg="#4a90e2", fg="white", width=25).grid(row=0, column=0, padx=10, pady=5)
        tk.Button(api_key_frame, text="Set AbuseIPDB API Key", command=self.set_abuseipdb_api_key, bg="#4a90e2", fg="white", width=25).grid(row=0, column=1, padx=10, pady=5)

        return api_key_frame

    def create_scan_controls_frame(self):
        scan_controls_frame = tk.LabelFrame(self.root, text="Scan Controls", font=("Arial", 14), bg="#ffffff", padx=20, pady=10)

        self.virustotal_button = tk.Button(scan_controls_frame, text="Scan with VirusTotal", command=lambda: self.start_scan(virustotal_scan), bg="#4a90e2", fg="white", width=20)
        self.virustotal_button.grid(row=0, column=0, padx=10, pady=5)

        self.abuseipdb_button = tk.Button(scan_controls_frame, text="Scan with AbuseIPDB", command=lambda: self.start_scan(abuseipdb_scan), bg="#4a90e2", fg="white", width=20)
        self.abuseipdb_button.grid(row=0, column=1, padx=10, pady=5)

        self.pause_button = tk.Button(scan_controls_frame, text="Pause", command=self.pause_scanning, state=tk.DISABLED, bg="#ff9500", fg="white", width=10)
        self.pause_button.grid(row=0, column=2, padx=10, pady=5)

        self.stop_button = tk.Button(scan_controls_frame, text="Stop", command=self.stop_scanning, state=tk.DISABLED, bg="#ff3b30", fg="white", width=10)
        self.stop_button.grid(row=0, column=3, padx=10, pady=5)

        return scan_controls_frame

    def create_file_controls_frame(self):
        file_controls_frame = tk.LabelFrame(self.root, text="File Controls", font=("Arial", 14), bg="#ffffff", padx=20, pady=10)

        tk.Button(file_controls_frame, text="Add Input File", command=self.load_input_file, bg="#4a90e2", fg="white", width=15).grid(row=0, column=0, padx=10, pady=5)
        tk.Button(file_controls_frame, text="Export Results", command=self.export_results, bg="#4a90e2", fg="white", width=15).grid(row=0, column=1, padx=10, pady=5)
        tk.Button(file_controls_frame, text="View History", command=self.view_history, bg="#4a90e2", fg="white", width=15).grid(row=0, column=2, padx=10, pady=5)

        return file_controls_frame

    def set_virustotal_api_key(self):
        self.set_api_key("virustotal_api_key")

    def set_abuseipdb_api_key(self):
        self.set_api_key("abuseipdb_api_key")

    def set_api_key(self, key_name):
        key = simpledialog.askstring("API Key", f"Enter your {key_name.replace('_', ' ').title()}:")
        if key:
            if key_name == "virustotal_api_key":
                self.virustotal_api_key = key
            else:
                self.abuseipdb_api_key = key
            self.save_configuration()
            self.log_message(f"{key_name.replace('_', ' ').title()} set.")

    def save_configuration(self):
        try:
            config = {
                "virustotal_api_key": self.virustotal_api_key,
                "abuseipdb_api_key": self.abuseipdb_api_key,
            }
            with open("config.json", "w") as config_file:
                json.dump(config, config_file)
        except Exception as e:
            self.log_message(f"Error saving configuration: {e}")

    def load_input_file(self):
        self.input_file = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("CSV files", "*.csv"), ("Excel files", "*.xlsx"), ("JSON files", "*.json")])
        if self.input_file:
            try:
                if self.input_file.endswith('.txt'):
                    with open(self.input_file, 'r') as file:
                        lines = file.readlines()
                        self.total_ips = len(lines)
                elif self.input_file.endswith('.csv'):
                    df = pd.read_csv(self.input_file)
                    self.total_ips = len(df)
                elif self.input_file.endswith('.json'):
                    with open(self.input_file, 'r') as file:
                        data = json.load(file)
                        self.total_ips = len(data)
                self.scan_info_label.config(text=f"Total IPs: {self.total_ips}")
                self.log_message(f"Loaded {self.total_ips} IPs from {self.input_file}.")
            except Exception as e:
                self.log_message(f"Error loading file: {e}")

    def start_scan(self, scan_function):
        if not self.input_file:
            messagebox.showwarning("Warning", "Please load an input file first.")
            return
        if self.scan_running:
            messagebox.showwarning("Warning", "A scan is already in progress.")
            return
        self.scan_running = True
        self.scanned_ips = 0
        self.scan_results = []
        self.pause_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.NORMAL)
        self.progress['value'] = 0
        self.scan_info_label.config(text=f"Scanned IPs: 0 / {self.total_ips} | Remaining IPs: {self.total_ips} | 0% completed")
        self.scan_thread = threading.Thread(target=self.scan_ips, args=(scan_function,))
        self.scan_thread.start()

    def scan_ips(self, scan_function):
        with open(self.input_file, 'r') as file:
            ips = [line.strip() for line in file.readlines()]
            self.total_ips = len(ips)

            for ip in ips:
                if self.stop_flag:
                    self.log_message("Scan stopped.")
                    break
                while self.pause_flag:
                    time.sleep(1)

                self.scanned_ips += 1
                self.progress['value'] = (self.scanned_ips / self.total_ips) * 100
                self.scan_info_label.config(text=f"Scanned IPs: {self.scanned_ips} / {self.total_ips} | Remaining IPs: {self.total_ips - self.scanned_ips} | {self.progress['value']:.2f}% completed")

                # Call the scan function (either VirusTotal or AbuseIPDB)
                result = scan_function(ip)
                
                # Check if rate limit is hit
                if result == "Rate limit exceeded":
                    self.log_message("WARNING - Rate limit exceeded. Pausing scans.")
                    # Disable scan buttons
                    self.virustotal_button.config(state=tk.DISABLED)
                    self.abuseipdb_button.config(state=tk.DISABLED)
                    self.stop_flag = True  # Optionally stop the scan
                    break

                self.scan_results.append(result)
                self.log_message(f"Scanned {ip}: {result}")

            self.scan_running = False
            self.pause_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.DISABLED)
            self.stop_flag = False  # Reset the stop flag after scan ends


    def pause_scanning(self):
        self.pause_flag = not self.pause_flag
        self.pause_button.config(text="Resume" if self.pause_flag else "Pause")
        if not self.pause_flag:
            self.log_message("Resuming scan...")

    def stop_scanning(self):
        self.stop_flag = True
        self.log_message("Stopping scan...")

    def export_results(self):
        if not self.scan_results:
            messagebox.showwarning("Warning", "No results to export.")
            return

        self.output_file = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if self.output_file:
            df = pd.DataFrame(self.scan_results)
            df.to_csv(self.output_file, index=False)
            
            # Show a dialog box with the export confirmation message
            messagebox.showinfo("Export Successful", f"Results exported to {self.output_file}.")
            
            # Log the message if needed
            self.log_message(f"Exported results to {self.output_file}.")


    def view_history(self):
        history_window = tk.Toplevel(self.root)
        history_window.title("Scan History")
        history_window.geometry("600x400")

        # Create ScrolledText widget for history
        history_text = scrolledtext.ScrolledText(history_window, wrap=tk.WORD, font=("Consolas", 10))
        history_text.pack(expand=True, fill=tk.BOTH)

        # Add a scrollbar
        scrollbar = Scrollbar(history_window, command=history_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        history_text.config(yscrollcommand=scrollbar.set)

        # Populate history text with scan results
        if self.scan_results:
            history_text.insert(tk.END, "IP Address | Result\n")
            history_text.insert(tk.END, "-" * 50 + "\n")
            for result in self.scan_results:
                ip_address = result.get('ip_address', 'N/A')  # Adjust based on your result structure
                result_str = str(result)  # You might want to format this string better
                history_text.insert(tk.END, f"{ip_address} | {result_str}\n")
        else:
            history_text.insert(tk.END, "No scan results available.")

        history_text.configure(state='disabled')  # Make it read-only


    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    root = tk.Tk()
    app = IPReputationToolUI(root)
    app.run()
