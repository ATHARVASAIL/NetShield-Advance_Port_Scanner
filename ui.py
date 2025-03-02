import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import ttkbootstrap as tb
from port_scanner import PortScanner
from vulnerability_checker import VulnerabilityChecker
from report_generator import ReportGenerator
from threat_intelligence import ThreatIntelligence
from visualization import Visualizer

class NetShieldUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Net Shield")
        self.root.geometry("1200x800")
        self.style = tb.Style(theme="darkly") 

        self.configure_styles()

        self.target_ip = tk.StringVar()
        self.ports = list(range(1, 1025))
        self.scan_results = []
        self.vulnerabilities = {}
        self.threat_intel = None

        self.create_widgets()

    def configure_styles(self):
        """Configure styles for widgets based on the current theme."""
        self.style.configure("TButton", font=("Helvetica", 14), padding=10)
        self.style.configure("TLabel", font=("Helvetica", 16))
        self.style.configure("Header.TLabel", font=("Helvetica", 28, "bold"))
        self.style.configure("TProgressbar", thickness=20)

    def create_widgets(self):

        self.header_frame = tb.Frame(self.root, bootstyle="primary")
        self.header_frame.pack(fill="x", padx=10, pady=10)

        self.header_label = tb.Label(
            self.header_frame,
            text="Net Shield",
            style="Header.TLabel",
            bootstyle="inverse-primary"
        )
        self.header_label.pack(pady=10)

        self.theme_button = tb.Button(
            self.header_frame,
            text="Switch to Light Mode",
            command=self.toggle_theme,
            bootstyle="info",
            width=20
        )
        self.theme_button.pack(side="right", padx=10)

        self.input_frame = tb.Frame(self.root)
        self.input_frame.pack(fill="x", padx=10, pady=10)

        self.target_label = tb.Label(self.input_frame, text="Target IP:")
        self.target_label.grid(row=0, column=0, padx=5, pady=5)

        self.target_entry = tb.Entry(self.input_frame, textvariable=self.target_ip, width=30, font=("Helvetica", 14))
        self.target_entry.grid(row=0, column=1, padx=5, pady=5)

        self.scan_button = tb.Button(
            self.input_frame,
            text="Scan",
            command=self.start_scan,
            bootstyle="success",
            width=15
        )
        self.scan_button.grid(row=0, column=2, padx=5, pady=5)

        self.result_frame = tb.Frame(self.root)
        self.result_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.result_text = tk.Text(self.result_frame, height=20, width=80, font=("Helvetica", 14))
        self.result_text.pack(fill="both", expand=True, padx=5, pady=5)

        self.progress_frame = tb.Frame(self.result_frame)
        self.progress_frame.pack(fill="x", padx=10, pady=10)

        self.progress_bar = ttk.Progressbar(self.progress_frame, orient="horizontal", length=800, mode="determinate")
        self.progress_bar.pack(side="left", fill="x", expand=True)

        self.progress_label = tb.Label(self.progress_frame, text="0%", font=("Helvetica", 14))
        self.progress_label.pack(side="right", padx=10)

        self.button_frame = tb.Frame(self.root)
        self.button_frame.pack(fill="x", padx=10, pady=10)

        self.report_button = tb.Button(
            self.button_frame,
            text="Generate Report",
            command=self.generate_report,
            bootstyle="info",
            width=20
        )
        self.report_button.grid(row=0, column=0, padx=5, pady=5)

        self.visualize_button = tb.Button(
            self.button_frame,
            text="Visualize",
            command=self.visualize,
            bootstyle="warning",
            width=20
        )
        self.visualize_button.grid(row=0, column=1, padx=5, pady=5)

        self.threat_button = tb.Button(
            self.button_frame,
            text="Check Threat",
            command=self.check_threat,
            bootstyle="danger",
            width=20
        )
        self.threat_button.grid(row=0, column=2, padx=5, pady=5)

    def toggle_theme(self):
        """Toggle between dark and light themes and update widget styles."""
        current_theme = self.style.theme_use()
        if current_theme == "darkly":
            self.style.theme_use("cosmo")
            self.theme_button.config(text="Switch to Dark Mode")
        else:
            self.style.theme_use("darkly")
            self.theme_button.config(text="Switch to Light Mode")

        self.configure_styles()

    def start_scan(self):
        target = self.target_ip.get()
        if not target:
            messagebox.showerror("Error", "Please enter a target IP")
            return

        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, "Scanning...\n")

        self.progress_bar["value"] = 0
        self.progress_bar["maximum"] = len(self.ports)
        self.progress_label.config(text="0%")
        self.root.update_idletasks()

        scanner = PortScanner(target, self.ports)
        self.scan_results, errors = scanner.scan_ports(self.update_progress)

        self.result_text.insert(tk.END, "Scan Results:\n")
        for port in self.scan_results:
            self.result_text.insert(tk.END, f"Port {port}: Open\n")

        if errors:
            self.result_text.insert(tk.END, "\nScanning Errors:\n")
            for error in errors:
                self.result_text.insert(tk.END, f"{error}\n")

        checker = VulnerabilityChecker(self.scan_results)
        self.vulnerabilities = checker.check_vulnerabilities()

        self.result_text.insert(tk.END, "\nVulnerabilities:\n")
        for port, vuln in self.vulnerabilities.items():
            self.result_text.insert(tk.END, f"Port {port}: {vuln}\n")

    def update_progress(self):
        """Update the progress bar and percentage label after each port is scanned."""
        self.progress_bar["value"] += 1
        progress_percent = int((self.progress_bar["value"] / self.progress_bar["maximum"]) * 100)
        self.progress_label.config(text=f"{progress_percent}%")
        self.root.update_idletasks()

    def generate_report(self):
        if not self.scan_results:
            messagebox.showerror("Error", "No scan results to generate report")
            return

        filename = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF Files", "*.pdf")])
        if filename:
            report_gen = ReportGenerator(self.scan_results, self.vulnerabilities, self.threat_intel)
            report_gen.generate_report(filename)
            messagebox.showinfo("Success", f"Report generated: {filename}")

    def visualize(self):
        if not self.vulnerabilities:
            messagebox.showerror("Error", "No vulnerabilities to visualize")
            return

        visualizer = Visualizer(self.scan_results, self.vulnerabilities)
        visualizer.plot_results()

    def check_threat(self):
        target = self.target_ip.get()
        if not target:
            messagebox.showerror("Error", "Please enter a target IP")
            return

        threat_checker = ThreatIntelligence(target)
        self.threat_intel = threat_checker.check_threat()
        self.result_text.insert(tk.END, "\nThreat Intelligence:\n")
        for key, value in self.threat_intel.items():
            self.result_text.insert(tk.END, f"{key}: {value}\n")

if __name__ == "__main__":
    root = tb.Window(themename="darkly")
    app = NetShieldUI(root)
    root.mainloop()