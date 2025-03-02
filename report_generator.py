from fpdf import FPDF
import matplotlib.pyplot as plt
import os

class ReportGenerator:
    def __init__(self, scan_results, vulnerabilities, threat_intel=None):
        self.scan_results = scan_results
        self.vulnerabilities = vulnerabilities
        self.threat_intel = threat_intel

    def generate_report(self, filename="report.pdf"):
        pdf = FPDF()
        pdf.add_page()
        pdf.set_auto_page_break(auto=True, margin=15)

        pdf.set_font("Arial", size=24, style="B")
        pdf.cell(200, 10, txt="Net Shield Scan Report", ln=True, align="C")
        pdf.ln(20)

        pdf.set_font("Arial", size=16, style="B")
        pdf.cell(200, 10, txt="Scan Results:", ln=True)
        pdf.set_font("Arial", size=12)
        for port in self.scan_results:
            pdf.cell(200, 10, txt=f"Port {port}: Open", ln=True)

        pdf.set_font("Arial", size=16, style="B")
        pdf.cell(200, 10, txt="Vulnerabilities:", ln=True)
        pdf.set_font("Arial", size=12)
        for port, vuln in self.vulnerabilities.items():
            pdf.cell(200, 10, txt=f"Port {port}: {vuln}", ln=True)

        if self.threat_intel:
            pdf.set_font("Arial", size=16, style="B")
            pdf.cell(200, 10, txt="Threat Intelligence:", ln=True)
            pdf.set_font("Arial", size=12)
            for key, value in self.threat_intel.items():
                pdf.multi_cell(200, 10, txt=f"{key}: {value}")

        self._plot_results()
        pdf.image("vulnerabilities.png", x=10, y=pdf.get_y(), w=180)
        os.remove("vulnerabilities.png")
        
        pdf.output(filename)
        print(f"Report generated: {filename}")

    def _plot_results(self):
        plt.figure(figsize=(10, 5))
        plt.bar(self.vulnerabilities.keys(), [1] * len(self.vulnerabilities), color='red')
        plt.title("Vulnerabilities Found")
        plt.xlabel("Ports")
        plt.ylabel("Vulnerability Count")
        plt.savefig("vulnerabilities.png", bbox_inches='tight')
        plt.close()