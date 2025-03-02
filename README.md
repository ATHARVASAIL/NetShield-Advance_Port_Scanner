# Net Shield - Network Security Tool

Net Shield is a GUI-based network security tool built using Python. It allows users to perform port scanning, vulnerability checking, threat intelligence analysis, and generate detailed reports in PDF format. The tool is designed to be user-friendly, efficient, and visually appealing.

---

## Features

1. **Port Scanner**:
   - Scans a target IP for open ports.
   - Multi-threaded for fast and efficient scanning.
   - Displays open ports and errors encountered during scanning.

2. **Vulnerability Checker**:
   - Checks for known vulnerabilities on open ports.
   - Provides a list of vulnerabilities for each open port.

3. **Threat Intelligence**:
   - Fetches threat intelligence data using the VirusTotal API.
   - Displays information such as malicious votes, reputation, and network details.

4. **Report Generator**:
   - Generates a detailed PDF report containing:
     - Scan results.
     - Vulnerability details.
     - Threat intelligence data.
     - Visualized graph of vulnerabilities.

5. **Visualization**:
   - Displays a bar graph of vulnerabilities found during the scan.

6. **Modern GUI**:
   - Built using `ttkbootstrap` for a sleek and modern look.
   - Supports dark and light themes.

7. **Error Handling**:
   - Logs and displays errors encountered during scanning.

---

## Prerequisites

Before running the project, ensure you have the following installed:

1. **Python 3.8 or higher**:
   - Download and install Python from [python.org](https://www.python.org/downloads/).

2. **Required Libraries**:
   - Install the required libraries using the following command:
     ```bash
     pip install -r requirements.txt
     ```

3. **VirusTotal API Key**:
   - Sign up for a free API key at [VirusTotal](https://www.virustotal.com/).
   - Replace `YOUR_VIRUSTOTAL_API_KEY` in `threat_intelligence.py` with your actual API key.

---

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/net-shield.git
   cd net-shield

---

## NetShield/
    │
    ├── main.py                # Entry point of the application
    ├── port_scanner.py        # Handles port scanning
    ├── vulnerability_checker.py # Checks for vulnerabilities
    ├── report_generator.py    # Generates PDF reports
    ├── visualization.py       # Handles visualization of vulnerabilities
    ├── threat_intelligence.py # Fetches threat intelligence data
    ├── ui.py                  # Handles the GUI
    ├── requirements.txt       # Lists all dependencies
    └── README.md              # Project documentation

---

## Usage

1. **Enter Target IP:**
Enter the target IP address in the input field.

2. **Scan Ports:**
Click the Scan button to start scanning for open ports.

3. **View Results:**
The scan results, vulnerabilities, and errors (if any) will be displayed in the text area.

4. **Check Threat Intelligence:**
Click the Check Threat button to fetch threat intelligence data for the target IP.

5. **Generate Report:**
Click the Generate Report button to save the scan results, vulnerabilities, threat intelligence, and graph in a PDF file.

6. **Visualize Vulnerabilities:**
Click the Visualize button to view a bar graph of vulnerabilities.

7. **Toggle Theme:**
Use the Switch to Light Mode or Switch to Dark Mode button to change the theme.

## Screenshots
1. **Dark Mode**
![alt text](<Screenshot 2025-03-02 215810.png>)

2. **Light Mode**
![alt text](<Screenshot 2025-03-02 220227.png>)

3. **PDF Report**
![alt text](<Screenshot 2025-03-02 220307.png>)

---

## Acknowledgments
1. ttkbootstrap: For providing modern and customizable themes for the GUI.

2. VirusTotal: For providing the threat intelligence API.

3. Matplotlib: For creating visualizations.


