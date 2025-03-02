import matplotlib.pyplot as plt

class Visualizer:
    def __init__(self, open_ports, vulnerabilities):
        self.open_ports = open_ports
        self.vulnerabilities = vulnerabilities

    def plot_results(self):
        plt.figure(figsize=(10, 5))
        plt.bar(self.vulnerabilities.keys(), [1] * len(self.vulnerabilities), color='red')
        plt.title("Vulnerabilities Found")
        plt.xlabel("Ports")
        plt.ylabel("Vulnerability Count")
        plt.show()