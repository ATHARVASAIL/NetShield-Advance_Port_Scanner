import requests

class ThreatIntelligence:
    def __init__(self, ip):
        self.ip = ip
        self.api_key = "e2920ff03568f132d9e1fe8629b95f91312c33d2e5211e227441796214033c76"

    def check_threat(self):
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{self.ip}"
        headers = {"x-apikey": self.api_key}
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            return self._parse_threat_data(data)
        else:
            return {"error": "Unable to fetch threat intelligence"}

    def _parse_threat_data(self, data):
        parsed_data = {}
        attributes = data.get("data", {}).get("attributes", {})

        parsed_data["IP"] = self.ip
        parsed_data["Harmless Votes"] = attributes.get("last_analysis_stats", {}).get("harmless", 0)
        parsed_data["Malicious Votes"] = attributes.get("last_analysis_stats", {}).get("malicious", 0)
        parsed_data["Suspicious Votes"] = attributes.get("last_analysis_stats", {}).get("suspicious", 0)
        parsed_data["Reputation"] = attributes.get("reputation", "Unknown")
        parsed_data["Country"] = attributes.get("country", "Unknown")
        parsed_data["Network"] = attributes.get("network", "Unknown")

        return parsed_data