import json
from datetime import datetime, timedelta
import requests
import re


def lambda_handler(event, context):
    # Set the end date to the current date
    end_date = datetime.now()

    # Calculate the start date as 2 years before the end date
    start_date = end_date - timedelta(days=2*365)

    # Format the dates as strings
    end_date_str = end_date.strftime('%Y-%m-%d')
    start_date_str = start_date.strftime('%Y-%m-%d')

    # API details
    vulncheck_token = "vulncheck_7072f9a55daccd4b463cc7bf4fd2cf73f8258befa87f86fa5b21adc02bbffec3"
    url_nist = "https://api.vulncheck.com/v3/index/nist-nvd2"
    epss_base_url = "https://api.first.org/data/v1/epss"

    headers = {
        "accept": "application/json",
        "authorization": f"Bearer {vulncheck_token}"
    }

    # Define the parameters with the start and end dates
    params = {
        "start_date": start_date_str,
        "end_date": end_date_str,
        "page": 1,  # Start with the first page
        "page_size": 100  # Number of results per page
    }

    # Define the tech stack
    tech_stack = [
        "C/C++", "GraphQL", "Flask", "PHP", "Ruby on Rails", "Java", "Python", "LabVIEW",
        "WordPress", "Kubernetes", "Raspberry Pi", "Vue.js", "Sass", "Lighttpd", "Docker",
        "Cairo", "Mathematica", "SAS", "Laravel", "Swift", "Heroku", "AWS", "C#", "Express.js",
        "App Inventor", "Kotlin", "IBM WebSphere Application Server", "Blockly", "Flutter",
        "Tomcat", "CircleCI", "Terraform", "Go (Golang)", "OPS5", "Prolog", "JSON", "Mercury",
        "Firebase", "Django", "Vyper", "Haskell", "SQL", "NoSQL", "Ansible", "Visual Basic", "NGINX",
        "Oracle WebLogic Server", "Solidity", "MATLAB", "Azure", "GitLab CI/CD", "JavaScript",
        "Elasticsearch", "React", "Jenkins", "Apache Kafka", "Rust", "TensorFlow", "Redis",
        "Huff Language", "GCP", "Git", "Microsoft IIS", "Node.js", "Spring Boot", "Julia",
        "Travis CI", "Scratch", "Move"
    ]

    # Function to fetch data for a given page from a given URL
    def fetch_all_data(url):
        all_data = []
        page = 1
        while True:
            params["page"] = page
            response = requests.get(url, headers=headers, params=params)
            if response.status_code == 200:
                data = response.json().get('data', [])
                if not data:
                    break
                all_data.extend(data)
                page += 1
            else:
                print(f"Failed to retrieve data: {response.status_code} - {response.text}")
                break
        return all_data

    # Function to find tech stack matches in the description
    def find_tech_stack(description):
        matches = []
        for tech in tech_stack:
            if re.search(r'\b' + re.escape(tech) + r'\b', description, re.IGNORECASE):
                matches.append(tech)
        return matches

    # Fetch data from NIST endpoint
    data_nist = fetch_all_data(url_nist)

    # Create a dictionary to combine data based on CVE
    combined_data = {}

    # Process NIST data and merge metrics
    for item in data_nist:
        cve = item.get("id")  # Use "id" field as the CVE identifier in NIST data
        description = item.get("descriptions", [{}])[0].get("value", "")
        if cve not in combined_data:
            combined_data[cve] = {
                "description": description,
                "metrics": [],  # Initialize metrics as an empty list
                "epss": None,   # Initialize EPSS score as None
                "risk": None,   # Initialize risk score as None
                "riskLevel": None,  # Initialize risk level as None
                "techstack": [] # Initialize tech stack matches as an empty list
            }
        cvss_metrics = item.get("metrics", {}).get("cvssMetricV31", [])
        for metric in cvss_metrics:
            combined_data[cve]["metrics"].append({
                "source": metric.get("source"),
                "type": metric.get("type"),
                "cvssData": metric.get("cvssData"),
                "exploitabilityScore": metric.get("exploitabilityScore"),
                "impactScore": metric.get("impactScore")
            })
        combined_data[cve]["techstack"] = find_tech_stack(description)

    # Get EPSS scores for CVEs
    cve_list = list(combined_data.keys())
    cve_batches = [cve_list[i:i+100] for i in range(0, len(cve_list), 100)]  # Batch CVEs by 100

    for batch in cve_batches:
        epss_response = requests.get(f"{epss_base_url}?cve={','.join(batch)}").json()
        for entry in epss_response.get('data', []):
            cve = entry['cve']
            epss_score = float(entry['epss'])  # Convert EPSS score to float
            if cve in combined_data:
                combined_data[cve]["epss"] = epss_score

                # Calculate the risk score
                impact_scores = [float(metric["impactScore"]) for metric in combined_data[cve]["metrics"] if metric["impactScore"] is not None]
                if impact_scores:
                    average_impact_score = sum(impact_scores) / len(impact_scores)
                    risk_score1 = (average_impact_score / 6)
                    risk_score = epss_score * risk_score1
                    combined_data[cve]["risk"] = f"{round(risk_score * 100, 2)}%"  # Express as percentage with "%" sign

                    # Determine risk level
                    risk_percentage = risk_score * 100
                    if risk_percentage >= 81:
                        risk_level = "Critical"
                    elif risk_percentage >= 61:
                        risk_level = "High"
                    elif risk_percentage >= 31:
                        risk_level = "Medium"
                    else:
                        risk_level = "Low"
                    combined_data[cve]["riskLevel"] = risk_level

    # Add sequential IDs
    for idx, (cve, details) in enumerate(combined_data.items(), start=1):
        details["id"] = f"{idx:03d}"

    # Convert combined data to a list for pretty printing
    combined_data_list = [{"cve": cve, **details} for cve, details in combined_data.items()]

    # Define the output file path
    output_file_path = "/tmp/cve_data_output.json"

    # Write the data to a file
    with open(output_file_path, 'w') as file:
        json.dump(combined_data_list, file, indent=4)

    return {
        'statusCode': 200,
        'body': json.dumps(f"Data has been written to {output_file_path}")
    }
