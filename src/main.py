import os
import re
from xml.etree import ElementTree as ET

def check_log4j_vulnerabilities_in_file(content):
    # CVE scores
    cve_scores = {
        "CVE-2021-44228": 10.0,
        "CVE-2022-23307": 10.0,
        "CVE-2019-17571": 9.8,
        "CVE-2022-23305": 9.1,
        "CVE-2021-45046": 9.0,
        "CVE-2022-23302": 9.0,
        "CVE-2021-45105": 7.5,
        "CVE-2020-9488": 7.5,
        "CVE-2021-4104": 7.5,
        "CVE-2021-44832": 6.6,
        "Potential misconfiguration": 5.0
    }

    # Patterns to search for
    vulnerabilities = {
        "Vulnerable Log4j v2 version": {
            "pattern": re.compile(r'(log4j\-(2\.(0|1[0-6]|17\.[01])(\.\d+)?(?!\.2)(?!\.4))\.jar)'),
            "xml_pattern": re.compile(r'<cp>[^<]*?(log4j-api\-(2\.(0|1[0-6]|17\.[01])(\.\d+)?(?!\.2)(?!\.4)))[^<]*?</cp>'),
            "CVE": ["CVE-2021-44228", "CVE-2021-45046", "CVE-2021-45105", "CVE-2021-44832"]
        },
        "Log4j v1 found, which is vulnerable": {
            "pattern": re.compile(r'log4j\-1\.[0-9]+\.[0-9]+'),
            "CVE": ["CVE-2019-17571", "CVE-2020-9488", "CVE-2021-4104", "CVE-2022-23302", "CVE-2022-23305", "CVE-2022-23307"]
        },
        "SocketServer found, possible vulnerability": {
            "pattern": re.compile(r'org\.apache\.log4j\.net\.SocketServer'),
            "CVE": ["CVE-2019-17571"]
        },
        "SMTPAppender found, possible vulnerability": {
            "pattern": re.compile(r'org\.apache\.log4j\.net\.SMTPAppender'),
            "CVE": ["CVE-2020-9488"]
        },
        "JMSAppender found, possible vulnerability": {
            "pattern": re.compile(r'org\.apache\.log4j\.net\.JMSAppender'),
            "CVE": ["CVE-2021-4104"]
        },
        "JMSSink found, possible vulnerability": {
            "pattern": re.compile(r'org\.apache\.log4j\.net\.JMSSink'),
            "CVE": ["CVE-2022-23302"]
        },
        "JDBCAppender found, possible vulnerability": {
            "pattern": re.compile(r'org\.apache\.log4j\.jdbc\.JDBCAppender'),
            "CVE": ["CVE-2022-23305"]
        },
        "Chainsaw component found, possible vulnerability": {
            "pattern": re.compile(r'org\.apache\.log4j\.chainsaw'),
            "CVE": ["CVE-2022-23307"]
        },
        "Suspicious configuration pattern found: logger.addAppender": {
            "pattern": re.compile(r'logger\.addAppender'),
            "CVE": ["Potential misconfiguration"]
        },
        "Suspicious configuration pattern found: log4j.additivity": {
            "pattern": re.compile(r'log4j\.additivity'),
            "CVE": ["Potential misconfiguration"]
        }
    }

    found_vulnerabilities = []

    # Check for all vulnerabilities
    for description, details in vulnerabilities.items():
        match = details["pattern"].search(content)
        if match:
            version = match.group(0)
            for cve in details["CVE"]:
                found_vulnerabilities.append((description, version, cve, cve_scores.get(cve, 0)))
        if "xml_pattern" in details:
            xml_match = details["xml_pattern"].search(content)
            if xml_match:
                version = xml_match.group(0)
                for cve in details["CVE"]:
                    found_vulnerabilities.append((description, version, cve, cve_scores.get(cve, 0)))

    return found_vulnerabilities

def check_config_file_for_vulnerable_versions(file_path):
    vulnerable_versions = {
        "log4j-core": ["2.0.0", "2.1.0", "2.2.0", "2.3.0", "2.4.0", "2.5.0", "2.6.0", "2.7.0", "2.8.0", "2.9.0", "2.10.0", "2.11.0", "2.12.0", "2.13.0", "2.14.0", "2.14.1", "2.15.0", "2.16.0", "2.17.0", "2.17.1"],
        "log4j-api": ["2.0.0", "2.1.0", "2.2.0", "2.3.0", "2.4.0", "2.5", "2.6.0", "2.7.0", "2.8", "2.9", "2.10", "2.11", "2.12", "2.13", "2.14.0", "2.14.1", "2.15.0", "2.16.0", "2.17.0", "2.17.1"],
       "log4j": [
            "1.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4", 
            "1.1", "1.1b1", "1.1b2", "1.1b3", "1.1b4", 
            "1.1b5", "1.1b6", "1.1b7", "1.1.1", "1.1.2", 
            "1.1.3", "1.2", "1.2.1", "1.2.2", "1.2.3", 
            "1.2.4", "1.2.5", "1.2.6", "1.2.7", "1.2.8", 
            "1.2.9", "1.2.10", "1.2.11", "1.2.12", "1.2.13", 
            "1.2.14", "1.2.15", "1.2.16", "1.2.17"
        ]
    }
    cve_scores = {
        "CVE-2021-44228": 10.0,
        "CVE-2022-23307": 10.0,
        "CVE-2019-17571": 9.8,
        "CVE-2022-23305": 9.1,
        "CVE-2021-45046": 9.0,
        "CVE-2022-23302": 9.0,
        "CVE-2021-45105": 7.5,
        "CVE-2020-9488": 7.5,
        "CVE-2021-4104": 7.5,
        "CVE-2021-44832": 6.6,
        "Potential misconfiguration": 5.0
    }

    found_vulnerabilities = []

    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        namespace = {'m': 'http://maven.apache.org/POM/4.0.0'}
        
        for dependency in root.findall('.//m:dependency', namespace):
            group_id = dependency.find('m:groupId', namespace)
            artifact_id = dependency.find('m:artifactId', namespace)
            version = dependency.find('m:version', namespace)
            
            if group_id is not None and artifact_id is not None and version is not None:
                group_id_text = group_id.text
                artifact_id_text = artifact_id.text
                version_text = version.text

                if artifact_id_text in vulnerable_versions and version_text in vulnerable_versions[artifact_id_text]:
                    cves = {
                        "log4j-core": ["CVE-2021-44228", "CVE-2021-45046", "CVE-2021-45105", "CVE-2021-44832"],
                        "log4j-api": ["CVE-2021-44228", "CVE-2021-45046", "CVE-2021-45105", "CVE-2021-44832"],
                        "log4j": ["CVE-2019-17571", "CVE-2020-9488", "CVE-2021-4104", "CVE-2022-23302", "CVE-2022-23305", "CVE-2022-23307"]
                    }
                    for cve in cves[artifact_id_text]:
                        found_vulnerabilities.append((f"Vulnerable {artifact_id_text} version: {version_text}", version_text, cve, cve_scores.get(cve, 0)))

    except ET.ParseError as e:
        print(f"Could not parse {file_path}: {e}")
    
    return found_vulnerabilities

def check_log4j_vulnerabilities_in_directory(directory_path):
    all_vulnerabilities = []

    for root, _, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            print(f"Scanning file: {file_path}")
            try:
                if (file == 'pom.xml' or file == 'build.gradle' or file == 'config.xml'):
                    vulnerabilities = check_config_file_for_vulnerable_versions(file_path)
                else:
                    with open(file_path, 'r', errors='ignore') as f:
                        content = f.read()
                        vulnerabilities = check_log4j_vulnerabilities_in_file(content)
                
                if vulnerabilities:
                    all_vulnerabilities.append((file_path, vulnerabilities))
            except Exception as e:
                print(f"Could not read file {file_path}: {e}")

    if not all_vulnerabilities:
        print("No vulnerabilities found.")
        return

    # Sort by CVE score
    sorted_vulnerabilities = sorted(
        all_vulnerabilities,
        key=lambda x: max(v[2] for v in x[1]),
        reverse=True
    )

    # Print the results
    print("Vulnerabilities found:")
    for file_path, vulnerabilities in sorted_vulnerabilities:
        print(f"File: {file_path}")
        for description, version, cve, score in vulnerabilities:
            recommendation = get_patch_recommendation(version, cve)
            print(f"  - {description} ({version}): {cve} (Score: {score})")
            print(f"    Recommendation: {recommendation}")

def get_patch_recommendation(version, cve):
    recommendations = {
        "CVE-2021-44228": "Upgrade to Log4j 2.17.1 or later. If upgrading is not possible, mitigate by setting the system property log4j2.formatMsgNoLookups to true or removing the JndiLookup class from the classpath.",
        "CVE-2021-45046": "Upgrade to Log4j 2.17.0 or later. This vulnerability is an extension of CVE-2021-44228 and requires an update to mitigate the risks effectively.",
        "CVE-2021-45105": "Upgrade to Log4j 2.17.0 or later. This vulnerability is related to uncontrolled recursion from self-referential lookups and needs to be addressed by updating.",
        "CVE-2021-44832": "Upgrade to Log4j 2.17.1 or later. This vulnerability affects Log4j 2.0-beta9 to 2.17.0 and involves a remote code execution vulnerability due to improper configuration.",
        "CVE-2019-17571": "Upgrade to Log4j 2.8.2 or later. This vulnerability affects Log4j 1.x and allows deserialization of untrusted data, leading to remote code execution. Can mitigate by deleting SocketServer.class from the jar.",
        "CVE-2020-9488": "Upgrade to Log4j 2.13.2 or later. This vulnerability involves a misconfiguration that could lead to a denial of service or remote code execution.",
        "CVE-2021-4104": "This affects Log4j 1.x versions. Since Log4j 1.x is no longer supported, the best course of action is to upgrade to Log4j 2.x. If upgrading is not possible, ensure that the JMSAppender is not configured in your logging configuration files.",
        "CVE-2022-23302": "Upgrade to Log4j 2.17.1 or later. This vulnerability allows a remote attacker to execute code via a crafted input.",
        "CVE-2022-23305": "Upgrade to Log4j 2.17.1 or later. This vulnerability allows for a denial of service (DoS) through uncontrolled recursion and should be mitigated by updating.",
        "CVE-2022-23307": "Upgrade to Log4j 2.17.1 or later. This critical vulnerability allows for remote code execution and should be addressed immediately.",
        "Potential misconfiguration": "Review your Log4j configuration files and ensure that they follow best practices. Remove unnecessary appenders, set proper logging levels, avoid using deprecated configurations, and ensure sensitive data is not logged. Additionally, make sure to follow the security guidelines provided by the Log4j maintainers to prevent any misconfigurations that could lead to security vulnerabilities."
    }
    return recommendations.get(cve, "No recommendation available for the specified CVE.")

cve_scores = {
    "CVE-2021-44228": 10.0,
    "CVE-2022-23307": 10.0,
    "CVE-2019-17571": 9.8,
    "CVE-2022-23305": 9.1,
    "CVE-2021-45046": 9.0,
    "CVE-2022-23302": 9.0,
    "CVE-2021-45105": 7.5,
    "CVE-2020-9488": 7.5,
    "CVE-2021-4104": 7.5,
    "CVE-2021-44832": 6.6,
    "Potential misconfiguration": 5.0
}

# Sort CVEs by score in descending order
sorted_cves = sorted(cve_scores.items(), key=lambda item: item[1], reverse=True)

# Print recommendations based on sorted CVEs
for cve, score in sorted_cves:
    print(f"CVE: {cve}, Score: {score}")
    print(f"Recommendation: {get_patch_recommendation(None, cve)}\n")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Scan a directory for Log4j vulnerabilities.')
    parser.add_argument('directory', type=str, help='The source directory to scan for vulnerabilities.')
    args = parser.parse_args()

    check_log4j_vulnerabilities_in_directory(args.directory)
