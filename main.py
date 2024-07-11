# This is a sample Python script.

# Press ⌃R to execute it or replace it with your code.
# Press Double ⇧ to search everywhere for classes, files, tool windows, actions, and settings.

import requests
from fnmatch import fnmatch
import re
import os
import json
from requests.adapters import HTTPAdapter, Retry

# shared session for all requests
request_session = requests.Session()
retries = Retry(total=5, backoff_factor=2)
request_session.mount('https://', HTTPAdapter(max_retries=retries))
# s.get("http://httpstat.us/503")

# get env vars
KEY = os.environ.get('KEY')

def parse_file_ioc(input_file_path):
    ips = []
    # check for unauthorized attempts against the server
    # with open(input_file_path) as file:
    #     for line in file:
    #         line = line.rstrip()
    #         if fnmatch(line, '* Invalid user * from *'):
    #             print(line)
    #             ips.append(line)
    regex_pattern = re.compile(".* Invalid user .* from (.*)")
    with open(input_file_path) as file:
        for line in file:
            line = line.rstrip()
            result = regex_pattern.search(line)
            if result:
                ip = result.group(1)
                print(line)
                print(ip)
                ips.append(ip)
    # dedup ips
    ips = list(set(ips))
    print(ips)
    return ips




def query_virus_total(ips):

    iocs = []
    for ip in ips:
    #     url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    # headers = {"accept": "application/json"}
    # response = requests.get(url, headers=headers)
    # print(response.text)

        ioc = get_threat_intel(ip)

        iocs.append(ioc)

    return {'indicators': iocs}


def get_threat_intel(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"accept": "application/json", "X-Apikey": KEY}

    response = request_session.get(url, headers=headers)
    response_json = response.json()
    print(response.text)
    # {'error': {'code': 'AuthenticationRequiredError', 'message': 'X-Apikey header is missing'}}
    if response_json.get('error'):
        raise Exception('There was an error')
    ioc = _extract_info(response.json())
    return ioc


def _extract_info(response_json):
    """
    output: {
        "value": "4.4.4.4",
        "type": "ip",
        "providers": [
            {
                "provider": "VirusTotal",
                "verdict": "malicious",
                "score": "90/100"
            },
            {
                "provider": "OTX",
                "verdict": "not malicious"
            }
        ]
    }
    """

    value = response_json['data']['id']
    print(f'value is {value}')
    _type = response_json['data']['type']
    if _type == 'ip_address':
        _type = 'ip'
    print(f'_type is {_type}')

    # process verdict
    harmless_score = response_json['data']['attributes']['last_analysis_stats']['harmless']
    print(f'harmless_score is {harmless_score}')
    malicious_score = response_json['data']['attributes']['last_analysis_stats']['malicious']
    print(f'malicious_score is {malicious_score}')
    total_score = harmless_score + malicious_score
    if total_score != 0:
        harmless_percent = float(harmless_score) / float(total_score) * 100
    else:
        harmless_percent = 100 # no harmless nor malicious score will be treated as harmless
    print(f'harmless_percent is {harmless_percent}')

    score = f'{harmless_score}/{total_score}'
    print(f'score is {score}')

    if harmless_percent > 50:
        verdict = 'harmless'
    else:
        verdict = 'malicious'
    print(f'verdict is {verdict}')

    ioc = {
        'value': value,
        'type': _type,
        'providers': [
            {
                'provider': 'VirusTotal',
                'verdict': verdict,
                'score': score
            }
        ]

    }
    return ioc


def main(input_file_path):
    ips = parse_file_ioc(input_file_path)
    iocs = query_virus_total(ips)
    print(json.dumps(iocs, indent=4))
    with open('final_results.json', 'w') as f:
        json.dump(iocs, f, indent=2)


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    input_file_path = './input.txt'
    main(input_file_path)


