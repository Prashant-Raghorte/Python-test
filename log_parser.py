import re

def parse_log(log_string):
    # Define a pattern to match key-value pairs
    pattern = re.compile(r'(\w+)=("[^"]+"|\S+)')
    
    # Initialize the dictionary to hold the parsed data
    parsed_data = {}
    
    # Iterate over all matches found in the log_string
    for match in pattern.finditer(log_string):
        key, value = match.groups()
        # Remove any surrounding quotes from the value
        value = value.strip('"')
        parsed_data[key] = value
    
    return parsed_data

log_string = (
    'SAC:0|Sacumen|CAAS|2021.2.0|3|MALICIOUS|High|'
    'cat=C2 cs1Label=subcat cs1=DNS_TUNNELING cs2Label=vueUrls '
    'cs2=https://aws-dev.sacdev.io/alerts?filter=alertId%3D%3D81650 '
    'cs3Label=Tags cs3=USA,Finance cs4Label=Url '
    'cs4=https://aws-dev.sacdev.io/settings/tir?rules.sort=4%3A1&filter=state%3D%3D2&selected=9739323 '
    'cn1Label=severityScore cn1=900 '
    'msg="Malicious activity was reported in CAAS= A threat intelligence rule has been automatically created in DAAS." '
    'dhost=bad.com dst=1.1.1.1'
)

parsed_output = parse_log(log_string)
print("Final Response:- ",parsed_output)
