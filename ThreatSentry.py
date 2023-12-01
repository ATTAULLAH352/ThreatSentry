import re
import subprocess
import json

def extract_foreign_addresses():
    try:
        # Run netstat command and capture the output
        netstat_output = subprocess.check_output(['netstat', '-ano'], universal_newlines=True)

        # Use regular expression to extract Foreign Addresses
        foreign_address_matches = re.findall(r'\d+\.\d+\.\d+\.\d+', netstat_output)

        # Remove duplicate addresses
        unique_foreign_addresses = list(set(foreign_address_matches))

        # Print and return the result
        print("Foreign Addresses extracted:")
        print(unique_foreign_addresses)

        return unique_foreign_addresses

    except Exception as e:
        print(f"An error occurred during IP address extraction: {e}")
        return []

def save_addresses_to_file(addresses, filename='foreign_addresses.txt'):
    try:
        with open(filename, 'w') as file:
            for address in addresses:
                file.write(address + '\n')

        print(f"Foreign Addresses saved to '{filename}'")

    except Exception as e:
        print(f"An error occurred during file saving: {e}")

def check_virustotal(ip_addresses, api_key):
    for ip_address in ip_addresses:
        try:
            print(f"Checking {ip_address} with VirusTotal:")
            
            # Use curl to make the API request
            curl_command = [
                "curl",
                f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}',
                '-H', f'x-apikey: {api_key}'
            ]

            # Run the curl command and capture the output
            result = subprocess.run(curl_command, capture_output=True, text=True)

            # Parse the JSON response
            data = json.loads(result.stdout)
            print(json.dumps(data, indent=2))
        except Exception as e:
            print(f"An error occurred during VirusTotal check for {ip_address}: {e}")

if __name__ == "__main__":
    # Provide your VirusTotal API key
    api_key = "390d7d312ce7384e23d1775d492a3877908104c71eb2a8689c4777e8557292f3"

    # Extract and save Foreign Addresses
    foreign_addresses = extract_foreign_addresses()
    save_addresses_to_file(foreign_addresses)

    # Check each IP address with VirusTotal
    check_virustotal(foreign_addresses, api_key)
