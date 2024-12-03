import csv
from collections import Counter

# Configurable threshold for failed login attempts, can be adjusted as per requirements
FAILED_LOGIN_THRESHOLD = 10

def parse_log_line(line):
    """
    Parses a single log line and extracts relevant information for analysis.
    - IP Address: The source IP making the request.
    - Endpoint: The requested endpoint (e.g., '/login').
    - Status Code: HTTP response code (e.g., '200', '401').
    - Failure Message: The message associated with the failed request (if any).
    
    Args:
    - line (str): A single line from the log file.
    
    Returns:
    - tuple: A tuple containing (ip_address, endpoint, status_code, failure_message)
    """
    parts = line.split(" ")  # Split the log line into parts using space as delimiter
    ip_address = parts[0]  # The first element is the IP address
    endpoint = parts[6]    # The 7th element is the requested endpoint
    status_code = parts[8] # The 9th element is the status code (HTTP response)
    # Failure message starts from the 11th part onwards (index 10)
    failure_message = " ".join(parts[10:]).strip() if len(parts) > 9 else ""
    
    return ip_address, endpoint, status_code, failure_message

def analyze_log(file_path):
    """
    Processes the log file and performs the necessary analysis.
    This includes counting the number of requests per IP, identifying the most accessed endpoint,
    and detecting suspicious activity (failed login attempts).
    
    Args:
    - file_path (str): The path to the log file.
    
    Returns:
    - tuple: Contains three counters (ip_requests, endpoint_requests, failed_logins)
    """
    ip_requests = Counter()     # To store the count of requests per IP address
    endpoint_requests = Counter()  # To store the count of requests per endpoint
    failed_logins = Counter()    # To store failed login attempts per IP address

    # Open and process the log file line by line
    with open(file_path, "r") as file:
        for line in file:
            ip_address, endpoint, status_code, failure_message = parse_log_line(line)
            
            # Update the counters with the extracted information
            ip_requests[ip_address] += 1
            endpoint_requests[endpoint] += 1
            
            # If status code is '401' (unauthorized) or the failure message indicates invalid credentials, increment failed logins
            if status_code == "401" or "Invalid credentials" in failure_message:
                failed_logins[ip_address] += 1

    return ip_requests, endpoint_requests, failed_logins

def save_to_csv(ip_requests, most_accessed, failed_logins, output_file="log_analysis_results.csv"):
    """
    Saves the analysis results to a CSV file. The CSV file contains:
    - IP address and their request counts.
    - Most accessed endpoint and the number of accesses.
    - Suspicious IP addresses (those exceeding the failed login threshold) and their failed login counts.
    
    Args:
    - ip_requests (Counter): A counter with IP addresses and their respective request counts.
    - most_accessed (tuple): A tuple containing the most accessed endpoint and its access count.
    - failed_logins (Counter): A counter with IP addresses and their respective failed login counts.
    - output_file (str): The output CSV file name (default is 'log_analysis_results.csv').
    """
    with open(output_file, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)

        # Write the IP address request counts
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_requests.items():
            writer.writerow([ip, count])

        # Add an empty row for space between sections
        writer.writerow([])

        # Write the most accessed endpoint
        writer.writerow(["Most Accessed Endpoint", "Access Count"])
        writer.writerow([most_accessed[0], most_accessed[1]])

        # Add an empty row for space between sections
        writer.writerow([])

        # Write suspicious IP addresses with failed login counts
        writer.writerow(["Suspicious IP Address", "Failed Login Count"])
        for ip, count in failed_logins.items():
            if count > FAILED_LOGIN_THRESHOLD:
                writer.writerow([ip, count])

def main():
    """
    Main function that orchestrates the log analysis.
    - Reads the log file.
    - Analyzes the log for IP request counts, most accessed endpoint, and suspicious failed logins.
    - Displays the results in the terminal.
    - Saves the analysis results to a CSV file.
    """
    log_file = "sample.log"  # Path to the log file (change this to your log file path)
    
    # Perform log analysis
    ip_requests, endpoint_requests, failed_logins = analyze_log(log_file)

    # Get the most accessed endpoint
    most_accessed = endpoint_requests.most_common(1)[0]  # Get the most accessed endpoint (returns a tuple (endpoint, count))

    # Display the IP request counts in a well-formatted manner
    print(f"{'IP Address':<20}Request Count")
    for ip, count in ip_requests.items():
        print(f"{ip:<20}{count}")

    # Display the most frequently accessed endpoint
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")

    # Display suspicious IP addresses based on failed login attempts exceeding the threshold
    print("\nSuspicious Activity Detected:")
    print(f"{'IP Address':<20}Failed Login Attempts")
    for ip, count in failed_logins.items():
        if count > FAILED_LOGIN_THRESHOLD:
            print(f"{ip:<20}{count}")

    # Save the results to a CSV file
    save_to_csv(ip_requests, most_accessed, failed_logins)

# Entry point of the script
if __name__ == "__main__":
    main()