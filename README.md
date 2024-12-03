# Log Analysis Script

This repository contains a Python script that processes a log file to identify suspicious activity, such as failed login attempts, most accessed endpoints, and general request counts by IP address. The results are printed in the terminal and saved to a CSV file.

### Note:
The `sample.log` file initially contained around 34 log entries. Later, additional log entries were added for testing purposes. These entries are intended to simulate a larger dataset, ensuring the script works effectively on larger logs and demonstrates the full range of functionality. 

## Features

- Counts the number of requests from each IP address
- Identifies the most accessed endpoint
- Detects suspicious IP addresses based on failed login attempts (status code `401` or failure message indicating invalid credentials)
- Outputs the results in the terminal and saves them to a CSV file

## Installation and Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/katakampranav/Log-Analysis-Script
   ```

2. **Install dependencies** (if necessary): 
   If you don't have `collections` or `csv` installed (unlikely, since they are part of Python's standard library), you can install them manually by running:
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure the log file**: 
   Replace the `sample.log` file with your actual log file if needed. The script assumes that the log file is formatted with space-separated values, with the IP address in the first column, the endpoint in the 7th column, and the status code in the 9th column.

## Running the Script

To run the script, execute the following command:
```bash
python log_analysis.py
```

## Example Output in the Terminal

The script will print the analysis results to the terminal. Below is an example of the output:
```
IP Address    Request Count
192.168.1.1   15
10.0.0.2      8
172.16.0.3    22

Most Frequently Accessed Endpoint:
/login (Accessed 26 times)

Suspicious Activity Detected:
IP Address    Failed Login Attempts
192.168.1.1   12
172.16.0.3    15
```

### Example Output on Personal Laptop

Below is a screenshot of the script running successfully in my personal laptop, demonstrating its functionality in analyzing the log file and producing the expected results:

![Log Analysis Output](https://github.com/user-attachments/assets/1156ecae-16fe-4862-a4dd-f83ccf812d8d)


## Example CSV Output

The script generates a CSV file (`log_analysis_results.csv`) with the following structure:
```
IP Address,Request Count
192.168.1.1,15
203.0.113.5,18
10.0.0.2,12
198.51.100.23,18
192.168.1.100,9

Most Accessed Endpoint,Access Count
/login,26

Suspicious IP Address,Failed Login Count
203.0.113.5,17
```

## Customization

- **Threshold for Failed Login Attempts**: Adjust the threshold for suspicious IP addresses by modifying the `FAILED_LOGIN_THRESHOLD` constant in the script.
- **Log File Path**: Update the `log_file` variable in the `main()` function to point to your actual log file.

## Author

This Log Analysis Script was developed by :
-	[@katakampranav](https://github.com/katakampranav)
-	Repository : https://github.com/katakampranav/Log-Analysis-Script

## Feedback

For any feedback or queries, please reach out to me at katakampranavshankar@gmail.com.
