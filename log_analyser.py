import re
from collections import defaultdict, Counter
import pandas as pd

# ===============================
# Config & Regex
# ===============================

LOG_FILE = "sample-log.log"

# Regex pattern to parse each log line
log_pattern = re.compile(
    r'(?P<ip>\S+) - (?P<country>\S+) - \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<endpoint>\S+) HTTP/1.1" '
    r'(?P<status>\d{3}) \d+ "-" "(?P<user_agent>[^"]+)" (?P<response_time>\d+)'
)

# ===============================
# Log Parsing
# ===============================

data = []

with open(LOG_FILE, "r", encoding="utf-8") as f:
    for line in f:
        match = log_pattern.search(line)
        if match:
            data.append(match.groupdict())

df = pd.DataFrame(data)

# ===============================
# Type Conversion
# ===============================

df['status'] = df['status'].astype(int)
df['response_time'] = df['response_time'].astype(int)

# ===============================
# Analysis & Insights
# ===============================

# 1. Top IPs making the most requests (can indicate scraping or DDoS)
print("\n--- Top IPs by Request Count ---")
print(df['ip'].value_counts().head(10))

# 2. Request volume by country
print("\n--- Requests per Country ---")
print(df['country'].value_counts())

# 3. Most commonly accessed endpoints (identify popular content)
print("\n--- Most Common Endpoints ---")
print(df['endpoint'].value_counts().head(10))

# 4. Endpoints with highest average response time (identify bottlenecks)
print("\n--- Top 5 Slowest Endpoints (avg response time) ---")
print(df.groupby('endpoint')['response_time'].mean().sort_values(ascending=False).head(5))

# 5. HTTP status code distribution (help identify errors, login failures)
print("\n--- Status Code Distribution ---")
print(df['status'].value_counts())

# 6. Rare user-agents (less than 3 requests) - can indicate suspicious bots/tools
print("\n--- Suspicious User-Agents (rarely seen) ---")
ua_counts = df['user_agent'].value_counts()
print(ua_counts[ua_counts < 3].head(10))

# 7. Suspicious IPs making high request volumes (possible brute-force or scraping)
print("\n--- Suspicious IPs (10+ requests) ---")
suspicious_ips = df['ip'].value_counts()[df['ip'].value_counts() > 10]
print(suspicious_ips)