#!/bin/bash
# Run this on Kali to capture all 12 test cases
cd ~/cse363-hw1-network-sniffing

echo "Cleaning old captures..."
sudo rm -f /tmp/capture.pcap /tmp/capture_eth0.pcap /tmp/capture_lo.pcap

echo "Starting HTTP servers..."
python3 -m http.server 8080 &
python3 -m http.server 9090 &
sleep 1

# Get our IP for non-standard port HTTP
MY_IP=$(hostname -I | awk '{print $1}')
echo "My IP: $MY_IP"

echo "Starting tcpdump on eth0..."
sudo tcpdump -i eth0 -w /tmp/capture_eth0.pcap &
PID1=$!
echo "Starting tcpdump on lo..."
sudo tcpdump -i lo -w /tmp/capture_lo.pcap "port 8080 or port 9090" &
PID2=$!
sleep 3

echo "=== DNS ==="
dig @8.8.8.8 www.cs.stonybrook.edu +short +timeout=3 +tries=1
dig @1.1.1.1 -p 5353 www.example.com +timeout=1 +tries=1
dig @8.8.8.8 esxi1.local +short +timeout=3 +tries=1
dig @8.8.8.8 -p 1053 db.corp +timeout=1 +tries=1

echo "=== HTTP ==="
curl -s -m 5 -A "Mozilla/5.0 (X11; Linux x86_64)" http://www.cs.stonybrook.edu/~cse363/ -o /dev/null -w "HTTP 80 normal: %{http_code}\n"
curl -s -m 5 -A "Mozilla/5.0 (X11; Linux x86_64)" http://127.0.0.1:8080/ -o /dev/null -w "HTTP 8080 normal: %{http_code}\n"
curl -s -m 5 -A "curl/8.11.1" -X POST http://www.cs.stonybrook.edu/~cse363/ -o /dev/null -w "HTTP 80 auto: %{http_code}\n"
curl -s -m 5 -A "python-requests/2.31.0" -X PUT http://127.0.0.1:9090/upload -o /dev/null -w "HTTP 9090 auto: %{http_code}\n"

echo "=== TLS ==="
GOOGLE_IP=$(dig +short google.com A | head -1)
IMAP_IP=$(dig +short imap.gmail.com A | head -1)
echo "google=$GOOGLE_IP imap=$IMAP_IP"

echo Q | openssl s_client -connect google.com:443 -servername google.com 2>/dev/null | head -1
echo Q | openssl s_client -connect imap.gmail.com:993 -servername imap.gmail.com 2>/dev/null | head -1
echo Q | openssl s_client -connect "$GOOGLE_IP":443 -noservername 2>/dev/null | head -1
echo Q | openssl s_client -connect "$IMAP_IP":993 -noservername 2>/dev/null | head -1

echo "=== Stopping ==="
sleep 2
sudo kill $PID1 $PID2 2>/dev/null
wait $PID1 $PID2 2>/dev/null
killall python3 2>/dev/null

echo "=== Merging captures ==="
sudo mergecap -w /tmp/capture.pcap /tmp/capture_eth0.pcap /tmp/capture_lo.pcap

echo "=== Testing with argus ==="
python3 argus.py -r /tmp/capture.pcap

echo "=== Copying files ==="
cp /tmp/capture.pcap test.pcap
python3 argus.py -r test.pcap > test.out
cat test.out

echo "DONE"
