#!/bin/bash

# Send the HTCPCP request
echo -e "GET / HTCPCP/1.0\r\nX-Scheme: coffee\r\n\r\n" | nc 127.0.0.1 1337 > /tmp/response.txt

# Check the response
if grep -q "200 OK" /tmp/response.txt; then
    # If the response is 200 OK, return 0
    exit 0
else
    # If the response is not 200 OK, return 1
    exit 1
fi