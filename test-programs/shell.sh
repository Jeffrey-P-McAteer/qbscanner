#!/bin/bash

echo "Shell script starting"
echo "Current directory: $(pwd)"
echo "Environment variable HOME: $HOME"

echo "Creating temp file..."
echo "Hello from shell script" > /tmp/shell_test.txt

echo "Reading temp file..."
cat /tmp/shell_test.txt

echo "Listing /tmp files..."
ls /tmp/shell_test.txt

echo "Cleaning up..."
rm /tmp/shell_test.txt

echo "Shell script complete"