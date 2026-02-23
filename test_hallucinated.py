#!/usr/bin/env python3

import os
import json

# Test hallucinated method signatures

# Wrong os.path method
if os.path.exist("file.txt"):  # Should be exists()
    print("File exists")

# Wrong string method
text = "hello world"
if text.contains("hello"):  # Python doesn't have contains()
    print("Found")

# Wrong JSON methods  
data = json.parse('{"key": "value"}')  # Should be loads()
result = json.stringify(data)  # Should be dumps()

# Wrong list method
my_list = []
my_list.push("item")  # Should be append()

print("Test file for hallucinated signatures")