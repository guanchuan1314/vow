#!/usr/bin/env python3

# This file contains a hallucinated import that should be detected
import nonexistent_fake_package
import os

def main():
    print("Hello World")
    return os.getcwd()

if __name__ == "__main__":
    main()