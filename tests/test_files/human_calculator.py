#!/usr/bin/env python3
"""
A simple calculator module for basic arithmetic operations.
Written by human developer for educational purposes.
"""

import math


def add(a, b):
    """Add two numbers and return the result."""
    return a + b


def subtract(a, b):
    """Subtract b from a and return the result."""
    return a - b


def multiply(a, b):
    """Multiply two numbers and return the result."""
    return a * b


def divide(a, b):
    """Divide a by b and return the result. Raises ZeroDivisionError if b is 0."""
    if b == 0:
        raise ZeroDivisionError("Cannot divide by zero")
    return a / b


def main():
    """Simple interactive calculator."""
    print("Simple Calculator")
    while True:
        try:
            operation = input("Enter operation (+, -, *, /) or 'quit': ").strip()
            if operation.lower() == 'quit':
                break
            
            if operation in ['+', '-', '*', '/']:
                num1 = float(input("Enter first number: "))
                num2 = float(input("Enter second number: "))
                
                if operation == '+':
                    result = add(num1, num2)
                elif operation == '-':
                    result = subtract(num1, num2)
                elif operation == '*':
                    result = multiply(num1, num2)
                elif operation == '/':
                    result = divide(num1, num2)
                
                print(f"Result: {result}")
            else:
                print("Invalid operation")
        except (ValueError, ZeroDivisionError) as e:
            print(f"Error: {e}")


if __name__ == "__main__":
    main()