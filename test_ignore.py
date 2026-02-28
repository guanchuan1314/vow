# vow-ignore
eval("test code")  # This should be suppressed

# vow-ignore:exec_usage
exec("dangerous stuff")  # This should be suppressed for this rule only

# vow-ignore-next-line
eval("next line test")  # This line should be suppressed

print("This is fine")  # This should not be suppressed