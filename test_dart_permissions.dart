import 'dart:io';

void main() {
  var file = File('test.txt');
  
  // These should be detected as insecure:
  file.setPermissions(FileMode(0777)); // Should be flagged
  file.setPermissions(FileMode(777));  // Should be flagged
  file.setPermissions(FileMode(0666)); // Should be flagged (world-writable)
  
  // This should be safe:
  file.setPermissions(FileMode(0644)); // Should NOT be flagged
  
  // More patterns to test:
  var mode = FileMode(0777); // Should be flagged
  var safeMode = FileMode(0644); // Should NOT be flagged
}