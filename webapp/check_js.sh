#!/usr/bin/env bash

FAILED=0
CHECKED=0

echo "Auditing vanilla JS files for syntax errors..."

# Exclude .git and search for .js files
while IFS= read -r -d '' file; do
  ((CHECKED++))

  ERROR_OUTPUT=$(node --check --input-type=module < "$file" 2>&1)

  if [ $? -ne 0 ]; then
    ((FAILED++))
    echo -e "\n\033[31m[FAILED]\033[0m $file"
    echo "$ERROR_OUTPUT" | grep -A 4 "SyntaxError" || echo "$ERROR_OUTPUT"
  fi
done < <(find . -name ".git" -prune -o -type f -name "*.js" -print0)

echo ""
echo "=========================================="
echo "Checked: $CHECKED | Passed: $((CHECKED - FAILED)) | Failed: $FAILED"
echo "=========================================="

if [ $FAILED -gt 0 ]; then
  exit 1
fi