#!/bin/bash

# Generate Lezer parsers
# This script generates TypeScript parsers from Lezer grammar files

set -e

# Generate CSP parser
echo "Generating CSP parser..."
npx @lezer/generator ./src/parsers/csp/csp.grammar -o ./src/parsers/csp/__generated__.ts

echo "Parser generation complete!"
