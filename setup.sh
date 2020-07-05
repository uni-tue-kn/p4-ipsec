#!/bin/bash

# Print script commands.
set -x
# Exit on errors.
set -e

# Set-up P4 environment
cd dependencies
sudo ./root-bootstrap.sh
./libyang-sysrepo.sh
./user-bootstrap.sh
cd ..