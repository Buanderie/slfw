#!/bin/bash

# Retrieve script directory
GENERATE_SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

$GENERATE_SCRIPT_DIR/getprojectversion $GENERATE_SCRIPT_DIR > $GENERATE_SCRIPT_DIR/cmd/version.txt
