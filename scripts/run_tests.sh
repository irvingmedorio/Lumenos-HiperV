#!/usr/bin/env bash
# run_tests.sh — Linux counterpart to run_tests.ps1
set -e
export LUMENOS_HYPERVISOR=${LUMENOS_HYPERVISOR:-mock}
echo "Running tests with LUMENOS_HYPERVISOR=$LUMENOS_HYPERVISOR"
python3 -m pytest tests/ -v "$@"
