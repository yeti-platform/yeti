#!/bin/bash
# This script gives a poor error message due to https://github.com/microsoft/vscode/issues/189924
# but still blocks the commit from happening, so sorta WAI
poetry run ruff check . && poetry run ruff format . --check

# Check the exit status of the previous command

if [ $? -ne 0 ]; then
    echo "ruff check failed. Aborting commit."
    exit 1
else
    echo "ruff check passed."
fi
