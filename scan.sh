#!/bin/bash
# Activate virtual environment and run scanner
source venv/bin/activate
python src/main.py "$@"
