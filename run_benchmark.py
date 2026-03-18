#!/usr/bin/env python3
"""Wrapper to run benchmark.run_eval as a script (workaround for -m cwd issues)."""
import sys
sys.path.insert(0, __import__("os").path.dirname(__import__("os").path.abspath(__file__)))

from dotenv import load_dotenv
load_dotenv()  # Load API keys from .env file

from benchmark.run_eval import main
main()
