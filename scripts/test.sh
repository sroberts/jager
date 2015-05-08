#! /bin/sh
pre-commit run --all-files
py.test --cov jager tests/
