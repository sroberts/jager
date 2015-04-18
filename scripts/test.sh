#! /bin/sh
pre-commit run --all-files
cp -r utilitybelt/data/ .
py.test tests/
