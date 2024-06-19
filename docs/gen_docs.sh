#!/bin/sh

(cd ../ && sphinx-apidoc -o docs binocular/)
make html