#!/bin/bash

# python3 -m http.server --directory /var/local/poc-classification/html 80 &
busybox httpd -h /var/local/poc-classification/html
