#!/usr/bin/env bash

set -euo pipefail

rsync -avh --progress --delete -e "ssh -i ~/.ssh/qnap_backup_orin" /home/jetson/git/ master@192.168.254.45:/share/rsync/devices/orin/git/
