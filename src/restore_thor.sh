#!/usr/bin/env bash

set -euo pipefail

rsync -avh --progress --delete -e "ssh -i ~/.ssh/qnap_backup_thor" master@192.168.254.45:/share/rsync/devices/thor/git/ /home/jetson/git/
