#!/usr/bin/env bash

ssh shanai-isucon-app-01 "sudo systemctl stop nginx.service"
ssh shanai-isucon-app-01 "sudo systemctl stop mysql.service"

ssh shanai-isucon-app-01 "sudo rm /var/log/nginx/access_tsv.log"
ssh shanai-isucon-app-01 "sudo rm /tmp/mysqld-slow.log"

ssh shanai-isucon-app-01 "sudo systemctl start nginx.service"
ssh shanai-isucon-app-01 "sudo systemctl start mysql.service"
ssh shanai-isucon-app-01 "sudo systemctl restart isu-go.service"
