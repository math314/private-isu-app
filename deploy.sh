#!/usr/bin/env bash
ssh shanai-isucon-app-01 "rm -r /tmp/etc"
ssh shanai-isucon-app-01 "mkdir -p /tmp/etc/nginx && mkdir -p /tmp/etc/mysql"

scp nginx/nginx.conf shanai-isucon-app-01:/tmp/etc/nginx
scp -r mysql/conf.d shanai-isucon-app-01:/tmp/etc/mysql
scp -r mysql/mysql.conf.d shanai-isucon-app-01:/tmp/etc/mysql

scp copyFiles.sh shanai-isucon-app-01:/tmp
ssh shanai-isucon-app-01 "/tmp/copyFiles.sh"

cd app/src
./setup.sh
cd ../..

ssh shanai-isucon-app-01 "sudo systemctl stop isu-go.service"

scp app/src/app shanai-isucon-app-01:/home/isucon/private_isu/webapp/golang
scp -r app/src/templates shanai-isucon-app-01:/home/isucon/private_isu/webapp/golang

ssh shanai-isucon-app-01 "sudo systemctl restart nginx.service"
ssh shanai-isucon-app-01 "sudo systemctl restart mysql.service"

ssh shanai-isucon-app-01 "sudo systemctl start isu-go.service"