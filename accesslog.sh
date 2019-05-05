#!/usr/bin/env bash

scp shanai-isucon-app-01:/var/log/nginx/access_tsv.log tmp.log
alp -f tmp.log --aggregates "/posts/,/image/,/@"