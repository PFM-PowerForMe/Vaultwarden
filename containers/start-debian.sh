#!/bin/sh

if [ -n "$ENCRYPTION_PUB_KEY" ];then
	echo "$ENCRYPTION_PUB_KEY" | gpg --import
	expect -f /gpg.sh
fi

service cron start

sh /start.sh
