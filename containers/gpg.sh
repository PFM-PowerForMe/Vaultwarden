#!/usr/bin/expect -f

# 禁止输出到屏幕
log_user 0

set trust_level "5"

spawn gpg --edit-key $env(ENCRYPTION_PUB_ID)
expect "gpg\>"
send "trust\r"
expect "Your decision?"
send "$trust_level\r"
expect "(y/N)"
send "y\r"
expect {
	"gpg\>" {
    	send "quit\r"
        exp_continue
    }
    eof
}

# 恢复输出到屏幕
log_user 1

# 调用 gpg -k 显示结果
spawn gpg -k
expect eof