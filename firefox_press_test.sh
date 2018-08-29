#!/bin/bash
rm -rf test.log
while :
do
	firefox --private-window http://finance.sina.com.cn/zl/china/2018-08-24/zl-ihicsiaw4320984.shtml &
	sleep 24; killall firefox
	firefox --new-tab http://zhuanlan.sina.com.cn/ &
	sleep 24; killall firefox
	firefox --new-tab http://sports.sina.com.cn/zl/ &
	sleep 24; killall firefox
	firefox --new-tab http://sports.sina.com.cn/zl/basketball/2018-08-25/zldoc-ihicsiaw8441084.shtml &
	sleep 24; killall firefox
	firefox --new-tab http://sports.sina.com.cn/zl/basketball/2018-08-22/zldoc-ihhzsnea7876731.shtml &
	sleep 24; killall firefox
	echo $(date) >> test.log 
done
