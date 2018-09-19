#!/bin/bash
rm -rf test.log
while :
do
	chromium-browser http://finance.sina.com.cn/zl/china/2018-08-12/zl-ihicsiaw4320984.shtml &
	sleep 12; killall chromium-browser
	chromium-browser http://zhuanlan.sina.com.cn/ &
	sleep 12; killall chromium-browser
	chromium-browser  http://sports.sina.com.cn/zl/ &
	sleep 12; killall chromium-browser
	chromium-browser http://sports.sina.com.cn/zl/basketball/2018-08-25/zldoc-ihicsiaw8441084.shtml &
	sleep 12; killall chromium-browser
	chromium-browser http://sports.sina.com.cn/zl/basketball/2018-08-22/zldoc-ihhzsnea7876731.shtml &
	sleep 12; killall chromium-browser
	chromium-browser http://edu.163.com/liuxue/#f=endnav &
	sleep 12; killall chromium-browser
	chromium-browser http://tech.163.com/smart/ &
	sleep 12; killall chromium-browser
	chromium-browser http://tech.163.com/special/kaiwu/ &
	sleep 12; killall chromium-browser
	chromium-browser http://tech.163.com/special/techat0007/ &
	sleep 12; killall chromium-browser
	chromium-browser http://tech.163.com/special/kaiwu/ &
	sleep 12; killall chromium-browser
	chromium-browser http://edu.163.com/ &
	sleep 12; killall chromium-browser
	chromium-browser http://v.163.com/ &
	sleep 12; killall chromium-browser
	chromium-browser http://live.163.com/room/174866.html &
	sleep 12; killall chromium-browser
	chromium-browser http://live.163.com/room/178298.html &
	sleep 12; killall chromium-browser
	chromium-browser http://foxue.163.com/ &
	sleep 12; killall chromium-browser
	chromium-browser http://jiankang.163.com/ &
	sleep 12; killall chromium-browser



	echo $(date) >> test.log 
done
