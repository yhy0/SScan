#!/usr/bin/python3
# -*- coding:utf-8 -*-
# @Author : yhy

yellow = '\033[01;33m'
white = '\033[01;37m'
green = '\033[01;32m'
blue = '\033[01;34m'
red = '\033[1;31m'
end = '\033[0m'

version = 'v0.8'
message = white + '{' + red + version + ' #dev' + white + '}'

SScan_banner = f"""{yellow}
SScan is a slow sensitive information detection and vulnerability scanning program.{green}
      _____ _____                 
      / ____/ ____|                
     | (___| (___   ___ __ _ _ __  {message}{blue}
      \___ \\___ \ / __/ _` | '_ \ 
      ____) |___) | (_| (_| | | | |
     |_____/_____/ \___\__,_|_| |_|
    
            {red}By yhy(https://github.com/yhy0/SScan.git) {blue}
"""

