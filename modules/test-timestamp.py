#!/usr/bin/python
# -*- coding: utf-8 -*-

import re
import datetime

#res = "Jan 19 17:23:49 raspberrypi kernel: [    0.000000] Booting Linux on physical CPU 0x0"
res ="Jan 19 17:23:49 raspberrypi kernel: [    0.000000] Booting Linux on physical CPU 0x0\nJan 19 17:23:54 raspberrypi python3[538]: Unable to trigger last system off event: Unable to parse log line: Jan 19 17:23:49 raspberrypi kernel: [    0.000000] Booting Linux on physical CPU 0x0\n"

#_linux_boot_log_regex = re.compile("^(?P<timestamp>.+) raspberrypi kernel: .+$")
_linux_boot_log_regex = re.compile(r'^(?P<timestamp>.+) raspberrypi .+$')

res = res.replace('\n', '')
print(res)
match = _linux_boot_log_regex.match(res)

if not match:
    raise ValueError("Unable to parse log line: {:}".format(res)) #salt.exceptions.CommandExecutionError("Unable to parse log line: {:}".format(res))

print(match.group("timestamp"))

now = datetime.datetime.now()
last_off = datetime.datetime.strptime(match.group("timestamp"), "%b %d %H:%M:%S").replace(year=now.year)
if last_off > now:
    last_off = last_off.replace(year=now.year-1)

print(last_off)
