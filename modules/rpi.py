#!/usr/bin/python
# -*- coding: utf-8 -*-

#######################################################################################################################################
# Forked from                                                                                                                         #
# https://www.inpact-hardware.com/article/1427/un-script-python-pour-suivre-frequences-tension-et-temperature-soc-dun-raspberry-pi    #
# https://gist.github.com/davlgd/07f6288e869519acb695774e146a20b6                                                                     #
# And Autopi                                                                                                                          #
# https://github.com/autopi-io                                                                                                        #
#######################################################################################################################################

import os
import csv
import time

import datetime
import logging
import re
#import salt.exceptions


log = logging.getLogger(__name__)

_gpu_temp_regex = re.compile("^temp=(?P<value>[-+]?[0-9]*\.?[0-9]*)'(?P<unit>.+)$")
_linux_boot_log_regex = re.compile("^(?P<timestamp>.+) raspberrypi kernel: .+$")

delay = 10
csv_file = "pi_soc_results.csv"

elapsed = 0


def help():
    """
    Shows this help information.
    """

    return #__salt__["sys.doc"]("rpi")


def temp():
    """
    Current temperature readings.
    """

    return {
        "cpu": temp_cpu(),
        "gpu": temp_gpu()
    }


def temp_cpu():
    """
    Current temperature of the ARM CPU.
    """

    tempFile = open( "/sys/class/thermal/thermal_zone0/temp" )
    raw = tempFile.read() #__salt__["cp.get_file_str"]("/sys/class/thermal/thermal_zone0/temp")
    tempFile.close()

    return {
        "value": float(raw) / 1000,
        "unit": "C"
    }


def temp_gpu():
    """
    Current temperature of the GPU.
    """

    raw = os.popen("vcgencmd measure_temp").readline() #__salt__["cmd.run"]("vcgencmd measure_temp")
    match = _gpu_temp_regex.match(raw)

    ret = match.groupdict()
    ret["value"] = float(ret["value"])

    return ret


def hw_serial():
    """
    Get hardware serial.
    """
    hw_serial = os.popen("grep -Po '^Serial\s*:\s*\K[[:xdigit:]]{16}' /proc/cpuinfo").readline()

    return hw_serial

def boot_time():
    """
    Get timestamp for last boot of system.
    """

    ret = {"value": None}

    #res = __salt__["cmd.shell"]("grep 'Booting Linux' /var/log/syslog | tail -1")
    res = os.popen("grep 'Booting Linux' /var/log/syslog | tail -1").readlines()
    if not res:
        return ret

    match = _linux_boot_log_regex.match(res[0])
    if not match:
        raise ValueError("Unable to parse log line: {:}".format(res)) #salt.exceptions.CommandExecutionError("Unable to parse log line: {:}".format(res))

    now = datetime.datetime.now()
    last_off = datetime.datetime.strptime(match.group("timestamp"), "%b %d %H:%M:%S").replace(year=now.year)
    if last_off > now:
        last_off = last_off.replace(year=now.year-1)

    ret["value"] = last_off.isoformat()

    return ret


def write_csv(mode, value):
    with open (csv_file, mode) as csv_file_opened:
        writer = csv.writer(csv_file_opened)
        writer.writerow(value)
       
    csv_file_opened.close()

def extract_float_value(text, start, end):
    result = ""
    
    if end == "":
        result = text[text.find(start)+1:len(text)]
    else:
        result = text[text.find(start)+1:text.find(end)]
    
    return float(result)

def get_temp():
    
    temp_r = os.popen("vcgencmd measure_temp").readline()
    temp_f = extract_float_value(temp_r, "=", "'")
    
    return temp_f

def get_cpu_temp():
    tempFile = open( "/sys/class/thermal/thermal_zone0/temp" )
    cpu_temp = tempFile.read()
    tempFile.close()
    return round(float(cpu_temp)/1000, 2)

def get_clock(part):
    
    clock_core_r = os.popen("vcgencmd measure_clock " + part).readline()
    clock_core_f = extract_float_value(clock_core_r, "=", "")/1000000
    
    return clock_core_f

def get_volt():
    
    volt_r = os.popen("vcgencmd measure_volts core").readline()
    volt_f = extract_float_value(volt_r, "=", "V")
    
    return volt_f

#print
#print(" Raspberry Pi SoC values :")
#print(" =========================")
#print

#write_csv("w", ["temp", "cpu_temp", "core freq", "arm freq", "volt", "sec"])

#while True:
 
#    values = [get_temp(), get_cpu_temp(), get_clock("core"), get_clock("arm"), get_volt(), elapsed]
    
    #print(" {0:.0f}°C - {1:.0f}°C - {2:.0f}/{3:.0f} MHz - {4:.2f} V".format(values[0], values[1], values[2], values[3], values[4]))
#    write_csv("a", values)
        
#    time.sleep(delay)
#    elapsed += delay