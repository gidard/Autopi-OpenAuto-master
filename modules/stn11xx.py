import logging
import parsing
import re
import salt.exceptions

from messaging import EventDrivenMessageClient, msg_pack as _msg_pack
from timeit import default_timer as timer


# Define the module's virtual name
__virtualname__ = "stn"

EXT_WAKE_RULE_PATTERN = "^(?:HIGH|LOW) FOR (?P<ms>[0-9]+) ms$"
EXT_SLEEP_RULE_PATTERN = "^(?:HIGH|LOW) FOR (?P<ms>[0-9]+) ms$"
UART_WAKE_RULE_PATTERN = "^(?P<min_us>[0-9]+)-(?P<max_us>[0-9]+) us$"
UART_SLEEP_RULE_PATTERN = "^(?P<sec>[0-9]+) s$"
VOLT_LEVEL_RULE_PATTERN = "^(?P<volts>[\<\>][0-9]{1,2}\.[0-9]{1,2})V FOR (?P<sec>[0-9]+) s$"
VOLT_CHANGE_RULE_PATTERN = "^(?P<volts_diff>[+-]?[0-9]{1}\.[0-9]{1,2})V IN (?P<ms>[0-9]+) ms$"
VOLT_LEVEL_PATTERN = "^(?P<value>[0-9]+\.[0-9]+)(?P<unit>V)$"

log = logging.getLogger(__name__)

client = EventDrivenMessageClient("obd")


def __virtual__():
    return __virtualname__


def __init__(opts):
    client.init(opts)


def _parse_rule(value, pattern):
    match = re.match(pattern, value)
    if not match:
        raise salt.exceptions.CommandExecutionError(
            "Failed to parse rule: {:s}".format(value))

    return match.groupdict()


def help():
    """
    Shows this help information.
    """

    return __salt__["sys.doc"](__virtualname__)


def _execute(cmd, **kwargs):
    """
    Private helper function to execute commands.
    """

    res = client.send_sync(_msg_pack(cmd, _handler="execute", **kwargs))

    if not "value" in res and not "values" in res:
        raise salt.exceptions.CommandExecutionError(
            "Execution of command '{:s}' returned no value(s)".format(cmd))

    return res


def _change(cmd, **kwargs):
    """
    Private helper function to perform change settings commands.
    """

    # Request warm reset for changes to take effect
    if not "reset" in kwargs:
        kwargs["reset"] = "warm"

    res = _execute(cmd, **kwargs)

    # Change commands must return OK
    if res.get("value", None) != "OK":
        raise salt.exceptions.CommandExecutionError(
            "Change settings command '{:s}' failed".format(cmd))

    return res


def info():
    res = _execute("STDIX")
    parsing.into_dict_parser(res.pop("values"), root=res)

    return res


def serial():
    res = _execute("STSN")

    return res


def power_config():
    """
    Summarizes active PowerSave configuration.
    """

    res = _execute("STSLCS")
    parsing.into_dict_parser(res.pop("values"), root=res)

    return res


def power_trigger_status():
    """
    Reports last active sleep/wakeup triggers since last reset.
    """

    res = _execute("STSLLT")
    parsing.into_dict_parser(res.pop("values"), root=res)

    return res


def power_pin_polarity(invert=None):
    """
    Specify whether the pin outputs a logic LOW or HIGH in low power mode.
    """

    ret = {}

    # Read out current settings
    if invert == None:
        cfg = power_config()

        ret["_stamp"] = cfg["_stamp"]
        ret["value"] = cfg["pwr_ctrl"]

        return ret

    # Write settings
    res = _change("STSLPCP {:d}".format(invert))
    ret.update(res)

    return ret


def sleep(delay_sec, keep_conn=False):
    """
    Enter sleep mode after the specified delay time.
    The OBD connection is closed as default in order to prevent STN wake up on UART communication.
    """

    res = _change("STSLEEP {:d}".format(delay_sec), reset=False, keep_conn=keep_conn)

    return res


def ext_wake(enable=None, ms=2000, rule=None):
    """
    External wake trigger configuration.
    """

    ret = {}

    # Read out current settings
    cfg = power_config()

    if enable == None:
        ret["_stamp"] = cfg["_stamp"]
        ret["value"] = cfg["ext_wake"]

        return ret

    # Write rule settings if enable
    if enable:
        kwargs = _parse_rule(rule, EXT_WAKE_RULE_PATTERN) if rule else {
            "ms": ms
        }
        res = _change("STSLXWT {ms:}".format(**kwargs))
        ret.update(res)

    # Enable/disable
    res = _change("STSLX {:s}, {:s}".format(
        "on" if cfg["ext_sleep"].startswith("ON") else "off",
        "on" if enable else "off")
    )
    ret.update(res)

    return ret


def ext_sleep(enable=None, ms=3000, rule=None):
    """
    External sleep trigger configuration.
    """

    ret = {}

    # Read out current settings
    cfg = power_config()

    if enable == None:
        ret["_stamp"] = cfg["_stamp"]
        ret["value"] = cfg["ext_sleep"]

        return ret

    # Write rule settings if enable
    if enable:
        kwargs = _parse_rule(rule, EXT_SLEEP_RULE_PATTERN) if rule else {
            "ms": ms
        }
        res = _change("STSLXST {ms:}".format(**kwargs))
        ret.update(res)

    # Enable/disable
    res = _change("STSLX {:s}, {:s}".format(
        "on" if enable else "off",
        "on" if cfg["ext_wake"].startswith("ON") else "off"
    ))
    ret.update(res)

    return ret


def uart_wake(enable=None, min_us=0, max_us=30000, rule=None):
    """
    UART wakeup pulse timing configuration.
    """

    ret = {}

    # Read out current settings
    cfg = power_config()

    if enable == None:
        ret["_stamp"] = cfg["_stamp"]
        ret["value"] = cfg["uart_wake"]

        return ret

    # Write rule settings if enable
    if enable:
        kwargs = _parse_rule(rule, UART_WAKE_RULE_PATTERN) if rule else {
            "min_us": min_us,
            "max_us": max_us
        }
        res = _change("STSLUWP {min_us:}, {max_us:}".format(**kwargs))
        ret.update(res)

    # Enable/disable
    res = _change("STSLU {:s}, {:s}".format(
        "on" if cfg["uart_sleep"].startswith("ON") else "off",
        "on" if enable else "off")
    )
    ret.update(res)

    return ret


def uart_sleep(enable=None, timeout_sec=1200, rule=None):
    """
    UART inactivity timeout configuration.
    """

    ret = {}

    # Read out current settings
    cfg = power_config()

    if enable == None:
        ret["_stamp"] = cfg["_stamp"]
        ret["value"] = cfg["uart_sleep"]

        return ret

    # Write rule settings if enable
    if enable:
        kwargs = _parse_rule(rule, UART_SLEEP_RULE_PATTERN) if rule else {
            "sec": timeout_sec
        }
        res = _change("STSLUIT {sec:}".format(**kwargs))
        ret.update(res)

    # Enable/disable
    res = _change("STSLU {:s}, {:s}".format(
        "on" if enable else "off",
        "on" if cfg["uart_wake"].startswith("ON") else "off"
    ))
    ret.update(res)

    return ret


def volt_level(samples=10):
    """
    Determine the current voltage level.
    """

    ret = {}

    start = timer()

    # Perform readings
    readings = []
    for idx in range(samples):
        res = _execute("ATRV")

        match = re.match(VOLT_LEVEL_PATTERN, res["value"])
        if not match:
            raise salt.exceptions.CommandExecutionError(
                "Failed to parse voltage level result #{:}: {:s}".format(idx, res))

        readings.append(float(match.group("value")))

    ret["duration"] = timer() - start
    ret["unit"] = "V"
    ret["average"] = sum(readings) / len(readings)
    ret["minimum"] = min(readings)
    ret["maximum"] = max(readings)
    
    return ret


def volt_calibrate(value=0000, confirm=False):
    """
    Manual calibration of voltage measurement.
    Default value '0000' will restore to the factory calibration.

    Optional arguments:
      - value (int): The value to set the calibration to. Default is 0000.
      - confirm (bool): Achknowledge the execution of this command. Default is 'False'.
    """

    if not confirm:
        raise salt.exceptions.CommandExecutionError(
            "This command will change the voltage calibration of the device - add parameter 'confirm=true' to continue anyway")

    res = _change("ATCV {:04d}".format(value), reset=False)
    log.info("Changed volt calibration to {}".format(value))

    return res


def volt_change_wake(enable=None, volts_diff="+0.2", ms=1000, rule=None):
    """
    Voltage change wakeup trigger configuration.
    """

    ret = {}

    # Read out current settings
    if enable == None:
        cfg = power_config()

        ret["_stamp"] = cfg["_stamp"]
        ret["value"] = cfg["vchg_wake"]

        return ret

    # Write rule settings if enable
    if enable:
        kwargs = _parse_rule(rule, VOLT_CHANGE_RULE_PATTERN) if rule else {
            "volts_diff": volts_diff,
            "ms": ms
        }
        res = _change("STSLVGW {volts_diff:}, {ms:}".format(**kwargs))
        ret.update(res)

    # Enable/disable
    res = _change("STSLVG {:s}".format("on" if enable else "off"))
    ret.update(res)

    return ret


def volt_level_wake(enable=None, volts=">13.2", sec=1, rule=None):
    """
    Voltage level wakeup trigger configuration.
    """

    ret = {}

    # Read out current settings
    cfg = power_config()

    if enable == None:
        ret["_stamp"] = cfg["_stamp"]
        ret["value"] = cfg["vl_wake"]

        return ret

    # Write rule settings if enable
    if enable:
        kwargs = _parse_rule(rule, VOLT_LEVEL_RULE_PATTERN) if rule else {
            "volts": volts,
            "sec": sec
        }
        res = _change("STSLVLW {volts:}, {sec:}".format(**kwargs))
        ret.update(res)

    # Enable/disable
    res = _change("STSLVL {:s}, {:s}".format(
        "on" if cfg["vl_sleep"].startswith("ON") else "off",
        "on" if enable else "off"
    ))
    ret.update(res)

    return ret


def volt_level_sleep(enable=None, volts="<13.0", sec=600, rule=None):
    """
    Voltage level sleep trigger configuration.
    """

    ret = {}

    # Read out current settings
    cfg = power_config()

    if enable == None:
        ret["_stamp"] = cfg["_stamp"]
        ret["value"] = cfg["vl_sleep"]

        return ret

    # Write rule settings if enable
    if enable:
        kwargs = _parse_rule(rule, VOLT_LEVEL_RULE_PATTERN) if rule else {
            "volts": volts,
            "sec": sec
        }
        res = _change("STSLVLS {volts:}, {sec:}".format(**kwargs))
        ret.update(res)

    # Enable/disable
    res = _change("STSLVL {:s}, {:s}".format(
        "on" if enable else "off",
        "on" if cfg["vl_wake"].startswith("ON") else "off"
    ))
    ret.update(res)

    return ret
