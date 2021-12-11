# -*- coding: utf-8 -*-

########################################################################
#                                                                      #
# python-OBD: A python OBD-II serial module derived from pyobd         #
#                                                                      #
# Copyright 2004 Donour Sizemore (donour@uchicago.edu)                 #
# Copyright 2009 Secons Ltd. (www.obdtester.com)                       #
# Copyright 2009 Peter J. Creath                                       #
# Copyright 2016 Brendan Whitfield (brendan-w.com)                     #
#                                                                      #
########################################################################
#                                                                      #
# obd.py                                                               #
#                                                                      #
# This file is part of python-OBD (a derivative of pyOBD)              #
#                                                                      #
# python-OBD is free software: you can redistribute it and/or modify   #
# it under the terms of the GNU General Public License as published by #
# the Free Software Foundation, either version 2 of the License, or    #
# (at your option) any later version.                                  #
#                                                                      #
# python-OBD is distributed in the hope that it will be useful,        #
# but WITHOUT ANY WARRANTY; without even the implied warranty of       #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the        #
# GNU General Public License for more details.                         #
#                                                                      #
# You should have received a copy of the GNU General Public License    #
# along with python-OBD.  If not, see <http://www.gnu.org/licenses/>.  #
#                                                                      #
########################################################################


import logging

from .__version__ import __version__
from .interfaces import *
from .commands import commands
from .OBDResponse import OBDResponse
from .utils import scan_serial, OBDStatus, OBDError, format_frame


logger = logging.getLogger(__name__)


class OBD(object):
    """
        Class representing an OBD-II connection
        with it's assorted commands/sensors.
    """

    def __init__(self, portstr=None, baudrate=None, timeout=None, protocol=None, load_commands=True, fast=False, interface_cls=ELM327, status_callback=None, reset_callback=None):
        self.interface = None
        self.supported_commands = set(commands.base_commands())
        self.fast = fast # global switch for disabling optimizations
        # TODO: Fast mode/last command cache is not always reset - this functionality should be moved to interface or removed completely
        self.__last_command = b"" # used for running the previous command with a CR
        self.__frame_counts = {} # keeps track of the number of return frames for each command
        self.reset_callback = reset_callback

        logger.debug("======================= Python-OBD (v%s) =======================" % __version__)
        self.__connect(interface_cls, portstr, baudrate, timeout=timeout, protocol=protocol, status_callback=status_callback)

        # Try to load the car's supported commands
        if load_commands:
            try:
                self.__load_commands()
            except:
                logger.exception("Unable to load OBD commands")

        logger.debug("===================================================================")


    def __connect(self, interface_cls, portstr, baudrate, timeout=None, protocol=None, status_callback=None):
        """
            Attempts to instantiate and open an ELM327 interface connection object.
        """

        if portstr is None:
            logger.info("Using serial scan to select port")

            portnames = scan_serial()
            if not portnames:
                logger.warning("No OBD-II adapters found")
                return

            logger.info("Available ports: " + str(portnames))

            for port in portnames:
                logger.info("Attempting to use port '{:}'".format(port))

                self.interface = interface_cls(port, timeout=timeout, status_callback=status_callback)
                try:
                    self.interface.open(baudrate, protocol=protocol)
                    if self.interface.status() != OBDStatus.NOT_CONNECTED:
                        break # success! stop searching for serial

                except:
                    logger.exception("Failed to use port '{:}'".format(port))

        else:
            logger.debug("Explicit port defined")

            self.interface = interface_cls(portstr, timeout=timeout, status_callback=status_callback)
            try:
                self.interface.open(baudrate, protocol=protocol)
            except:
                logger.exception("Failed to use explicit port '{:}'".format(portstr))

        if self.interface.status() == OBDStatus.NOT_CONNECTED:
            raise OBDError("Failed to connect to interface '{:}' - see log for details".format(interface_cls))


    def __load_commands(self):
        """
            Queries for available PIDs, sets their support status,
            and compiles a list of command objects.
        """

        if self.status() != OBDStatus.BUS_CONNECTED:
            logger.warning("Cannot load commands - no connection to bus")
            return

        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("Querying for supported commands")

        pid_getters = commands.pid_getters()
        for get in pid_getters:
            # PID listing commands should sequentialy become supported
            # Mode 1 PID 0 is assumed to always be supported
            if not self.test_cmd(get, warn=False):
                continue

            # when querying, only use the blocking OBD.query()
            # prevents problems when query is redefined in a subclass (like Async)
            response = OBD.query(self, get)

            if response.is_null():
                logger.info("No valid data for PID listing command: %s" % get)
                continue

            # loop through PIDs bitarray
            for i, bit in enumerate(response.value):
                if bit:

                    mode = get.mode
                    pid  = get.pid + i + 1

                    if commands.has_pid(mode, pid):
                        self.supported_commands.add(commands[mode][pid])

                    # set support for mode 2 commands
                    if mode == 1 and commands.has_pid(2, pid):
                        self.supported_commands.add(commands[2][pid])

        logger.info("Finished querying with %d commands supported" % len(self.supported_commands))


    def close(self):
        """
            Closes the connection, and clears supported_commands
        """

        self.supported_commands = set()

        if self.interface is not None:
            self.interface.close()
            self.interface = None


    def status(self):
        """ returns the OBD connection status """
        
        return self.interface.status()


    def connection(self):
        """ Returns the serial connection object """

        return self.interface.connection()


    def protocol(self, verify=True):
        """ Returns the active protocol object but verifies it first if requested """

        return self.interface.protocol(verify=verify)


    def supported_protocols(self):
        """ Returns all protocols supported by the interface """
        
        return self.interface.supported_protocols()


    def change_protocol(self, protocol, **kwargs):
        """ Change protocol for interface """

        if self.status() == OBDStatus.NOT_CONNECTED:
            raise OBDError("Not connected to interface")

        ret = self.interface.set_protocol(protocol, **kwargs)

        # Try to load OBD commands
        if kwargs.get("verify", True):
            self.__load_commands()
        else:
            self.supported_commands = set(commands.base_commands())

        return ret


    def is_connected(self):
        """
            Returns a boolean for whether a connection with the car's bus was made.
        """
        return self.status() == OBDStatus.BUS_CONNECTED


    def print_commands(self):
        """
            Utility function meant for working in interactive mode.
            Prints all commands supported by the car.
        """
        for c in self.supported_commands:
            print(str(c))


    def supports(self, cmd):
        """
            Returns a boolean for whether the given command
            is supported by the car
        """
        return cmd in self.supported_commands


    def test_cmd(self, cmd, warn=True):
        """
            Returns a boolean for whether a command will
            be sent without using force=True.
        """
        # test if the command is supported
        if not self.supports(cmd):
            if warn:
                logger.warning("'%s' is not supported" % str(cmd))
            return False

        # mode 06 is only implemented for the CAN protocols
        if cmd.mode == 6 and self.interface.protocol().ID not in ["6", "7", "8", "9"]:
            if warn:
                logger.warning("Mode 06 commands are only supported over CAN protocols")
            return False

        return True


    def query(self, cmd, header=None, force=False):
        """
            Sends commands to the car, and protects against sending unsupported commands.
        """

        if self.status() == OBDStatus.NOT_CONNECTED:
            raise OBDError("Not connected to interface")

        # if the user forces, skip all checks
        if not force and not self.test_cmd(cmd):
            return OBDResponse()

        # query command and retrieve message
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("Querying command: %s" % str(cmd))

        cmd_string = self.__build_command_string(cmd)

        try:
            messages = self.interface.query(cmd_string, header=header)

        finally:

            # if we're sending a new command, note it
            # first check that the current command WASN'T sent as an empty CR
            # (CR is added by the ELM327 class)
            if cmd_string:
                self.__last_command = cmd_string

        # if we don't already know how many frames this command returns,
        # log it, so we can specify it next time
        if cmd not in self.__frame_counts:
            self.__frame_counts[cmd] = sum([len(m.frames) for m in messages])

        if not messages:
            logger.warning("No valid OBD messages returned")
            return OBDResponse()

        return cmd(messages) # compute a response object


    def send(self, msg_string, header=None, auto_format=False, expect_response=False, raw_response=False, format_response=False, echo=False):
        """
            Low-level method that sends a raw message on bus.
        """

        if self.status() == OBDStatus.NOT_CONNECTED:
            raise OBDError("Not connected to interface")

        # Enforce no AT commands
        if msg_string[:2].upper() in ["AT", "ST"]:
            raise ValueError("AT and ST commands are not allowed - use 'execute' instead")

        # Set given header or use default
        self.interface.set_header(header)

        # Set CAN automatic formatting
        self.interface.set_can_auto_format(auto_format)

        # Set responses expected or not
        self.interface.set_expect_responses(bool(expect_response))

        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("Sending message: %s" % str(msg_string))

        try:
            if isinstance(expect_response, bool):  # NOTE: In Python 'bool' is child of 'int'
                lines = self.interface.send(msg_string, raw_response=raw_response)

                # Check for empty response
                if expect_response and not raw_response and not lines:
                    raise OBDError("Expected response but got empty")

            else:
                lines = self.interface.send("{:} {:X}".format(msg_string, expect_response), raw_response=raw_response)  # Specify the number of expected frames (to avoid waiting for timeout)

                # Check expected response matches actual
                if expect_response and not raw_response and expect_response != len(lines):
                    raise OBDError("Expected response of {:} but got {:}".format(expect_response, len(lines)))

            # If echo prepend request message including header
            if echo:
                lines.insert(0, msg_string if header == None else "{:} {:}".format(header, msg_string))

        finally:

            # Remember to update last command
            self.__last_command = msg_string

        # Format frames if requested
        if format_response:
            header_bits = getattr(self.interface._protocol, "HEADER_BITS", None)
            lines = [format_frame(l, header_bits) for l in lines]

        return lines


    def execute(self, cmd_string, raw_response=False):
        """
            Low-level method to execute an AT command on the interface.
        """

        if self.status() == OBDStatus.NOT_CONNECTED:
            raise OBDError("Not connected to interface")

        try:

            if logger.isEnabledFor(logging.DEBUG):
                logger.debug("Executing AT command against interface: %s" % str(cmd_string))

            lines = self.interface.relay(cmd_string, raw_response=raw_response)

        finally:

            # Remember to update last command
            self.__last_command = cmd_string

        return lines


    def reset(self, mode="warm"):
        """
            Reboots interface and re-initializes connection and configuration settings.
        """

        if self.status() == OBDStatus.NOT_CONNECTED:
            raise OBDError("Not connected to interface")

        # Remember to clear
        self.__last_command = ""
        self.__frame_counts = {}

        if not mode or mode.lower() == "warm":
            self.interface.warm_reset()
        elif mode.lower() == "cold":
            self.interface.reset()
        else:
            raise ValueError("Unsupported reset mode")

        if self.reset_callback:
            try:
                self.reset_callback(mode.lower())
            except:
                logger.exception("Failed to trigger reset callback")


    def __build_command_string(self, cmd):
        """ assembles the appropriate command string """
        cmd_string = cmd.command

        # Append explicitly defined frame count
        if cmd.frames != None:
            cmd_string += str(cmd.frames).encode()

        # if we know the number of frames that this command returns,
        # only wait for exactly that number. This avoids some harsh
        # timeouts from the ELM, thus speeding up queries.
        elif self.fast and cmd.fast and (cmd in self.__frame_counts):
            cmd_string += str(self.__frame_counts[cmd]).encode()

        # if we sent this last time, just send a CR
        # (CR is added by the ELM327 class)
        if self.fast and (cmd_string == self.__last_command):
            cmd_string = b""

        return cmd_string
