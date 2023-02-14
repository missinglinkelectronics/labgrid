# pylint: disable=no-member
import subprocess
import os
import re
import attr
import imp
import tempfile
from pathlib import Path

from ..factory import target_factory
from ..step import step
from .common import Driver
from .exception import ExecutionError
from ..util.helper import processwrapper
from ..util.managedfile import ManagedFile
import logging

JTAG_CONF_INTEL = """
Remote1 {
	Host = "HOST";
	Password = "PASSWORD";
}
"""

@target_factory.reg_driver
@attr.s(eq=False)
class QuartusPGMDriver(Driver):

    bindings = {
        "interface": {"QuartusUSBJTAG", "NetworkQuartusUSBJTAG"},
    }

    image = attr.ib(
        default=None,
        validator=attr.validators.optional(attr.validators.instance_of(str))
    )

    def __attrs_post_init__(self):
        super().__attrs_post_init__()

        if self.target.env:
            self.tool = self.target.env.config.get_tool('quartus_pgm') or 'quartus_pgm'
        else:
            self.tool = 'quartus_pgm'

    @Driver.check_active
    @step(args=['filename', 'devnum'])
    def flash(self, filename=None, devnum=1):
        return self.operate(filename, "P", devnum)

    #INFORMATION: for some reason quartus_pgm requires a valid programming file in order to erase the chip!
    @Driver.check_active
    @step(args=['filename', 'devnum'])
    def erase(self, filename=None, devnum=1):
        return self.operate(filename, "R", devnum)

    @Driver.check_active
    @step(args=['filename', 'operation', 'devnum'])
    def operate(self, filename=None, operation="P", devnum=1):
        if filename is None and self.image is not None:
            filename = self.target.env.config.get_image_path(self.image)

        log = logging.getLogger("QPGM_Driver")

        try:
            lib_path = imp.find_module("libfilsel")[1]
        except Exception as e:
            return False, "could not find libfilsel!", str(e)

        my_env = os.environ.copy()
        my_env["LD_PRELOAD"] = os.pathsep.join(filter(None, [lib_path, os.environ.get('LD_PRELOAD')]))
        my_env["FILSEL_ORG_PATH"] = str((Path(os.path.expanduser('~')) / ".jtag.conf").resolve())

        cable = f"--cable=\"{self.interface.device_name} on " + \
                f"{self.interface.host}:{self.interface.jtagd_port} " + \
                f"{self.interface.device_port}\""

        operation = f"--operation=\"{operation};{filename}@{str(devnum)}\""
        cmd = f"{self.tool} {cable} --mode=JTAG {operation}"

        with tempfile.NamedTemporaryFile() as conf_temp:

            cfg = JTAG_CONF_INTEL.replace("HOST", self.interface.host + ":" + str(self.interface.jtagd_port))\
                                 .replace("PASSWORD", self.interface.jtagd_password)
            conf_temp.write(cfg.encode("utf-8"))
            conf_temp.flush()
            log.info("Flashing with command: " + str(cmd))
            my_env["FILSEL_DEST_PATH"] = conf_temp.name

            stdout, stderr = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=my_env).communicate()

        if "Quartus Prime Programmer was successful." in stdout.decode("utf-8"):
            return True, stdout.decode("utf-8"), stderr.decode("utf-8")
        else:
            return False, stdout.decode("utf-8"), stderr.decode("utf-8")

