# pylint: disable=no-member
import subprocess
import os
import attr
import importlib
import logging
import tempfile
from pathlib import Path

from ..factory import target_factory
from ..step import step
from .common import Driver

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
    def operate(self, filename=None, operation="P", devnum=1) -> tuple[str, str]:
        if filename is None and self.image is not None:
            filename = self.target.env.config.get_image_path(self.image)

        log = logging.getLogger("QPGM_Driver")

        lib_path = importlib.machinery.PathFinder.find_spec('libfilsel').origin

        ld_preload = [lib_path, os.getenv('LD_PRELOAD', "")]
        os.environ["LD_PRELOAD"] = os.pathsep.join(ld_preload)
        os.environ["FILSEL_ORG_PATH"] = str((Path(os.path.expanduser('~')) / ".jtag.conf").resolve())

        cable = f"'{self.interface.device_name} on {self.interface.host}:{self.interface.jtagd_port} {self.interface.device_port}'"
        operation = f"'{operation};{filename}@{str(devnum)}'"
        cmd = f"{self.tool} -c {cable} -m JTAG -o {operation}"

        with tempfile.NamedTemporaryFile() as conf_temp:

            cfg = self.interface.extra['jtag_conf']
            conf_temp.write(cfg.encode("utf-8"))
            conf_temp.flush()
            log.info("Flashing with command: %s", cmd)
            os.environ["FILSEL_DEST_PATH"] = conf_temp.name

            process = subprocess.Popen(cmd, shell=True,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()

        if "Quartus Prime Programmer was successful." in stdout.decode("utf-8"):
            return stdout.decode("utf-8"), stderr.decode("utf-8")
        else:
            raise subprocess.CalledProcessError(process.returncode,
                    cmd, output=stdout, stderr=stderr)

