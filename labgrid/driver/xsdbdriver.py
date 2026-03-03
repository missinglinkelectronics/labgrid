"Xilinx System Debugger (XSDB) driver"
import attr
import subprocess

from .common import Driver
from ..factory import target_factory
from ..resource.udev import XilinxUSBJTAG
from ..resource.remote import NetworkXilinxUSBJTAG
from ..step import step


@target_factory.reg_driver
@attr.s(eq=False)
class XSDBDriver(Driver):
    bindings = {
        "interface": {XilinxUSBJTAG, NetworkXilinxUSBJTAG},
    }

    bitstream = attr.ib(
        default=None,
        validator=attr.validators.optional(attr.validators.instance_of(str))
    )

    def __attrs_post_init__(self):
        super().__attrs_post_init__()

        # FIXME make sure we always have an environment or config
        if self.target.env:
            self.xsdb_bin = self.target.env.config.get_tool('xsdb') or 'xsdb'
        else:
            self.xsdb_bin = 'xsdb'

    @Driver.check_active
    @step(args=['tcl_cmds', 'interactive'])
    def run(self, tcl_cmds, interactive=False):
        url = self.interface.agent_url.split(":")
        if not url[1]:
            url[1] = self.interface.host

        tcl_cmd = "connect -url {}; ".format(":".join(url))
        tcl_cmd += "puts [" + "; ".join(tcl_cmds) + "]"
        if not interactive:
            tcl_cmd += '; disconnect'

        cmd = [self.xsdb_bin, "-quiet", "-eval", tcl_cmd]
        if interactive:
            cmd.append('-interactive')
            proc = subprocess.run(cmd, check=True)
        else:
            proc = subprocess.run(cmd, check=True, capture_output=True, encoding='utf-8')
            return proc.stdout + proc.stderr

    @Driver.check_active
    @step(args=['filename'])
    def program_bitstream(self, filename):
        if filename is None and self.bitstream is not None:
            filename = self.target.env.config.get_image_path(self.bitstream)

        self.run(["fpga {}".format(filename)])

    @Driver.check_active
    @step(args=['bootmode'])
    def force_bootmode_reset(self, bootmode):
        # Check FPGA type
        prop = str(self.run([
            'puts [ jtag targets -filter { is_fpga == "1" } ]'
        ]))
        # MPSoC specific
        if "xczu" in prop or "xcvc" in prop:
            if bootmode == 'jtag': mode = '0x0100'
            elif bootmode == 'sd': mode = '0xE100'
            elif bootmode == 'qspi': mode = '0x2100'
            elif bootmode == 'emmc': mode = '0x6100'
            elif bootmode == 'usb': mode = '0x7100'
            else: raise KeyError(f"invalid boot mode {bootmode}")

            self.run([
                'target -set -filter {name =~ "PSU"}',
                'mwr 0xffca0010 0x0',
                'mwr 0xff5e0200 ' + mode,
                'rst -system',
                'after 1000',
                'con'
            ])
        elif "xc7z" in prop: raise NotImplementedError("Zynq7000 is not implemented yet")
        else: raise NotImplementedError("connected device is not supported")
