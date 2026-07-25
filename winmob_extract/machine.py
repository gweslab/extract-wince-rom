"""PE machine-type resolution for reconstructed modules.

romimage stamps the image's IMAGE_FILE_MACHINE value into
ROMHDR.usCPUType, which is authoritative when populated. An image that
leaves it 0 records the CPU nowhere else, so the caller supplies it with
--machine.
"""


# IMAGE_FILE_MACHINE_* values romimage emits in ROMHDR.usCPUType
# (winnt.h IMAGE_FILE_MACHINE_ARM / THUMB / ARMNT / I386 / SH3 / SH3DSP /
# SH4 / R3000 / R4000 / R10000 / WCEMIPSV2 / MIPS16 / MIPSFPU / MIPSFPU16).
KNOWN_MACHINES = (
    0x01C0, 0x01C2, 0x01C4, 0x014C,
    0x01A2, 0x01A3, 0x01A6,
    0x0162, 0x0166, 0x0168, 0x0169, 0x0266, 0x0366, 0x0466,
)

MACHINE_NAMES = {
    'arm': 0x01C0, 'thumb': 0x01C2, 'armv7': 0x01C4,
    'mips': 0x0166, 'mips16': 0x0266, 'mipsfpu': 0x0366,
    'sh3': 0x01A2, 'sh4': 0x01A6, 'x86': 0x014C,
}


class MachineUnknown(Exception):
    """The image names no usable CPU and no --machine was supplied."""


def resolve_machine(cpu_type, machine_override):
    """Return the IMAGE_FILE_MACHINE value to stamp into emitted PEs.

    Raises MachineUnknown when the ROMHDR carries no usable usCPUType and
    the caller passed no --machine.
    """
    if machine_override is not None:
        return machine_override
    if cpu_type in KNOWN_MACHINES:
        return cpu_type
    raise MachineUnknown(
        "ROMHDR usCPUType is 0x{:04X}, which names no known CPU. Pass "
        "--machine <arch> to stamp the output PEs. One of: {}.".format(
            cpu_type, ', '.join(sorted(MACHINE_NAMES)))
    )
