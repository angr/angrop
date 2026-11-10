import pytest

import angr
import angrop  # noqa: F401
from angrop.errors import RopException


def _builder():
    project = angr.Project("/bin/true", arch="amd64", auto_load_libs=False)
    return project, project.analyses.ROP().chain_builder


def test_ret2csu_payload_layout():
    project, builder = _builder()
    chain = builder.ret2csu(
        0x401000,
        0x402000,
        0x403000,
        1,
        [2, 0x404000, 0x405000],
    )
    assert chain.payload_len == (8 + 7) * project.arch.bytes
    assert chain.payload_str()[:8] == (0x401000).to_bytes(8, "little")


def test_ret2csu_rejects_truncated_first_argument():
    _, builder = _builder()
    with pytest.raises(RopException, match="fit 32 bits"):
        builder.ret2csu(0x401000, 0x402000, 0x403000, 0, [1 << 32, 2, 3])


def test_ret2csu_custom_cleanup_and_next_pc():
    project, builder = _builder()
    chain = builder.ret2csu(
        0x401000,
        0x402000,
        0x403000,
        0,
        [1, 2, 3],
        cleanup_slots=2,
        next_pc=0x406000,
    )
    assert chain.payload_len == (8 + 2 + 1) * project.arch.bytes
