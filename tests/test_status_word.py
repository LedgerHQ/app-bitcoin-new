from pathlib import Path
from typing import List, Dict, Any, Tuple
import re

from boilerplate_client.exception import DeviceException


SW_RE = re.compile(r"""(?x)
    \#                                 # character '#'
    define                             # string 'define'
    \s+                                # spaces
    (?P<identifier>SW(?:_[A-Z0-9]+)*)  # identifier (e.g. 'SW_OK')
    \s+                                # spaces
    0x(?P<sw>[a-fA-F0-9]{4})           # 4 bytes status word
""")


def parse_sw(path: Path) -> List[Tuple[str, int]]:
    if not path.is_file():
        raise FileNotFoundError(f"Can't find file: '{path}'")

    sw_h: str = path.read_text()

    return [(identifier, int(sw, base=16))
            for identifier, sw in SW_RE.findall(sw_h) if sw != "9000"]


def test_status_word(sw_h_path):
    expected_status_words: List[Tuple[str, int]] = parse_sw(sw_h_path)
    status_words: Dict[int, Any] = DeviceException.exc

    assert len(expected_status_words) == len(status_words), (
        f"{expected_status_words} doesn't match {status_words}")

    # just keep status words
    expected_status_words = [sw for (identifier, sw) in expected_status_words]

    for sw in status_words.keys():
        assert sw in expected_status_words, f"{status_words[sw]}({hex(sw)}) not found in sw.h!"
