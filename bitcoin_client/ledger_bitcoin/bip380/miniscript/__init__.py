"""
Miniscript
==========

Miniscript is an extension to Bitcoin Output Script descriptors. It is a language for \
writing (a subset of) Bitcoin Scripts in a structured way, enabling analysis, composition, \
generic signing and more.

For more information about Miniscript, see https://bitcoin.sipa.be/miniscript.
"""

from .fragments import Node
from .satisfaction import SatisfactionMaterial
