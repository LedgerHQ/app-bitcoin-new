# Copyright (c) 2020 The Bitcoin Core developers
# Copyright (c) 2021 Antoine Poinsot
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from .errors import MiniscriptPropertyError


# TODO: implement __eq__
class Property:
    """Miniscript expression property"""

    # "B": Base type
    # "V": Verify type
    # "K": Key type
    # "W": Wrapped type
    # "z": Zero-arg property
    # "o": One-arg property
    # "n": Nonzero arg property
    # "d": Dissatisfiable property
    # "u": Unit property
    types = "BVKW"
    props = "zondu"

    def __init__(self, property_str=""):
        """Create a property, optionally from a str of property and types"""
        allowed = self.types + self.props
        invalid = set(property_str).difference(set(allowed))

        if invalid:
            raise MiniscriptPropertyError(
                f"Invalid property/type character(s) '{''.join(invalid)}'"
                f" (allowed: '{allowed}')"
            )

        for literal in allowed:
            setattr(self, literal, literal in property_str)

        self.check_valid()

    def __repr__(self):
        """Generate string representation of property"""
        return "".join([c for c in self.types + self.props if getattr(self, c)])

    def has_all(self, properties):
        """Given a str of types and properties, return whether we have all of them"""
        return all([getattr(self, pt) for pt in properties])

    def has_any(self, properties):
        """Given a str of types and properties, return whether we have at least one of them"""
        return any([getattr(self, pt) for pt in properties])

    def check_valid(self):
        """Raises a MiniscriptPropertyError if the types/properties conflict"""
        # Can only be of a single type.
        if len(self.type()) > 1:
            raise MiniscriptPropertyError(f"A Miniscript fragment can only be of a single type, got '{self.type()}'")

        # Check for conflicts in type & properties.
        checks = [
            # (type/property, must_be, must_not_be)
            ("K", "u", ""),
            ("V", "", "du"),
            ("z", "", "o"),
            ("n", "", "z"),
        ]
        conflicts = []

        for (attr, must_be, must_not_be) in checks:
            if not getattr(self, attr):
                continue
            if not self.has_all(must_be):
                conflicts.append(f"{attr} must be {must_be}")
            if self.has_any(must_not_be):
                conflicts.append(f"{attr} must not be {must_not_be}")
        if conflicts:
            raise MiniscriptPropertyError(f"Conflicting types and properties: {', '.join(conflicts)}")

    def type(self):
        return "".join(filter(lambda x: x in self.types, str(self)))

    def properties(self):
        return "".join(filter(lambda x: x in self.props, str(self)))
