"""
All the exceptions raised when dealing with Miniscript.
"""


class MiniscriptMalformed(ValueError):
    def __init__(self, message):
        self.message = message


class MiniscriptNodeCreationError(ValueError):
    def __init__(self, message):
        self.message = message


class MiniscriptPropertyError(ValueError):
    def __init__(self, message):
        self.message = message

# TODO: errors for type errors, parsing errors, etc..
