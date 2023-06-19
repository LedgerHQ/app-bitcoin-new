class DescriptorParsingError(ValueError):
    """Error while parsing a Bitcoin Output Descriptor from its string representation"""

    def __init__(self, message):
        self.message = message
