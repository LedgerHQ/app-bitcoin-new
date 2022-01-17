DEFAULT_SPECULOS_MNEMONIC = "glory promote mansion idle axis finger extra february uncover one trip resource lawn turtle enact monster seven myth punch hobby comfort wild raise skin"

default_settings = {
    "mnemonic": DEFAULT_SPECULOS_MNEMONIC,  # mnemonic to use when running speculos
    "automation_file": None  # path of the automation file to use for speculos if used, or None
}


def test_settings(s: dict):
    """Decorator that adds the given settings to the "test_settings" field of a test function."""
    def decorator(func):
        if not hasattr(func, 'test_settings'):
            func.test_settings = default_settings.copy()
        func.test_settings.update(s)
        return func
    return decorator


def automation(filename: str):
    """Adds the automation_file setting to use `filename` as the Speculos automation file."""
    return test_settings({"automation_file": filename})
