from ragger_bitcoin import RaggerClient


def test_get_version(client: RaggerClient, app_version: str):
    returned_app_name, returned_app_version, returned_app_flags = client.get_version()

    assert returned_app_version == app_version, "App version in Makefile did not match the one returned by the app"
