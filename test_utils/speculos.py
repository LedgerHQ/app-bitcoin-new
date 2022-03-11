from contextlib import contextmanager
import json
from typing import Union

from bitcoin_client.ledger_bitcoin.client_base import TransportClient
from speculos.client import SpeculosClient


@contextmanager
def automation(client: Union[TransportClient, SpeculosClient], file_or_automation: Union[str, dict]):
    if not isinstance(client, SpeculosClient):
        # not speculos, ignore automation rules
        yield
    else:
        if isinstance(file_or_automation, str):
            aut_obj = json.load(open(file_or_automation))
            if not isinstance(aut_obj, dict):
                raise ValueError("Invalid automation file")
        else:
            aut_obj = file_or_automation

        client.set_automation_rules(aut_obj)

        yield

        # clear automation rules
        client.set_automation_rules({"version": 1, "rules": []})
