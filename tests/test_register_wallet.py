from bitcoin_client.bitcoin_cmd_builder import AddrType

# default speculos seed: glory promote mansion idle axis finger extra february uncover one trip resource lawn turtle enact monster seven myth punch hobby comfort wild raise skin

def test_register_wallet(cmd):
    res = cmd.register_wallet(
        wallet_type=0,
        name="My test wallet",
        threshold=2,
        n_keys=3,
        pubkeys=["xpub1", "xpub2", "xpub3"]
    )

    # TODO
    print(res.hex())