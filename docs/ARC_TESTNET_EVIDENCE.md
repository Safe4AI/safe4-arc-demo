# Arc Testnet settlement evidence

Safe4's first chain gate is a real USDC transfer performed from standalone
tooling. This isolates RPC, signing, gas, token, and explorer behavior from the
service integration.

## Confirmed transaction

| Field | Value |
|---|---|
| RPC used | `https://rpc.blockdaemon.testnet.arc.io` |
| Chain ID | `5042002` |
| USDC | `0x3600000000000000000000000000000000000000` |
| Sender | `0x4B4DcB8491Eec70decad34F0C627b47C41ae0B26` |
| Recipient | `0x530271DA8CC4e44375f22ad9632bC61A55382f88` |
| Amount | `10000` base units (`0.01 USDC`) |
| Block | `53987658` |
| Transaction | [`0x24e9595078de0778428eea09af2a10ec53828c10aca6e4c5517ef1dd09144a7a`](https://testnet.arcscan.app/tx/0x24e9595078de0778428eea09af2a10ec53828c10aca6e4c5517ef1dd09144a7a) |

## Verify it yourself

No private key is needed:

```bash
python scripts/verify_arc_settlement.py \
  --rpc-url https://rpc.blockdaemon.testnet.arc.io \
  --chain-id 5042002 \
  --usdc-address 0x3600000000000000000000000000000000000000 \
  --tx-hash 0x24e9595078de0778428eea09af2a10ec53828c10aca6e4c5517ef1dd09144a7a \
  --sender 0x4B4DcB8491Eec70decad34F0C627b47C41ae0B26 \
  --recipient 0x530271DA8CC4e44375f22ad9632bC61A55382f88 \
  --amount-units 10000
```

Success prints:

```text
ARC_SETTLEMENT_OK tx=0x24e9595078de0778428eea09af2a10ec53828c10aca6e4c5517ef1dd09144a7a from=0x4B4DcB8491Eec70decad34F0C627b47C41ae0B26 to=0x530271DA8CC4e44375f22ad9632bC61A55382f88 amount_units=10000 block=53987658
```

The verifier fetches both the transaction and receipt. A successful receipt
containing any USDC log is insufficient: the verifier requires the expected
chain, contract, sender, recipient, amount, calldata, status, and event.

## Sending a new testnet transfer

The sender requires an explicit recipient:

```bash
python scripts/arc_testnet_transfer.py --recipient 0xYOUR_TESTNET_RECIPIENT --amount 0.01
```

Set `ARC_PRIVATE_KEY` only in the local process environment. Never put it in a
command argument, committed `.env` file, issue, pull request, or chat.
