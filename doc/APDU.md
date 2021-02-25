# Application Protocol Data Unit (APDU)

The communication protocol used by [BOLOS](https://ledger.readthedocs.io/en/latest/bolos/overview.html) to exchange [APDU](https://en.wikipedia.org/wiki/Smart_card_application_protocol_data_unit) is very close to [ISO 7816-4](https://www.iso.org/standard/77180.html) with a few differences:

- `Lc` length is always exactly 1 byte
- No `Le` field in APDU command
- Maximum size of APDU command is 260 bytes: 5 bytes of header + 255 bytes of data
- Maximum size of APDU response is 260 bytes: 258 bytes of response data + 2 bytes of status word

Status words tend to be similar to common [APDU responses](https://www.eftlab.com/knowledge-base/complete-list-of-apdu-responses/) in the industry.

## Command APDU

| Field name | Length (bytes) | Description |
| --- | --- | --- |
| CLA | 1 | Instruction class - indicates the type of command |
| INS | 1 | Instruction code - indicates the specific command |
| P1 | 1 | Instruction parameter 1 for the command |
| P2 | 1 | Instruction parameter 2 for the command |
| Lc | 1 | The number of bytes of command data to follow (a value from 0 to 255) |
| CData | var | Command data with `Lc` bytes |

## Response APDU

| Field name | Length (bytes) | Description |
| --- | --- | --- |
| RData | var | Reponse data (can be empty) |
| SW | 2 | Status word containing command processing status (e.g. `0x9000` for success) |
