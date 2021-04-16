# vault-decrypt-legacy
This utility will decrypt any value from Vault storage provided you have the unseal keys.

It works only with pre version 1 Vault data and was tested with version 0.8.5

# Usage

```
 ❯ ./vault-decrypt-legacy
INFO[0000] Vault-decrypt starting version 0.3
  -debug
        Enable debug output (optional)
  -encrypted-file string
        Path to the file to decrypt
  -key-ring string
        Path to a file with the keyring (default "tmp/data/core/keyring")
  -unseal-keys string
        Path to a file with the unseal keys, one per line

INFO[0000] Vault-decrypt starting version 0.3
INFO[0000] Decrypted data:([]uint8) (len=606 cap=610) {
 00000000  7b 22 6c 65 61 73 65 5f  69 64 22 3a 22 61 75 74  |{"lease_id":"aut|
...
 00000250  30 31 54 30 30 3a 30 30  3a 30 30 5a 22 7d        |01T00:00:00Z"}|
}
{
        "lease_id": "auth/token/create/cf/1d3535a653be7c91a131c744dab191c9a3a43e7b",
        "client_token": "b0ac6edc-8392-1969-3268-16421d60b7d1",
...
        "last_renewal_time": "0001-01-01T00:00:00Z"
}⏎
```
