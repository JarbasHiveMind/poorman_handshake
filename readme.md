# Poor Man's Handshake

securely exchange symmetric encryption keys over insecure channels

## Usage

```python
from poorman_handshake import HandShake

server = HandShake()
client = HandShake()

# send this from client to server over any insecure channel
pub = client.pubkey

# this key will be used after handshake for encryption
server.generate_key()
shake = server.communicate_key(pub)

# send shake from server to client over any insecure channel
client.receive_key(shake)

assert client.aes_key == server.aes_key
```

## How does it work

ephemeral PGP keys are created and used only to exchange a symmetric key to 
be used in follow up communications, it's dead simple