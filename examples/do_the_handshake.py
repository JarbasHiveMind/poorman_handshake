from poorman_handshake import HandShake

server = HandShake()
client = HandShake()

# send this from client to server over any insecure channel
pub = client.pubkey

shake = server.communicate_key(pub)

# send shake from server to client over any insecure channel
client.receive_key(shake)

assert client.aes_key == server.aes_key

print(client.aes_key)