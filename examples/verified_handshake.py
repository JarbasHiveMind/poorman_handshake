from poorman_handshake import HandShake

server = HandShake()
client = HandShake()

# send this from client to server over any insecure channel
pub = client.pubkey

shake = server.communicate_secret(pub)
server_pub = server.communicate_pub(pub)  # for verification

# send shake + pub from server to client over any insecure channel
client.receive_and_verify(shake, server_pub)

assert client.aes_key == server.aes_key

print(client.aes_key)