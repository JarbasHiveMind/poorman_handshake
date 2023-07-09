from setuptools import setup

setup(
    name='poorman_handshake',
    version='0.2.1',
    packages=['poorman_handshake', 'poorman_handshake.asymmetric',
              'poorman_handshake.symmetric'],
    url='https://github.com/JarbasHiveMind/poorman_handshake',
    license='Apache-2.0',
    author='jarbasAi',
    install_requires=["PGPy"],
    author_email='jarbasai@mailfence.com',
    description='poor man\'s key exchange, powered by RSA'
)
