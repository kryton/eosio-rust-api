# EOSIO-API
The aim of this project is to allow rust apps the ability to talk to a nodeos server.

## how to use
see [tictactoe](examples/tictactoe.rs) for a toy sample.

### notes
* it expects to be run with keosd 
`--http-server-address 127.0.0.1:3888` 
for testing.
* built against 2.0/2.1 nodeos.
* uses [abieos](https://github.com/eosio/abieos) to do EOSIO serialization/de-serialization
* currently uses 'push_transaction' to push actions.

### warnings
canonical signing is done via keosd compatible wallet API. 

it's probably not a good idea to pass private keys in here.
