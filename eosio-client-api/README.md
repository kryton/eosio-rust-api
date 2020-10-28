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
* you need to create the wallet, put the password in the .env file
* do a search/replace of EOS7ctUUZhtCGHnxUnh4Rg5eethj3qNS5S9fijyLMKgRsBLh8eMBB and replace it with your public key for testing

### warnings
canonical signing is done via keosd compatible wallet API. 

it's probably not a good idea to pass private keys in here.
