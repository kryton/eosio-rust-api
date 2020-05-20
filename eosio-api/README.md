# EOSIO-API
The aim of this project is to allow rust apps the ability to talk to a nodeos server.

### notes
* keosd --http-server-address 127.0.0.1:3888
* built against 2.0/2.1 nodeos.

### warnings
canonical signing is done via keosd compatible wallet API. 

it's probably not a good idea to pass private keys in here.
