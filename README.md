# EOSIO API 4 Rust
## What is it?

An API to allow Rust services to communicate with a [EOSIO](https://github.com/EOSIO/eos) node.

## What is it not?

This is not an API to allow you to write contracts in rust.  (see [eosio-rust](https://github.com/sagan-software/eosio-rust) for that)

This code interacts via the REST API so you can use it in your middleware/webapps etc to execute actions 
and query the EOSIO node.
## Components
* [libabieos-sys](/libabieos-sys) [de-]serialization of the [ABIEOS](https://github.com/EOSIO/abieos) protocol from/to json 
* [client-keys](/eosio-client-keys) key generation, signing, and hashing tools
* [client-api](/eosio-client-api) library to interact with the HTTP EOSIO endpoint
## Status

 _early_ stages.

It should be able to:
 * sign things (with the help of keosd) 
 * verify keys.
 * pack/unpack abieos serialization using [abieos](https://github.com/EOSIO/abieos)
 * 'play' [tic-tac-toe](/eosio-client-api/examples/tictactoe.rs), using the contract from the [EOSIO Tic Tac Toe Smart Contract tutorial](https://developers.eos.io/welcome/v2.0/tutorials/tic-tac-toe-game-contract).

I am also new to Rust. Feel free to raise issues on style/technique/idiomatic issues. I'm here to learn.


## Build notes

`$ git submodule update --init --recursive`

* This currently uses a forked version of [abieos](https://github.com/kryton/abieos) due to some json parsing differences.
* This should work with the current release of EOSIO (2.0.x), although I actually use the _develop_ branch for development. 
