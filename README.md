# EOSIO API 4 Rust
## What is it?

An API to allow Rust services to communicate with a [EOSIO](https://github.com/EOSIO/eos) node.

## What is it not?

This is not an API to allow you to write contracts in rust.  (see [eosio-rust](https://github.com/sagan-software/eosio-rust) for that)

This code interacts via the REST API so you can use it in your middleware/webapps etc to execute actions 
and query the EOSIO node.

## Status

 _early_ stages.

It should be able to:
 * sign things (with the help of keosd) 
 * verify keys.
 * pack/unpack abieos serialization using [abieos](https://github.com/EOSIO/abieos)
 * 'play' [tic-tac-toe](/eosio-client-api/examples/tictactoe.rs), using the popular EOSIO TTT Contract.

I am also new to Rust. Feel free to raise issues on style/technique/idiomatic issues. I'm here to learn.


## Build notes

`$ git submodule update --init --recursive`

this currently uses a forked version of [abieos](https://github.com/kryton/abieos) due to some json parsing differences.
