# EOSIO API 4 Rust
## What is it?

An API to allow Rust services to communicate with a [EOSIO](https://github.com/EOSIO/eos) node.

## What is it not?

This is not an API to allow you to write contracts in rust. 

It interacts via the REST API so you can use it in your middleware/webapps etc to execute actions 
and query the EOSIO node.

## Status

 _early_ stages.

It should be able to:
 * sign things (with the help of keosd) 
 * verify keys.
 * pack/unpack abieos serialization using [abieos](https://github.com/EOSIO/abieos)

I am also new to Rust. Feel free to raise issues on style/technique/idiomatic issues. I'm here to learn.

and yes. I've been told '_I code pretty well for a manager_' before.

## Build notes

`$ git submodule update --init --recursive`

you also need to apply the patch to abieos to enable it to create a static C library PR#51.
