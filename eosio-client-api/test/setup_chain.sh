#!/usr/bin/env bash
# the following sets up the test accounts
wallet_pass=$(cat ../.env)
cleos wallet unlock --password ${wallet_pass}
cleos create account eosio tafoacvsqlmw EOS7dEQPzEToTPDsTGvZtngBExBaNXTCveYdokAjDxbQpV6WxLG4s EOS7A3h9cbRHsPBTgh9NJ8Z8bZN2PW5vHGhZnnkc8SAVtpHK3wHDF
cleos create account eosio lkrqvqpxhnqe EOS5HzkzvFvGH9tcPoTmXEyuMNac6qsm972CZmnNm3Q3jjKCPPjRY EOS64QhKFBXso2jjdvvUhMZBsAu4v1ZqVGom1e8e7PbAr49ZeD4d8
cleos create account eosio fwonhjnefmps EOS8fdsPr1aKsmszNHeY4RrgupbabNQ5nmLgQWMEkTn2dENrPbRgP EOS7ctUUZhtCGHnxUnh4Rg5eethj3qNS5S9fijyLMKgRsBLh8eMBB
cleos set contract fwonhjnefmps $PWD good-2.wasm good-2.abi
