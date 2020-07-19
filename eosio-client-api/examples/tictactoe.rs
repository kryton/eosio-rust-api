// `error_chain!` can recurse deeply
#![recursion_limit = "1024"]

// Import the macro. Don't forget to add `error-chain` in your
// `Cargo.toml`!
#[macro_use]
extern crate error_chain;

mod errors {
    error_chain! {
    foreign_links {
            EOSIOAPI(eosio_client_api::errors::Error);
            LIBEOSIOAPI(libabieos_sys::errors::Error);
            STDIO(std::io::Error);
        }
    }
}

use crate::errors::{Error, Result};
use chrono::Duration;
use eosio_client_api::api_types::{vec_u8_to_hex, ActionIn, AuthorizationIn, GetInfo};
use eosio_client_api::json_rpc::{create_setabi_action, create_setcode_action, AbiTrio, EOSRPC};
use eosio_client_api::wallet_types::{get_wallet_pass, Wallet};
use eosio_client_api::wasm::WASM;
use libabieos_sys::ABIEOS;
use std::{env, fs};
//use serde_json::Value;
use serde_json::json;

async fn upgrade_wasm(
    wallet: &Wallet,
    eos: &EOSRPC,
    wasm: &WASM,
    abi: &str,
    account: &str,
    info: &GetInfo,
) -> Result<()> {
    let hash = wasm.hash();
    let hash_str = vec_u8_to_hex(&hash)?;
    let stored_hash = eos.get_code_hash(account).await?;

    if stored_hash.code_hash != hash_str {
        //  let _eosio_raw = eos.get_raw_abi("eosio")?.decode_abi()?;
        let exp_time = info.set_exp_time(Duration::seconds(3600));
        let abi_trio = AbiTrio::create("eosio", "eosio", &eos).await?;
        let action_code =
            create_setcode_action(&abi_trio.acct_abi, account, wasm).map_err(|e| {
                abi_trio.destroy();
                Error::with_chain(e, "upgrade_wasm/create_setcode")
            })?;

        let action_abi = create_setabi_action(&abi_trio.sys_abi, &abi_trio.acct_abi, account, abi)
            .map_err(|e| {
                abi_trio.destroy();
                Error::with_chain(e, "upgrade_wasm/create_setabi")
            })?;

        let actions: Vec<ActionIn> = vec![action_code, action_abi];

        let _tr = eos
            .push_transaction(
                &abi_trio.txn_abi,
                &wallet,
                actions,
                &info.head_block_id,
                exp_time,
            )
            .await
            .map_err(|e| {
                abi_trio.destroy();
                Error::with_chain(e, "upgrade_wasm/push_transaction")
            })?;

        println!("Code & ABI has been uploaded");
        Ok(())
    } else {
        println!("Code is already there");
        Ok(())
    }
}

pub fn create_game_action(
    abieos: &ABIEOS,
    main: &str,
    host: &str,
    challenger: &str,
) -> Result<ActionIn> {
    let auth = AuthorizationIn {
        permission: "active".to_string(),
        actor: String::from(host),
    };
    let v_auth: Vec<AuthorizationIn> = vec![auth];
    let js = json!( {
        "challenger": String::from(challenger),
        "host":String::from(host),
    })
    .to_string();
    let hex = abieos.json_to_hex(main, "create", &js)?;
    let data = String::from(hex);

    Ok(ActionIn {
        name: "create".to_string(),
        account: main.to_string(),
        authorization: v_auth,
        data,
    })
}

pub fn close_game_action(
    abieos: &ABIEOS,
    main: &str,
    host: &str,
    challenger: &str,
) -> Result<ActionIn> {
    let auth = AuthorizationIn {
        permission: "active".to_string(),
        actor: String::from(host),
    };
    let v_auth: Vec<AuthorizationIn> = vec![auth];
    let js = json!( {
        "challenger": String::from(challenger),
        "host":String::from(host),
    })
    .to_string();

    let hex = abieos.json_to_hex(main, "create", &js)?;
    let data = String::from(hex);

    Ok(ActionIn {
        name: "close".to_string(),
        account: main.to_string(),
        authorization: v_auth,
        data,
    })
}

pub fn move_game_action(
    abieos: &ABIEOS,
    main: &str,
    host: &str,
    challenger: &str,
    by: &str,
    row: u16,
    col: u16,
) -> Result<ActionIn> {
    // person doing the move 'by' authorizes it.
    let auth = AuthorizationIn {
        permission: "active".to_string(),
        actor: String::from(by),
    };
    let v_auth: Vec<AuthorizationIn> = vec![auth];
    let js = json!( {
        "challenger": String::from(challenger),
        "host":String::from(host),
        "by":String::from(by),
        "row":row,
        "column":col
    })
    .to_string();

    let hex = abieos.json_to_hex(main, "move", &js)?;
    let data = String::from(hex);

    Ok(ActionIn {
        name: "move".to_string(),
        account: main.to_string(),
        authorization: v_auth,
        data,
    })
}

async fn start_game(
    wallet: &Wallet,
    eos: &EOSRPC,
    game_acct: &str,
    player_host: &str,
    player_challenger: &str,
) -> Result<(usize, String)> {
    let info = eos.get_info().await?;
    let exp_time = info.set_exp_time(Duration::seconds(3600));
    let abi_trio: AbiTrio = AbiTrio::create("eosio", game_acct, eos).await?;
    let ca = create_game_action(
        &abi_trio.acct_abi,
        game_acct,
        player_host,
        player_challenger,
    )
    .map_err(|e| {
        abi_trio.destroy();
        Error::with_chain(e, "start_game/create_game_action")
    })?;
    let tr = eos
        .push_transaction(
            &abi_trio.txn_abi,
            &wallet,
            vec![ca],
            &info.head_block_id,
            exp_time,
        )
        .await
        .map_err(|e| {
            abi_trio.destroy();
            Error::with_chain(e, "start_game/push_transaction")
        })?;
    abi_trio.destroy();
    Ok((tr.processed.block_num, tr.transaction_id))
}

async fn end_game(
    wallet: &Wallet,
    eos: &EOSRPC,
    game_acct: &str,
    player_host: &str,
    player_challenger: &str,
) -> Result<(usize, String)> {
    let info = eos.get_info().await?;
    let exp_time = info.set_exp_time(Duration::seconds(3600));
    let abi_trio: AbiTrio = AbiTrio::create("eosio", game_acct, eos).await?;
    let ca = close_game_action(
        &abi_trio.acct_abi,
        game_acct,
        player_host,
        player_challenger,
    )
    .map_err(|e| {
        abi_trio.destroy();
        Error::with_chain(e, "end_game/close_game_action")
    })?;
    let tr = eos
        .push_transaction(
            &abi_trio.txn_abi,
            &wallet,
            vec![ca],
            &info.head_block_id,
            exp_time,
        )
        .await
        .map_err(|e| {
            abi_trio.destroy();
            Error::with_chain(e, "end_game/push_transaction")
        })?;
    abi_trio.destroy();
    Ok((tr.processed.block_num, tr.transaction_id))
}

async fn move_game(
    wallet: &Wallet,
    eos: &EOSRPC,
    game_acct: &str,
    player_host: &str,
    player_challenger: &str,
    by: &str,
    row: u16,
    col: u16,
) -> Result<(usize, String)> {
    let info = eos.get_info().await?;
    let exp_time = info.set_exp_time(Duration::seconds(3600));
    let abi_trio: AbiTrio = AbiTrio::create("eosio", game_acct, eos).await?;
    let ca = move_game_action(
        &abi_trio.acct_abi,
        game_acct,
        player_host,
        player_challenger,
        by,
        row,
        col,
    )
    .map_err(|e| {
        abi_trio.destroy();
        Error::with_chain(e, "move_game/move_game_action")
    })?;
    let tr = eos
        .push_transaction(
            &abi_trio.txn_abi,
            &wallet,
            vec![ca],
            &info.head_block_id,
            exp_time,
        )
        .await
        .map_err(|e| {
            abi_trio.destroy();
            Error::with_chain(e, "move_game/push_transaction")
        })?;
    abi_trio.destroy();
    Ok((tr.processed.block_num, tr.transaction_id))
}

async fn get_board(eos: &EOSRPC, game_acct: &str) -> Result<()> {
    let abi_trio: AbiTrio = AbiTrio::create("eosio", game_acct, eos).await?;

    let tr = eos
        .get_table_rows(
            &game_acct,
            "tictactoe",
            "games",
            "",
            "",
            "",
            10,
            "",
            "",
            "dec",
            false,
            true,
        )
        .await?;
    for row in tr.rows {
        let data = row.data;

        let str = abi_trio
            .acct_abi
            .hex_to_json(&game_acct, "game", data.as_bytes());
        println!("{:?}", str);
    }
    Ok(())
}

fn get_args() -> Result<(String, String, String, String, String)> {
    let args: Vec<String> = env::args().collect();
    let host = {
        if args.len() > 1 {
            &args[1]
        } else {
            "http://127.0.0.1:8888"
            //  "https://api.testnet.eos.io"
        }
    };
    let wallet_url = {
        if args.len() > 2 {
            &args[2]
        } else {
            "http://127.0.0.1:3888"
        }
    };
    let account = {
        if args.len() > 3 {
            &args[3]
        } else {
            "fwonhjnefmps"
        }
    };
    let player_host = {
        if args.len() > 4 {
            &args[3]
        } else {
            "lkrqvqpxhnqe"
        }
    };
    let player_challenger = {
        if args.len() > 4 {
            &args[3]
        } else {
            "tafoacvsqlmw"
        }
    };
    Ok((
        host.parse().unwrap(),
        wallet_url.parse().unwrap(),
        account.parse().unwrap(),
        player_host.parse().unwrap(),
        player_challenger.parse().unwrap(),
    ))
}

async fn run() -> Result<bool> {
    let (host, wallet_url, account, player_host, player_challenger) = get_args()?;
    let eos = EOSRPC::non_blocking(String::from(host)).await?;
    let info = eos.get_info().await?;
    let wallet = Wallet::create_with_chain_id(
        EOSRPC::non_blocking(String::from(wallet_url)).await?,
        &info.chain_id,
    );
    let wallet_pass = get_wallet_pass()?;

    let ttt_wasm: WASM = WASM::read_file("examples/tictactoe.wasm")?;
    let ttt_abi = fs::read_to_string("examples/tictactoe.abi")?;

    wallet.unlock("default", &wallet_pass).await?;
    upgrade_wasm(&wallet, &eos, &ttt_wasm, &ttt_abi, &account, &info).await?;

    // clears a game if there way one
    let _trans_end = end_game(&wallet, &eos, &account, &player_host, &player_challenger);

    let trans_start = start_game(&wallet, &eos, &account, &player_host, &player_challenger).await?;
    println!("Started {:?}", trans_start);

    let moves = vec![
        (&player_host, 1, 1),
        (&player_challenger, 0, 0),
        (&player_host, 1, 0),
        (&player_challenger, 2, 2),
        (&player_host, 1, 2),
    ];
    for g_move in moves {
        //  println!("Move {} {}/{}", &g_move.0, g_move.1, g_move.2);
        let trans_move = move_game(
            &wallet,
            &eos,
            &account,
            &player_host,
            &player_challenger,
            &g_move.0,
            g_move.1,
            g_move.2,
        )
        .await?;
        println!("Move {} {:?}", &g_move.0, trans_move);
        get_board(&eos, &account).await?;
    }
    // get_board(&eos,&account)?;
    let trans_end = end_game(&wallet, &eos, &account, &player_host, &player_challenger).await?;
    println!("Ended {:?}", trans_end);

    Ok(true)
}

#[tokio::main]
async fn main() {
    println!("This example uploads the tic-tac-toe wasm, and pushes actions on it");
    println!("It also fetches data from RAM to see the 'game'");
    if let Err(ref e) = run().await {
        println!("error: {}", e);

        for e in e.iter().skip(1) {
            println!("caused by: {}", e);
        }

        // The backtrace is not always generated. Try to run this example
        // with `RUST_BACKTRACE=1`.
        if let Some(backtrace) = e.backtrace() {
            println!("backtrace: {:?}", backtrace);
        }

        ::std::process::exit(1);
    }
}
