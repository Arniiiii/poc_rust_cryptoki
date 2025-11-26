// Copyright 2024 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::Attribute;
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;
use std::env;

fn main() -> eyre::Result<()> {
    // initialize a new Pkcs11 object using the module from the env variable
    let pkcs11 = Pkcs11::new(
        env::var("TEST_PKCS11_MODULE")
            .unwrap_or_else(|_| "/usr/lib64/softhsm/libsofthsm2.so".to_string()),
    )?;

    pkcs11.initialize(CInitializeArgs::OsThreads)?;

    let slot = pkcs11.get_all_slots()?;

    println!("slots: \n{:?}", slot);

    let slot = pkcs11.get_slots_with_token()?;

    println!("slots with token: \n{:?}", slot);

    let slot = pkcs11.get_slots_with_initialized_token()?;

    println!("slots with initialized token: \n{:?}", slot);

    Ok(())
}
