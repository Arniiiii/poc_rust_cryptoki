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

    let slot = pkcs11.get_slots_with_token()?[0];

    println!("slots: \n{}", slot.to_string());

    // initialize a test token
    let so_pin =
        AuthPin::new(env::var("PKCS11_SO_PIN").unwrap_or_else(|_| "1234567890".to_string()));
    pkcs11.init_token(slot, &so_pin, "Test Token")?;

    let user_pin =
        AuthPin::new(env::var("PKCS11_USER_PIN").unwrap_or_else(|_| "0987654321".to_string()));

    // initialize user PIN
    {
        let session = pkcs11.open_rw_session(slot)?;
        session.login(UserType::So, Some(&so_pin))?;
        session.init_pin(&user_pin)?;
    }

    // login as a user, the token has to be already initialized
    let session = pkcs11.open_rw_session(slot)?;
    session.login(UserType::User, Some(&user_pin))?;

    // finally initializing complete, doing actual stuff.

    // ECDSA PART

    // openssl ecparam -name secp256k1 -outform der | xxd -p | sed -Ez 's/\n//;s/../0x&, /g;s/, $//;s/(.*)/let elliptic_curve_params = vec![\1];\n/'
    let elliptic_curve_params = vec![0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a];

    // template of the public key
    let pub_key_template = vec![
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::Verify(true),
        Attribute::Encrypt(true),
        Attribute::EcParams(elliptic_curve_params),
        Attribute::Label("ec_pub".into()),
    ];

    let priv_key_template = vec![
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sign(true),
        Attribute::Decrypt(true),
        Attribute::Sensitive(true),
        Attribute::Label("ec_private".into()),
    ];

    // generate an RSA key according to passed templates
    let (public, private) = session.generate_key_pair(
        &Mechanism::EccKeyPairGen,
        &pub_key_template,
        &priv_key_template,
    )?;

    let data_to_sign = vec![1, 2, 3, 4, 5, 6, 7];

    let signature = session.sign(&Mechanism::Ecdsa, private, &data_to_sign)?;

    session.verify(&Mechanism::Ecdsa, public, &data_to_sign, &signature)?;

    println!("Successfully verified a signature: '{:?}'", signature);

    Ok(())
}
