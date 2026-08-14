//! Credit card extraction (Go: `browser/chromium/extract_creditcard.go`).

use std::path::Path;

use hbd_core::CreditCardEntry;
use keyring::MasterKeys;

use crate::chromium::decrypt::decrypt_value;
use crate::chromium::error::Result;
use crate::chromium::sqliteutil::{count_rows, query_rows};

const DEFAULT_CREDIT_CARD_QUERY: &str = "SELECT COALESCE(guid, ''), name_on_card, expiration_month, expiration_year,
    card_number_encrypted, COALESCE(nickname, ''), COALESCE(billing_address_id, '') FROM credit_cards";
const COUNT_CREDIT_CARD_QUERY: &str = "SELECT COUNT(*) FROM credit_cards";

const YANDEX_CREDIT_CARD_QUERY: &str = "SELECT guid, public_data, private_data FROM records";
const YANDEX_CREDIT_CARD_COUNT_QUERY: &str = "SELECT COUNT(*) FROM records";

/// Extracts cards from Chromium's flat `credit_cards` table
/// (Go: `extractCreditCards`).
pub fn extract_credit_cards(master_keys: &MasterKeys, path: &Path) -> Result<Vec<CreditCardEntry>> {
    Ok(query_rows(path, false, DEFAULT_CREDIT_CARD_QUERY, |row| {
        let guid: String = row.get(0)?;
        let name: String = row.get(1)?;
        let month: String = row.get(2)?;
        let year: String = row.get(3)?;
        let enc_number: Vec<u8> = row.get(4)?;
        let nickname: String = row.get(5)?;
        let address: String = row.get(6)?;

        let number = decrypt_value(master_keys, &enc_number).unwrap_or_default();
        Ok(CreditCardEntry {
            guid,
            name,
            number: String::from_utf8_lossy(&number).into_owned(),
            exp_month: month,
            exp_year: year,
            nick_name: nickname,
            address,
            cvc: String::new(),
            comment: String::new(),
        })
    })?)
}

/// Yandex reads a `records(guid, public_data, private_data)` table with JSON
/// blobs; the private half is AES-GCM-sealed with AAD = guid.
/// (Go: `extractYandexCreditCards`.)
pub fn extract_yandex_credit_cards(
    master_keys: &MasterKeys,
    path: &Path,
) -> Result<Vec<CreditCardEntry>> {
    let data_key =
        match crate::chromium::yandex::load_yandex_data_key(path, master_keys.v10.as_deref()) {
            Ok(k) => k,
            Err(e) if e.is_master_password() => {
                log::warn!("{}: {}", path.display(), e);
                return Ok(Vec::new());
            }
            Err(e) => return Err(e.into()),
        };

    Ok(query_rows(path, false, YANDEX_CREDIT_CARD_QUERY, |row| {
        let guid: String = row.get(0)?;
        let public_data: String = row.get(1)?;
        let private_data: Vec<u8> = row.get(2)?;

        let mut public = PublicData::default();
        if !public_data.is_empty() {
            if let Ok(v) = serde_json::from_str::<PublicData>(&public_data) {
                public = v;
            } else {
                log::debug!("yandex: parse public_data for {}: invalid json", guid);
            }
        }
        let mut entry = CreditCardEntry {
            guid: guid.clone(),
            name: public.card_holder,
            exp_month: public.expire_date_month,
            exp_year: public.expire_date_year,
            nick_name: public.card_title,
            number: String::new(),
            address: String::new(),
            cvc: String::new(),
            comment: String::new(),
        };

        let aad = crate::chromium::yandex::yandex_card_aad(&guid);
        let Ok(plaintext) = hbd_crypto::aead::aes_gcm_decrypt_blob(&data_key, &private_data, &aad)
        else {
            log::debug!("yandex: decrypt card {}: gcm failed", guid);
            return Ok(entry);
        };
        let Ok(private) = serde_json::from_str::<PrivateData>(&String::from_utf8_lossy(&plaintext))
        else {
            log::debug!("yandex: parse private_data for {}: invalid json", guid);
            return Ok(entry);
        };
        entry.number = private.full_card_number;
        entry.cvc = private.pin_code;
        entry.comment = private.secret_comment;
        Ok(entry)
    })?)
}

/// Plaintext JSON half of a Yandex card record (Go: `yandexPublicData`).
#[derive(Debug, Default, serde::Deserialize)]
pub(crate) struct PublicData {
    pub card_holder: String,
    pub card_title: String,
    pub expire_date_year: String,
    pub expire_date_month: String,
}

/// JSON decoded from the AES-GCM-sealed private blob (Go: `yandexPrivateData`).
#[derive(Debug, Default, serde::Deserialize)]
pub(crate) struct PrivateData {
    pub full_card_number: String,
    pub pin_code: String,
    pub secret_comment: String,
}

pub fn count_credit_cards(path: &Path) -> Result<i64> {
    Ok(count_rows(path, false, COUNT_CREDIT_CARD_QUERY)?)
}

pub fn count_yandex_credit_cards(path: &Path) -> Result<i64> {
    Ok(count_rows(path, false, YANDEX_CREDIT_CARD_COUNT_QUERY)?)
}
