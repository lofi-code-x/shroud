use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use shroud_core::auth::{AUTH_TAG_LEN, compute_auth_tag_bytes};
use shroud_core::config::AuthorizedClient;

pub fn validate_auth(
    known_clients: &[AuthorizedClient],
    client_id: &str,
    nonce: &[u8],
    timestamp: i64,
    presented_tag: &str,
) -> bool {
    let Some(client) = known_clients.iter().find(|it| it.client_id == client_id) else {
        return false;
    };

    let Ok(presented_tag) = STANDARD_NO_PAD.decode(presented_tag) else {
        return false;
    };
    if presented_tag.len() != AUTH_TAG_LEN {
        return false;
    }

    let Ok(expected_tag) = compute_auth_tag_bytes(
        client.client_secret.as_bytes(),
        nonce,
        timestamp,
        &client.client_id,
    ) else {
        return false;
    };

    constant_time_eq(&expected_tag, &presented_tag)
}

fn constant_time_eq(expected: &[u8], presented: &[u8]) -> bool {
    if expected.len() != presented.len() {
        return false;
    }

    let mut diff = 0u8;
    for (left, right) in expected.iter().zip(presented) {
        diff |= left ^ right;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use shroud_core::auth::compute_auth_tag;

    const CLIENT_ID: &str = "11111111-1111-1111-1111-111111111111";
    const CLIENT_SECRET: &str = "test-secret";

    fn clients() -> Vec<AuthorizedClient> {
        vec![AuthorizedClient {
            client_id: CLIENT_ID.to_string(),
            client_secret: CLIENT_SECRET.to_string(),
        }]
    }

    #[test]
    fn validates_correct_hmac() {
        let nonce = [7u8; 16];
        let timestamp = 1_800_000_000;
        let tag = compute_auth_tag(CLIENT_SECRET.as_bytes(), &nonce, timestamp, CLIENT_ID)
            .expect("compute tag");

        assert!(validate_auth(
            &clients(),
            CLIENT_ID,
            &nonce,
            timestamp,
            &tag
        ));
    }

    #[test]
    fn rejects_malformed_hmac() {
        assert!(!validate_auth(
            &clients(),
            CLIENT_ID,
            &[7u8; 16],
            1_800_000_000,
            "not-base64!",
        ));
    }

    #[test]
    fn rejects_wrong_hmac() {
        let nonce = [7u8; 16];
        let timestamp = 1_800_000_000;
        let tag =
            compute_auth_tag(b"wrong-secret", &nonce, timestamp, CLIENT_ID).expect("compute tag");

        assert!(!validate_auth(
            &clients(),
            CLIENT_ID,
            &nonce,
            timestamp,
            &tag
        ));
    }
}
