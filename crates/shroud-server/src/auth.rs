use shroud_core::auth::compute_auth_tag;
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

    let Ok(expected_tag) = compute_auth_tag(
        client.client_secret.as_bytes(),
        nonce,
        timestamp,
        &client.client_id,
    ) else {
        return false;
    };

    expected_tag == presented_tag
}
