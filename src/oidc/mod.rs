type OidcClient = openidconnect::core::CoreClient<
    openidconnect::EndpointSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointMaybeSet,
    openidconnect::EndpointMaybeSet,
>;

static CLIENTS: std::sync::LazyLock<std::sync::RwLock<std::collections::HashMap<u64, OidcClient>>> =
    std::sync::LazyLock::new(|| std::sync::RwLock::new(std::collections::HashMap::new()));

pub fn discover(
    issuer: openidconnect::url::Url,
    client_id: &str,
    client_secret: &str,
    redirect: openidconnect::url::Url,
) -> Option<()> {
    let mut hasher = std::hash::DefaultHasher::new();
    std::hash::Hash::hash(issuer.as_str(), &mut hasher);
    std::hash::Hash::hash(client_id, &mut hasher);
    std::hash::Hash::hash(client_secret, &mut hasher);
    std::hash::Hash::hash(redirect.as_str(), &mut hasher);
    let key = std::hash::Hasher::finish(&hasher);

    let mut clients = CLIENTS.write().ok()?;
    if clients.contains_key(&key) {
        return Some(());
    }

    let client = openidconnect::reqwest::blocking::ClientBuilder::new()
        .redirect(openidconnect::reqwest::redirect::Policy::none())
        .build()
        .ok()?;

    let metadata = openidconnect::core::CoreProviderMetadata::discover(
        &openidconnect::IssuerUrl::from_url(issuer),
        &client,
    )
    .ok()?;

    let client = openidconnect::core::CoreClient::from_provider_metadata(
        metadata,
        openidconnect::ClientId::new(String::from(client_id)),
        Some(openidconnect::ClientSecret::new(String::from(
            client_secret,
        ))),
    )
    .set_redirect_uri(openidconnect::RedirectUrl::from_url(redirect));

    clients.insert(key, client);

    Some(())
}
