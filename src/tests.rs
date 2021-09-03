#[tokio::test]
async fn it_fetches_google_keys() -> reqwest::Result<()> {
    let client = reqwest::Client::new();
    crate::GOOGLE.fetch(&client).await?;

    Ok(())
}


#[tokio::test]
async fn it_fetches_apple_keys() -> reqwest::Result<()> {
    let client = reqwest::Client::new();

    match crate::APPLE.fetch(&client).await {
        Ok(_) => Ok(()),
        // Apple's JWKS endpoint has a habit of sporadically timing out
        Err(e) if e.is_timeout() => Ok(()),
        Err(e) => Err(e)
    }
}