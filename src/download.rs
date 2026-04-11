use sha2::{Sha256, Digest};
use anyhow::{Result, Context};

pub fn download_to_memory(url: &str, expected_size: Option<u64>, expected_sha256: Option<&str>) -> Result<Vec<u8>>
{

    // 创建阻塞客户端
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let response = client.get(url).send()
        .with_context(|| format!("Failed to send request to {}", url))?;

    if !response.status().is_success() {
        return Err(anyhow::anyhow!("Failed to download file: HTTP {}", response.status()));
    }

    let content_length = response.content_length();
    if let Some(expected) = expected_size && content_length != Some(expected) {
            anyhow::bail!("File size mismatch: expected {} bytes, got {} bytes", expected, content_length.unwrap_or(0));
    }

    let bytes = response.bytes()
        .with_context(|| format!("Failed to read response body from {}", url))?
        .to_vec();

    if let Some(expected) = expected_size && bytes.len() as u64 != expected {
            anyhow::bail!("File size mismatch after reading: expected {} bytes, got {} bytes", expected, bytes.len());
    }

    if let Some(expected_hex) = expected_sha256 {
        let mut hasher = Sha256::new();
        hasher.update(&bytes);

        let hash_bytes = hasher.finalize();

        let hash_hex = hash_bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>();

        if hash_hex != expected_hex {
            anyhow::bail!(
                "SHA256 mismatch: expected {}, got {}",
                expected_hex, hash_hex
            );
        }
    }

    Ok(bytes)


}