use std::path::Path;
use serde::{Deserialize, Serialize};
use tokio::fs;
use tracing::info;

pub const MAX_OUTPUT_CHARS: usize = 30_000;
pub const PREVIEW_HEAD_CHARS: usize = 15_000;
pub const PREVIEW_TAIL_CHARS: usize = 10_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchdogResult {
    pub output: String,
    pub is_truncated: bool,
    pub total_chars: usize,
    pub log_file_path: Option<String>,
}

/// Protects LLM context window by truncating output exceeding MAX_OUTPUT_CHARS (30KB)
/// and saving the full raw log to /workspace/logs/cmd_<id>.log
pub async fn process_command_output(
    cmd_id: &str,
    raw_output: &str,
    log_dir: &Path,
) -> Result<WatchdogResult, std::io::Error> {
    let total_chars = raw_output.chars().count();

    if total_chars <= MAX_OUTPUT_CHARS {
        return Ok(WatchdogResult {
            output: raw_output.to_string(),
            is_truncated: false,
            total_chars,
            log_file_path: None,
        });
    }

    // Ensure log directory exists
    fs::create_dir_all(log_dir).await?;
    let sanitized_id = cmd_id.replace(|c: char| !c.is_alphanumeric() && c != '_' && c != '-', "_");
    let log_file_name = format!("cmd_{}.log", sanitized_id);
    let log_path = log_dir.join(&log_file_name);

    // Save full raw output
    fs::write(&log_path, raw_output).await?;
    info!("Output exceeded 30KB ({} chars). Full dump saved to {:?}", total_chars, log_path);

    // Extract head and tail
    let chars: Vec<char> = raw_output.chars().collect();
    let head: String = chars.iter().take(PREVIEW_HEAD_CHARS).collect();
    let tail_start = if total_chars > PREVIEW_TAIL_CHARS {
        total_chars - PREVIEW_TAIL_CHARS
    } else {
        0
    };
    let tail: String = chars.iter().skip(tail_start).collect();

    let formatted_output = format!(
        "{}\n\n\
================================================================================\n\
[!] WATCHDOG NOTICE: Output truncated (Total {} characters).\n\
[!] Full unmodified output saved to: {}\n\
================================================================================\n\n\
{}",
        head,
        total_chars,
        log_path.to_string_lossy(),
        tail
    );

    Ok(WatchdogResult {
        output: formatted_output,
        is_truncated: true,
        total_chars,
        log_file_path: Some(log_path.to_string_lossy().into_owned()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_small_output_not_truncated() {
        let temp_dir = TempDir::new().unwrap();
        let small_text = "Small output text 123";
        let res = process_command_output("test_1", small_text, temp_dir.path()).await.unwrap();

        assert!(!res.is_truncated);
        assert_eq!(res.total_chars, small_text.len());
        assert_eq!(res.output, small_text);
        assert!(res.log_file_path.is_none());
    }

    #[tokio::test]
    async fn test_large_output_truncated_and_saved() {
        let temp_dir = TempDir::new().unwrap();
        let large_text = "A".repeat(40_000);
        let res = process_command_output("test_large", &large_text, temp_dir.path()).await.unwrap();

        assert!(res.is_truncated);
        assert_eq!(res.total_chars, 40_000);
        assert!(res.output.contains("[!] WATCHDOG NOTICE: Output truncated"));
        assert!(res.log_file_path.is_some());

        let log_file = PathBuf::from(res.log_file_path.unwrap());
        assert!(log_file.exists());
        let saved_content = tokio::fs::read_to_string(log_file).await.unwrap();
        assert_eq!(saved_content.len(), 40_000);
    }
}
