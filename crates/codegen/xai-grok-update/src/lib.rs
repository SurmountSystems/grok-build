pub mod auto_update;
mod minimum_version;
pub mod oss_update;
pub mod version;

pub use auto_update::UpdateStatus;
pub use minimum_version::enforce_minimum_version_or_exit;
pub use oss_update::{
    OSS_GITHUB_REPO, OssUpdateStatus, check_against_main, format_build_id, how_to_update_message,
    print_oss_update_status,
};
pub use version::{UpdateConfig, channel_label, channel_name, write_version_cache};
