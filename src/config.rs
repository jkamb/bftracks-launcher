use serde_derive::{Deserialize, Serialize};
#[derive(Serialize, Deserialize)]
pub struct Config {
    #[serde(rename = "GamePath")]
    pub game_path: String,
}
