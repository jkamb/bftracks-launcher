
use serde_derive::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct Config
{
    #[serde(rename = "GamePath")]
    pub game_path: String
}