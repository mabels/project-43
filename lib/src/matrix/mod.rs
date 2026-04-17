pub mod client;
pub mod room;

pub use client::{login, restore_or_login, MatrixConfig};
pub use room::{list_joined_rooms, listen, resolve_room_id, send_message, RoomInfo};
