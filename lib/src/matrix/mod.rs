pub mod client;
pub mod device;
pub mod global;
pub mod pointer;
pub mod room;
pub mod verification;

pub use client::{login, logout, restore, MatrixConfig, SavedConfig};
pub use device::{delete_devices, list_devices, DeviceInfo};
pub use global::resolve_agent_room;
pub use pointer::{device_id_from_config, RoomPointerStore};
pub use room::{
    join_room, list_joined_rooms, listen, purge_room_history, redact_event, resolve_room_id,
    send_message, set_room_alias, JoinResult, ListenPointer, RoomInfo,
};
pub use verification::{verify_own_device, EmojiItem};
