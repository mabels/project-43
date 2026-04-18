pub mod client;
pub mod device;
pub mod room;
pub mod verification;

pub use client::{login, logout, restore, MatrixConfig, SavedConfig};
pub use device::{delete_devices, list_devices, DeviceInfo};
pub use room::{
    join_room, list_joined_rooms, listen, resolve_room_id, send_message, set_room_alias,
    JoinResult, RoomInfo,
};
pub use verification::verify_own_device;
