pub mod keygen;
pub mod store;
pub mod subcmd;

use anyhow::Result;
use p43::key_store::store::KeyStore;
use subcmd::KeyCmd;

pub fn run(cmd: KeyCmd, ks: &KeyStore) -> Result<()> {
    match cmd {
        KeyCmd::Generate {
            uid,
            algo,
            no_encrypt,
        } => keygen::run(ks, &uid, &algo, no_encrypt),
        KeyCmd::List => store::run_list(ks),
        KeyCmd::ExportPub { key } => store::run_export_pub(ks, &key),
        KeyCmd::ExportPriv { key } => store::run_export_priv(ks, &key),
        KeyCmd::Import { file } => store::run_import(ks, &file),
        KeyCmd::Delete { key } => store::run_delete(ks, &key),
        KeyCmd::RegisterCard { key, ident } => store::run_register_card(ks, &key, &ident),
        KeyCmd::ImportCard { uid, card } => {
            store::run_import_card(ks, card.as_deref(), uid.as_deref())
        }
        KeyCmd::ListCards => store::run_list_cards(),
    }
}
