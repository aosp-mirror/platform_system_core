//! Example showing how to access the `trusty.security_vm.vm_cid` system property with Rust.

use trusty_properties::security_vm;

fn main() {
    match security_vm::vm_cid() {
        Ok(Some(cid)) => println!("CID: {cid}"),
        Ok(None) => println!("CID property not set"),
        Err(e) => println!("Error: {e:?}"),
    }
}
