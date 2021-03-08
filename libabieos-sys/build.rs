//extern crate cmake;
//use cmake;
// to regen -
use sys_info;
// bindgen lib/abieos/src/abieos.h -o src/bindings.rs
fn main() {
    let dst = cmake::Config::new("lib/abieos")
        //  .build_target("abieos_static")
        .build_target("abieos")
        .build();
    // let dst = cmake::build("lib/abieos");
    println!("*********{}*********", sys_info::os_type().unwrap());

    println!("cargo:rustc-link-search={}/build", dst.display());
    println!("cargo:rustc-link-lib=abieos");
    if sys_info::os_type().unwrap() == "Linux" {
        println!("cargo:rustc-link-lib=stdc++");
    } else {
        println!("cargo:rustc-link-lib=c++");
    }
}
