//extern crate cmake;
//use cmake;
// to regen -
// bindgen lib/abieos/src/abieos.h -o src/bindings.rs
fn main() {
    let dst = cmake::Config::new("lib/abieos")
      //  .build_target("abieos_static")
       .build_target("abieos")
        .build();
    // let dst = cmake::build("lib/abieos");
    println!("cargo:rustc-link-lib=c++");
    println!("cargo:rustc-link-search={}/build", dst.display());
    println!("cargo:rustc-link-lib=abieos");
    //println!("cargo:rustc-link-lib=stdc++");


}
