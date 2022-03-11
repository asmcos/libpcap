use std::env;
use std::ffi::CStr;
use std::os::raw::c_char;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-env-changed=LIBPCAP_LIBDIR");
    println!("cargo:rerun-if-env-changed=LIBPCAP_VER");
	println!("cargo:rustc-link-lib=pcap");
}
