
fn main() {
    println!("cargo:rerun-if-env-changed=LIBPCAP_LIBDIR");
    println!("cargo:rerun-if-env-changed=LIBPCAP_VER");
	println!("cargo:rustc-link-lib=pcap");
}
