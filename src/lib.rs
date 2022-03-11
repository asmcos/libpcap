use std::ffi::{self, CStr, CString};
use libc::{c_char};
use std::ptr;

mod clib;

#[inline]
unsafe fn cstr_to_string(ptr: *const libc::c_char) -> String {

    CStr::from_ptr(ptr as _).to_str().unwrap().to_owned()
}


pub fn lookup() {

	let mut errbuf = [0i8; 256];
	unsafe {
		let devices = clib::pcap_lookupdev(errbuf.as_mut_ptr());
		println!("{:?}",cstr_to_string(devices));
	}
}
