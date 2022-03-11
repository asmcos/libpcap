#![allow(non_camel_case_types)]
#![allow(warnings, unused)]


use std::ffi::{self, CStr, CString};
use libc::{c_char};
use std::ptr;
use std::time;

mod clib;

use clib::{pcap_t};

pub struct Handle {
    handle: *mut pcap_t,
}

impl Handle {
    fn new(handle: *mut pcap_t) -> Handle {
        Handle { handle }
    }
}



#[inline]
unsafe fn cstr_to_string(ptr: *const libc::c_char) -> String {

    CStr::from_ptr(ptr as _).to_str().unwrap().to_owned()
}

pub fn make_timeval(duration: time::Duration) -> libc::timeval {
    libc::timeval {
        tv_sec: duration.as_secs() as i64,
        tv_usec: duration.subsec_micros() as i64,
    }
}

impl clib::pcap_pkthdr{
	fn new(){

		let ts = make_timeval(time::Duration::new(10, 0));

	}
}


pub fn lookup( ) -> String{

	let mut errbuf = [0i8; 256];
	let devs = unsafe {
		let devices = clib::pcap_lookupdev(errbuf.as_mut_ptr());
		cstr_to_string(devices)
	};

	devs	
}


pub fn pcap_open(interface_name: &str)->Result<Handle,bool>{

	let snaplen :i32 = 5000;
	let promisc   = true;
	let read_timeout_ms :i32 = 2000;

	open_live(interface_name,snaplen,promisc,read_timeout_ms)

}


pub fn open_live(
    interface_name: &str,
    snaplen: i32,
    promisc: bool,
    read_timeout_ms: i32,
    ) -> Result<Handle, bool> {

	let interface_name = CString::new(interface_name).unwrap();
    let mut err_buf = [0i8; 256];
    let handle = unsafe {
        clib::pcap_open_live(
            interface_name.as_ptr(),
            snaplen,
            promisc as i32,
            read_timeout_ms,
            err_buf.as_mut_ptr(),
        )
    };
    if handle.is_null() {
		Err(false)
    } else {
        Ok(Handle::new(handle))
    }

}

pub fn next(h:Handle){

	let mut header: *mut clib::pcap_pkthdr = ptr::null_mut();
    let mut data: *const libc::c_uchar = ptr::null();

	data = unsafe {
		let d = clib::pcap_next(h.handle ,header);
		d
	}
}
