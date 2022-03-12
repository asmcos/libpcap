#![allow(non_camel_case_types)]
#![allow(warnings, unused)]


use std::ffi::{self, CStr, CString};
use libc::{c_char,c_uchar};
use std::ptr;
use std::time;

mod clib;

use clib::{pcap_t,pcap_pkthdr};

pub struct Packet {
    pub handle: *mut pcap_t,
    pub header: *mut pcap_pkthdr,
    pub data: *const u8,
    pub head: pcap_pkthdr,
}

impl Packet {
    fn new(handle: *mut pcap_t) -> Packet {
        let mut head = make_pkthdr();
        Packet { 
            handle: handle,
            header: &mut head,
            data: ptr::null() ,
            head: head,
         }
    }
}


#[inline]
unsafe fn cstr_to_string(ptr: *const libc::c_char) -> String {

    CStr::from_ptr(ptr as _).to_str().unwrap().to_owned()
}

pub fn make_pkthdr( ) -> clib::pcap_pkthdr {

    let duration = time::Duration::new(10,0);

    clib::pcap_pkthdr{
        ts:
            libc::timeval {
            tv_sec: duration.as_secs() as i64,
            tv_usec: duration.subsec_micros() as libc::suseconds_t,
            },
        caplen : 0,
        len :0,
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


pub fn open(interface_name: &str)->Result<Packet,bool>{

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
    ) -> Result<Packet, bool> {

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
        Ok(Packet::new(handle))
    }

}

pub fn next(p:&mut Packet)-> *const libc::c_uchar{

    let mut header = &mut p.head;

	let data = unsafe {

        let d = clib::pcap_next((*p).handle,&mut *header);

        println!("{:?},{:?}",header.len,header.caplen);

		d
	};
    data
}

pub fn next_ex(p:&mut Packet)->i32{
        
    let mut header: *mut clib::pcap_pkthdr = ptr::null_mut();
    let mut data: *const libc::c_uchar = ptr::null();
    
    let data = unsafe {

        
        let d = clib::pcap_next_ex((*p).handle ,&mut header,&mut (*p).data);
        (*p).header = header;
        println!("{:?},{:?},{:?}",d,(*header).len,(*header).caplen);
        d
    };
    data
}
