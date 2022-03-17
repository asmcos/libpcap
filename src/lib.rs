#![allow(non_camel_case_types)]
#![allow(warnings, unused)]
#![allow(dead_code)]

use std::ffi::{self, CStr, CString};
use libc::{c_char,c_uchar};
use std::ptr;
use std::time;
use std::fmt;
mod clib;

use clib::{pcap_t,pcap_pkthdr};

pub struct Packet {
    pub handle: *mut pcap_t,
    pub head: pcap_pkthdr,
    pub data: *const u8,
}

impl Packet {
    fn new(handle: *mut pcap_t) -> Packet {
        let mut head = make_pkthdr();
        let mut p = Packet { 
            handle: handle,
            head: head, 
            data: ptr::null() ,
         };
        p
    }
}

impl fmt::Debug for Packet{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let ret = write!(
            f,
            "Packet {{ ts: {}.{:06}, caplen: {}, len: {} }}",
            self.head.ts.tv_sec, self.head.ts.tv_usec, self.head.caplen, self.head.len
        );
        println!("Data  {:?},Length {:?}",self.data,self.head.len);
	unsafe {
		for i in 0..self.head.len{
			let a = self.data.offset(i as isize);
			print!("0x{:02x}, ",*a);		
		}
	}
		println!();
		ret
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


pub fn open(interface_name: &str)->Packet{

	let snaplen :i32 = 5000;
	let promisc   = true;
	let read_timeout_ms :i32 = 2000;

	open_live(interface_name,snaplen,promisc,read_timeout_ms).unwrap()

}

pub fn close(p:&mut Packet){
    unsafe {
        clib::pcap_close((*p).handle);
    }
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


    let data = unsafe {

        let d = clib::pcap_next((*p).handle,&mut p.head);
        p.data = d;
        d
    };
    data
}

pub fn next_ex(p:&mut Packet)->i32{
        
    let mut header: *mut clib::pcap_pkthdr = ptr::null_mut();
    let mut data: *const libc::c_uchar = ptr::null();
    
    let data = unsafe {

        
        let d = clib::pcap_next_ex((*p).handle ,&mut header,&mut (*p).data);
        p.head = *header;
        d
    };
    data
}

