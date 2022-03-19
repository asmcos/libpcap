#![allow(dead_code)]
#![allow(non_camel_case_types)]
#![allow(warnings, unused)]

use std::net::IpAddr;

fn main() {


    let devices = libpcap::findalldevs();

    println!("Find devices {:?},\nUse default: {}",devices,devices[0]);

    let mut netp:u32=0;
    let mut maskp:u32=0;
    let ret = libpcap::lookupnet(devices[0].as_str(),&mut netp,&mut maskp);
    if (ret != -1){
        println!("IP:{:?}\nmask:{:?}",IpAddr::V4(u32::from_be(netp).into()),IpAddr::V4(u32::from_be(maskp).into()));
    } 

    let mut Packet = libpcap::open(devices[0].as_str());
   
	
    while let data = libpcap::next_ex(&mut Packet){
        println!("{:?},{:?}",Packet.data,Packet.head.len);
        println!("{:?}",Packet);
    }

    libpcap::close(&mut Packet);
}
