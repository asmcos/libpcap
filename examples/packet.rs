#![allow(dead_code)]
#![allow(non_camel_case_types)]
#![allow(warnings, unused)]

fn main() {

    let dev = libpcap::lookup();
    println!("Found net device: {}",dev);

    let mut Packet = libpcap::open(dev.as_str());
   
     
    while let data = libpcap::next(&mut Packet){
        println!("{:?}",Packet);
    }
    
	/*
    while let data = libpcap::next_ex(&mut Packet){
        println!("{:?},{:?}",Packet.data,Packet.head.len);
    }*/

    libpcap::close(&mut Packet);
}
