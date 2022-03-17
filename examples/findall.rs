#![allow(dead_code)]
#![allow(non_camel_case_types)]
#![allow(warnings, unused)]

fn main() {


    let devices = libpcap::findalldevs();

    println!("Find devices {:?},\nUse default: {}",devices,devices[0]);

    let mut Packet = libpcap::open(devices[0].as_str());
   
	
    while let data = libpcap::next_ex(&mut Packet){
        println!("{:?},{:?}",Packet.data,Packet.head.len);
        println!("{:?}",Packet);
    }

    libpcap::close(&mut Packet);
}
