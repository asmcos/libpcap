
fn main() -> Result<(),bool> {

	let dev = libpcap::lookup();
	println!("Found net device: {}",dev);

	let mut Packet = libpcap::open(dev.as_str())?;
   
unsafe { 
    /* 
    while let data = libpcap::next(&mut Packet){
        println!("{:?}",data);
    }*/
    
    while let data = libpcap::next_ex(&mut Packet){
        println!("{:?},{:?}",Packet.data,Packet.head.len);
    }
}
    Ok(())
}
