
fn main() -> Result<(),bool> {

	let dev = libpcap::lookup();
	println!("Found net device: {}",dev);

	let mut Packet = libpcap::open(dev.as_str())?;
   
     
    while let data = libpcap::next(&mut Packet){
        println!("{:?}",Packet);
    }
    
	/*
    while let data = libpcap::next_ex(&mut Packet){
        println!("{:?},{:?}",Packet.data,Packet.head.len);
    }*/

    Ok(())
}
