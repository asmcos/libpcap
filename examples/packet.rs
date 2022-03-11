fn main() {

	let dev = libpcap::lookup();
	println!("Found net device: {}",dev);

	let h = libpcap::pcap_open(dev.as_str());

}
