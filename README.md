Rust-wrapped version of C libpcap.

### Windows
install WinPcap.

### Linux
install libpcap-dev

### Mac OS X
libpcap should be installed on Mac OS X by default.


### C source code
<https://github.com/the-tcpdump-group/libpcap>

### Demo

```rust
	let dev = libpcap::lookup();
	println!("Found net device: {}",dev);

	let mut Packet = libpcap::open(dev.as_str())?;
   
     
    while let data = libpcap::next(&mut Packet){
        println!("{:?}",Packet);
    }

```
result

```
Packet { ts: 1647398752.372106, caplen: 74, len: 74 }Data  0x5619ab247d10,Length 74
0xfc, 0x33, 0x42, 0x5e, 0x4a, 0x01, 0x68,..................
```

