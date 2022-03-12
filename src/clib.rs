
//
// C interface libpcap
//

#![allow(non_camel_case_types)]
#![allow(warnings, unused)]

use libc::{c_char, c_int, c_uchar, c_uint, c_ushort, sockaddr, timeval, FILE};

pub const PCAP_ERRBUF_SIZE:i32=256;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct bpf_program {
    pub bf_len: c_uint,
    pub bf_insns: *mut bpf_insn,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct bpf_insn {
    pub code: c_ushort,
    pub jt: c_uchar,
    pub jf: c_uchar,
    pub k: c_uint,
}

pub struct pcap {
    _unused: [u8; 0],
}
pub type pcap_t  = pcap;

pub enum pcap_dumper_t {}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct pcap_file_header {
    pub magic: c_uint,
    pub version_major: c_ushort,
    pub version_minor: c_ushort,
    pub thiszone: c_int,
    pub sigfigs: c_uint,
    pub snaplen: c_uint,
    pub linktype: c_uint,
}

pub type pcap_direction_t = c_uint;

pub const PCAP_D_INOUT: pcap_direction_t = 0;
pub const PCAP_D_IN: pcap_direction_t = 1;
pub const PCAP_D_OUT: pcap_direction_t = 2;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct pcap_pkthdr {
    pub ts: timeval,
    pub caplen: c_uint,
    pub len: c_uint,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct pcap_stat {
    pub ps_recv: c_uint,
    pub ps_drop: c_uint,
    pub ps_ifdrop: c_uint,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct pcap_if_t {
    pub next: *mut pcap_if_t,
    pub name: *mut c_char,
    pub description: *mut c_char,
    pub addresses: *mut pcap_addr_t,
    pub flags: c_uint,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct pcap_addr_t {
    pub next: *mut pcap_addr_t,
    pub addr: *mut sockaddr,
    pub netmask: *mut sockaddr,
    pub broadaddr: *mut sockaddr,
    pub dstaddr: *mut sockaddr,
}

pub type pcap_handler = ::std::option::Option<
    unsafe extern "C" fn(arg1: *mut c_uchar, arg2: *const pcap_pkthdr, arg3: *const c_uchar),
>;


extern "C" {
    pub fn pcap_lookupdev(arg1: *mut c_char) -> *mut c_char;
    pub fn pcap_lookupnet(arg1: *const c_char, arg2: *mut c_uint, arg3: *mut c_uint,
                           arg4: *mut c_char) -> c_int;
    pub fn pcap_create(arg1: *const c_char, arg2: *mut c_char) -> *mut pcap_t;
    pub fn pcap_set_snaplen(arg1: *mut pcap_t, arg2: c_int) -> c_int;
    pub fn pcap_set_promisc(arg1: *mut pcap_t, arg2: c_int) -> c_int;
    // pub fn pcap_can_set_rfmon(arg1: *mut pcap_t) -> c_int;
    pub fn pcap_set_timeout(arg1: *mut pcap_t, arg2: c_int) -> c_int;
    pub fn pcap_set_buffer_size(arg1: *mut pcap_t, arg2: c_int) -> c_int;
    pub fn pcap_activate(arg1: *mut pcap_t) -> c_int;
    pub fn pcap_open_live(arg1: *const c_char, arg2: c_int, arg3: c_int, arg4: c_int,
                           arg5: *mut c_char) -> *mut pcap_t;
    pub fn pcap_open_dead(arg1: c_int, arg2: c_int) -> *mut pcap_t;
    pub fn pcap_open_offline(arg1: *const c_char, arg2: *mut c_char) -> *mut pcap_t;
    pub fn pcap_fopen_offline(arg1: *mut FILE, arg2: *mut c_char) -> *mut pcap_t;
    pub fn pcap_close(arg1: *mut pcap_t);
    pub fn pcap_loop(arg1: *mut pcap_t, arg2: c_int,
                      arg3: pcap_handler, arg4: *mut c_uchar) -> c_int;
    // pub fn pcap_dispatch(arg1: *mut pcap_t, arg2: c_int, arg3: pcap_handler,
    //                      arg4: *mut c_uchar)-> c_int;
    pub fn pcap_next(arg1: *mut pcap_t, arg2: *mut pcap_pkthdr) -> *const c_uchar;

    pub fn pcap_next_ex(
        arg1: *mut pcap_t,
        arg2: *mut *mut pcap_pkthdr,
        arg3: *mut *const c_uchar,
    ) -> c_int;
    // pub fn pcap_breakloop(arg1: *mut pcap_t);
    pub fn pcap_stats(arg1: *mut pcap_t, arg2: *mut pcap_stat) -> c_int;
    pub fn pcap_setfilter(arg1: *mut pcap_t, arg2: *mut bpf_program) -> c_int;
    pub fn pcap_setdirection(arg1: *mut pcap_t, arg2: pcap_direction_t) -> c_int;
    // pub fn pcap_getnonblock(arg1: *mut pcap_t, arg2: *mut c_char) -> c_int;
    pub fn pcap_setnonblock(arg1: *mut pcap_t, arg2: c_int, arg3: *mut c_char) -> c_int;
    pub fn pcap_sendpacket(arg1: *mut pcap_t, arg2: *const c_uchar, arg3: c_int) -> c_int;
    // pub fn pcap_statustostr(arg1: c_int) -> *const c_char;
    // pub fn pcap_strerror(arg1: c_int) -> *const c_char;
    pub fn pcap_geterr(arg1: *mut pcap_t) -> *mut c_char;
    // pub fn pcap_perror(arg1: *mut pcap_t, arg2: *mut c_char);
    pub fn pcap_compile(
        arg1: *mut pcap_t,
        arg2: *mut bpf_program,
        arg3: *const c_char,
        arg4: c_int,
        arg5: c_uint,
    ) -> c_int;
    // pub fn pcap_compile_nopcap(arg1: c_int, arg2: c_int, arg3: *mut bpf_program,
    //                            arg4: *const c_char, arg5: c_int, arg6: c_uint) -> c_int;
    pub fn pcap_freecode(arg1: *mut bpf_program);
    pub fn pcap_offline_filter(
        arg1: *const bpf_program,
        arg2: *const pcap_pkthdr,
        arg3: *const c_uchar,
    ) -> c_int;
    pub fn pcap_datalink(arg1: *mut pcap_t) -> c_int;
    // pub fn pcap_datalink_ext(arg1: *mut pcap_t) -> c_int;
    pub fn pcap_list_datalinks(arg1: *mut pcap_t, arg2: *mut *mut c_int) -> c_int;
    pub fn pcap_set_datalink(arg1: *mut pcap_t, arg2: c_int) -> c_int;
    pub fn pcap_free_datalinks(arg1: *mut c_int);
    pub fn pcap_datalink_name_to_val(arg1: *const c_char) -> c_int;
    pub fn pcap_datalink_val_to_name(arg1: c_int) -> *const c_char;
    pub fn pcap_datalink_val_to_description(arg1: c_int) -> *const c_char;
    // pub fn pcap_snapshot(arg1: *mut pcap_t) -> c_int;
    // pub fn pcap_is_swapped(arg1: *mut pcap_t) -> c_int;
    // pub fn pcap_major_version(arg1: *mut pcap_t) -> c_int;
    // pub fn pcap_minor_version(arg1: *mut pcap_t) -> c_int;
    // pub fn pcap_file(arg1: *mut pcap_t) -> *mut FILE;
    pub fn pcap_fileno(arg1: *mut pcap_t) -> c_int;
    pub fn pcap_dump_open(arg1: *mut pcap_t, arg2: *const c_char) -> *mut pcap_dumper_t;
    pub fn pcap_dump_fopen(arg1: *mut pcap_t, fp: *mut FILE) -> *mut pcap_dumper_t;
    // pub fn pcap_dump_file(arg1: *mut pcap_dumper_t) -> *mut FILE;
    // pub fn pcap_dump_ftell(arg1: *mut pcap_dumper_t) -> c_long;
    pub fn pcap_dump_flush(arg1: *mut pcap_dumper_t) -> c_int;
    pub fn pcap_dump_close(arg1: *mut pcap_dumper_t);
    pub fn pcap_dump(arg1: *mut c_uchar, arg2: *const pcap_pkthdr, arg3: *const c_uchar);
    pub fn pcap_findalldevs(arg1: *mut *mut pcap_if_t, arg2: *mut c_char) -> c_int;
    pub fn pcap_freealldevs(arg1: *mut pcap_if_t);
    // pub fn pcap_lib_version() -> *const c_char;
    // pub fn bpf_image(arg1: *const bpf_insn, arg2: c_int) -> *mut c_char;
    // pub fn bpf_dump(arg1: *const bpf_program, arg2: c_int);
    pub fn pcap_get_selectable_fd(arg1: *mut pcap_t) -> c_int;

}

