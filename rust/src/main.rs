use bpf_sys::*;
use std::mem;
use std::ptr;

fn main() {
    // Load the eBPF program
    let program = include_bytes!("program.o");

    // Load the eBPF program into the kernel
    let prog_fd = unsafe {
        bpf_load_program(
            BPF_PROG_TYPE_XDP,
            program.as_ptr() as *const _,
            program.len() as u32,
            "GPL\0".as_ptr() as *const _,
            0,
        )
    };

    if prog_fd < 0 {
        panic!("Failed to load eBPF program");
    }

    // Attach the program to the network interface
    let ifindex = bpf_get_link_ifindex_by_name(b"eth0\0".as_ptr() as *const _);
    let attach_mode = BPF_XDP_ATTACH_MODE_SKB_MODE as u32;
    let ret = unsafe { bpf_set_link_xdp_fd(ifindex, prog_fd, attach_mode) };

    if ret != 0 {
        panic!("Failed to attach eBPF program to interface");
    }

    println!("eBPF program attached successfully");

    // Wait indefinitely
    unsafe {
        let mut exit_code: i32 = 0;
        let exit_code_ptr = &mut exit_code as *mut _;
        ptr::write_volatile(exit_code_ptr, 0);
        mem::forget(exit_code_ptr);
    }

    // Detach the program when the process exits
    unsafe {
        bpf_set_link_xdp_fd(ifindex, -1, attach_mode);
    }
}
