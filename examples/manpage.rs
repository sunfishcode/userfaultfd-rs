//! Port of the example from the `userfaultfd` manpage.
use rustix::fd::{AsRawFd, BorrowedFd};
use rustix::io::{MapFlags, PollFd, PollFlags, ProtFlags};
use std::env;
use std::ffi::c_void;
use std::ptr;
use userfaultfd::{Event, Uffd, UffdBuilder};

fn fault_handler_thread(uffd: Uffd) {
    let page_size = rustix::process::page_size();

    // Create a page that will be copied into the faulting region

    let page = unsafe {
        rustix::io::mmap_anonymous(
            ptr::null_mut(),
            page_size,
            ProtFlags::READ | ProtFlags::WRITE,
            MapFlags::PRIVATE,
        )
        .expect("mmap")
    };

    // Loop, handling incoming events on the userfaultfd file descriptor

    let mut fault_cnt = 0;
    loop {
        // See what poll() tells us about the userfaultfd

        let fd = unsafe { BorrowedFd::borrow_raw_fd(uffd.as_raw_fd()) };
        let mut pollfd = [PollFd::new(&fd, PollFlags::IN)];
        let nready = rustix::io::poll(&mut pollfd, -1).expect("poll");

        println!("\nfault_handler_thread():");
        let revents = pollfd[0].revents();
        println!(
            "    poll() returns: nready = {}; POLLIN = {}; POLLERR = {}",
            nready,
            revents.contains(PollFlags::IN),
            revents.contains(PollFlags::ERR),
        );

        // Read an event from the userfaultfd
        let event = uffd
            .read_event()
            .expect("read uffd_msg")
            .expect("uffd_msg ready");

        // We expect only one kind of event; verify that assumption

        if let Event::Pagefault { addr, .. } = event {
            // Display info about the page-fault event

            println!("    UFFD_EVENT_PAGEFAULT event: {:?}", event);

            // Copy the page pointed to by 'page' into the faulting region. Vary the contents that are
            // copied in, so that it is more obvious that each fault is handled separately.

            for c in unsafe { std::slice::from_raw_parts_mut(page as *mut u8, page_size) } {
                *c = b'A' + fault_cnt % 20;
            }
            fault_cnt += 1;

            let dst = (addr as usize & !(page_size as usize - 1)) as *mut c_void;
            let copy = unsafe { uffd.copy(page, dst, page_size, true).expect("uffd copy") };

            println!("        (uffdio_copy.copy returned {})", copy);
        } else {
            panic!("Unexpected event on userfaultfd");
        }
    }
}

fn main() {
    let num_pages = env::args()
        .nth(1)
        .expect("Usage: manpage <num_pages>")
        .parse::<usize>()
        .unwrap();

    let page_size = rustix::process::page_size();
    let len = num_pages * page_size;

    // Create and enable userfaultfd object

    let uffd = UffdBuilder::new()
        .close_on_exec(true)
        .non_blocking(true)
        .user_mode_only(true)
        .create()
        .expect("uffd creation");

    // Create a private anonymous mapping. The memory will be demand-zero paged--that is, not yet
    // allocated. When we actually touch the memory, it will be allocated via the userfaultfd.

    let addr = unsafe {
        rustix::io::mmap_anonymous(
            ptr::null_mut(),
            len,
            ProtFlags::READ | ProtFlags::WRITE,
            MapFlags::PRIVATE,
        )
        .expect("mmap")
    };

    println!("Address returned by mmap() = {:p}", addr);

    // Register the memory range of the mapping we just created for handling by the userfaultfd
    // object. In mode, we request to track missing pages (i.e., pages that have not yet been
    // faulted in).

    uffd.register(addr, len).expect("uffd.register()");

    // Create a thread that will process the userfaultfd events
    let _s = std::thread::spawn(move || fault_handler_thread(uffd));

    // Main thread now touches memory in the mapping, touching locations 1024 bytes apart. This will
    // trigger userfaultfd events for all pages in the region.

    // Ensure that faulting address is not on a page boundary, in order to test that we correctly
    // handle that case in fault_handling_thread()
    let mut l = 0xf;

    while l < len {
        let ptr = (addr as usize + l) as *mut u8;
        let c = unsafe { *ptr };
        println!("Read address {:p} in main(): {:?}", ptr, c as char);
        l += 1024;
        std::thread::sleep(std::time::Duration::from_micros(100000));
    }
}
