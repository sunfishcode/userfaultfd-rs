use crate::error::{Error, Result};
use crate::{IoctlFlags, Uffd};
use bitflags::bitflags;
use rustix::io::{ioctl_uffdio_api, UffdFeatureFlags, UffdioApi, UserfaultfdFlags};

cfg_if::cfg_if! {
    if #[cfg(any(feature = "linux5_7", feature = "linux4_14"))] {
        bitflags! {
            /// Used with `UffdBuilder` to determine which features are available in the current kernel.
            pub struct FeatureFlags: u64 {
                const PAGEFAULT_FLAG_WP = UffdFeatureFlags::PAGEFAULT_FLAG_WP.bits();
                const EVENT_FORK = UffdFeatureFlags::EVENT_FORK.bits();
                const EVENT_REMAP = UffdFeatureFlags::EVENT_REMAP.bits();
                const EVENT_REMOVE = UffdFeatureFlags::EVENT_REMOVE.bits();
                const MISSING_HUGETLBFS = UffdFeatureFlags::MISSING_HUGETLBFS.bits();
                const MISSING_SHMEM = UffdFeatureFlags::MISSING_SHMEM.bits();
                const EVENT_UNMAP = UffdFeatureFlags::EVENT_UNMAP.bits();
                const SIGBUS = UffdFeatureFlags::SIGBUS.bits();
                const THREAD_ID = UffdFeatureFlags::THREAD_ID.bits();
            }
        }
    } else {
        bitflags! {
            /// Used with `UffdBuilder` to determine which features are available in the current kernel.
            pub struct FeatureFlags: u64 {
                const PAGEFAULT_FLAG_WP = UffdFeatureFlags::PAGEFAULT_FLAG_WP.bits();
                const EVENT_FORK = UffdFeatureFlags::EVENT_FORK.bits();
                const EVENT_REMAP = UffdFeatureFlags::EVENT_REMAP.bits();
                const EVENT_REMOVE = UffdFeatureFlags::EVENT_REMOVE.bits();
                const MISSING_HUGETLBFS = UffdFeatureFlags::MISSING_HUGETLBFS.bits();
                const MISSING_SHMEM = UffdFeatureFlags::MISSING_SHMEM.bits();
                const EVENT_UNMAP = UffdFeatureFlags::EVENT_UNMAP.bits();
            }
        }
    }
}
/// A builder for initializing `Uffd` objects.
///
/// ```
/// use userfaultfd::UffdBuilder;
///
/// let uffd = UffdBuilder::new()
///     .close_on_exec(true)
///     .non_blocking(true)
///     .user_mode_only(true)
///     .create();
/// assert!(uffd.is_ok());
/// ```
pub struct UffdBuilder {
    close_on_exec: bool,
    non_blocking: bool,
    user_mode_only: bool,
    req_features: FeatureFlags,
    req_ioctls: IoctlFlags,
}

impl UffdBuilder {
    /// Create a new builder with no required features or ioctls, `close_on_exec` and
    /// `non_blocking` both set to `false`, and `user_mode_only` set to `true`.
    pub fn new() -> UffdBuilder {
        UffdBuilder {
            close_on_exec: false,
            non_blocking: false,
            user_mode_only: true,
            req_features: FeatureFlags::empty(),
            req_ioctls: IoctlFlags::empty(),
        }
    }

    /// Enable the close-on-exec flag for the new userfaultfd object (see the description of
    /// `O_CLOEXEC` in [`open(2)`](http://man7.org/linux/man-pages/man2/open.2.html)).
    pub fn close_on_exec(&mut self, close_on_exec: bool) -> &mut Self {
        self.close_on_exec = close_on_exec;
        self
    }

    /// Enable non-blocking operation for the userfaultfd object.
    ///
    /// If this is set to `false`, `Uffd::read_event()` will block until an event is available to
    /// read. Otherwise, it will immediately return `None` if no event is available.
    pub fn non_blocking(&mut self, non_blocking: bool) -> &mut Self {
        self.non_blocking = non_blocking;
        self
    }

    /// Enable user-mode only flag for the userfaultfd object.
    ///
    /// If set to `false`, the process must have the `CAP_SYS_PTRACE` capability starting with Linux 5.11
    /// or object creation will fail with EPERM. When set to `true`, userfaultfd can't be used
    /// to handle kernel-mode page faults such as when kernel tries copying data to userspace.
    ///
    /// When used with kernels older than 5.11, this has no effect; the process doesn't need
    /// `CAP_SYS_PTRACE` and can handle kernel-mode page faults.
    pub fn user_mode_only(&mut self, user_mode_only: bool) -> &mut Self {
        self.user_mode_only = user_mode_only;
        self
    }

    /// Add a requirement that a particular feature or set of features is available.
    ///
    /// If a required feature is unavailable, `UffdBuilder.create()` will return an error.
    pub fn require_features(&mut self, feature: FeatureFlags) -> &mut Self {
        self.req_features |= feature;
        self
    }

    /// Add a requirement that a particular ioctl or set of ioctls is available.
    ///
    /// If a required ioctl is unavailable, `UffdBuilder.create()` will return an error.
    pub fn require_ioctls(&mut self, ioctls: IoctlFlags) -> &mut Self {
        self.req_ioctls |= ioctls;
        self
    }

    /// Create a `Uffd` object with the current settings of this builder.
    pub fn create(&self) -> Result<Uffd> {
        // first do the syscall to get the file descriptor
        let mut flags = UserfaultfdFlags::empty();
        if self.close_on_exec {
            flags |= UserfaultfdFlags::CLOEXEC;
        }
        if self.non_blocking {
            flags |= UserfaultfdFlags::NONBLOCK;
        }

        if self.user_mode_only {
            flags |= UserfaultfdFlags::USER_MODE_ONLY;
        }

        let fd = match unsafe { rustix::io::userfaultfd(flags) } {
            Ok(fd) => fd,
            // setting the USER_MODE_ONLY flag on kernel pre-5.11 causes it to return EINVAL.
            // If the user asks for the flag, we first try with it set, and if kernel gives
            // EINVAL we try again without the flag set.
            Err(rustix::io::Error::INVAL) if self.user_mode_only => unsafe {
                rustix::io::userfaultfd(flags & !UserfaultfdFlags::USER_MODE_ONLY)?
            },
            Err(e) => return Err(e.into()),
        };

        // Wrap the fd up so that a failure in this function body closes it with the drop.
        let uffd = Uffd { fd };

        // then do the UFFDIO_API ioctl to set up and ensure features and other ioctls are available
        let mut api = UffdioApi {
            api: rustix::io::UFFD_API,
            features: self.req_features.bits(),
            ioctls: 0,
        };
        ioctl_uffdio_api(&uffd.fd, &mut api)?;
        let supported =
            IoctlFlags::from_bits(api.ioctls).ok_or(Error::UnrecognizedIoctls(api.ioctls))?;
        if !supported.contains(self.req_ioctls) {
            Err(Error::UnsupportedIoctls(supported))
        } else {
            Ok(uffd)
        }
    }
}
