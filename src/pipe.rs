// Copyright © 2026 Pathway

use std::io;

#[cfg(unix)]
use std::os::fd::{AsFd, OwnedFd};

#[cfg(unix)]
use cfg_if::cfg_if;
#[cfg(unix)]
use nix::fcntl::{fcntl, FcntlArg, FdFlag, OFlag};
#[cfg(unix)]
use nix::unistd;

#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub enum ReaderType {
    Blocking,
    NonBlocking,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub enum WriterType {
    Blocking,
    NonBlocking,
}

#[derive(Debug)]
pub struct Pipe {
    #[cfg(unix)]
    pub reader: OwnedFd,
    #[cfg(unix)]
    pub writer: OwnedFd,
    #[cfg(windows)]
    pub reader: std::os::windows::io::OwnedHandle,
    #[cfg(windows)]
    pub writer: std::os::windows::io::OwnedHandle,
}

#[cfg(unix)]
fn set_non_blocking(fd: impl AsFd) -> io::Result<()> {
    let fd = fd.as_fd();
    let flags = fcntl(fd, FcntlArg::F_GETFL)?;
    let flags = OFlag::from_bits_retain(flags);
    fcntl(fd, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK))?;
    Ok(())
}

#[cfg(unix)]
#[cfg_attr(target_os = "linux", allow(dead_code))]
fn set_cloexec(fd: impl AsFd) -> io::Result<()> {
    let fd = fd.as_fd();
    let flags = fcntl(fd, FcntlArg::F_GETFD)?;
    let flags = FdFlag::from_bits_retain(flags);
    fcntl(fd, FcntlArg::F_SETFD(flags | FdFlag::FD_CLOEXEC))?;
    Ok(())
}

#[cfg(unix)]
pub fn pipe(reader_type: ReaderType, writer_type: WriterType) -> io::Result<Pipe> {
    cfg_if! {
        if #[cfg(target_os = "linux")] {
            let (reader, writer) = unistd::pipe2(OFlag::O_CLOEXEC)?;
        } else {
            let (reader, writer) = unistd::pipe()?;
            set_cloexec(&reader)?;
            set_cloexec(&writer)?;
        }
    }

    if let ReaderType::NonBlocking = reader_type {
        set_non_blocking(&reader)?;
    }

    if let WriterType::NonBlocking = writer_type {
        set_non_blocking(&writer)?;
    }

    Ok(Pipe { reader, writer })
}

#[cfg(windows)]
pub fn pipe(reader_type: ReaderType, writer_type: WriterType) -> io::Result<Pipe> {
    use std::os::windows::io::{FromRawHandle, OwnedHandle};
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateNamedPipeA, PIPE_ACCESS_INBOUND, PIPE_TYPE_BYTE, PIPE_WAIT,
    };
    use windows_sys::Win32::System::Pipes::{
        PIPE_UNLIMITED_INSTANCES,
    };

    unsafe {
        // Create a unique pipe name
        let pipe_name = format!("\\\\.\\pipe\\pathway_pipe_{}", std::process::id());
        let pipe_name_c = std::ffi::CString::new(pipe_name.clone()).unwrap();

        let read_handle = CreateNamedPipeA(
            pipe_name_c.as_ptr() as *const u8,
            PIPE_ACCESS_INBOUND,
            PIPE_TYPE_BYTE | if matches!(reader_type, ReaderType::NonBlocking) { 0 } else { PIPE_WAIT },
            PIPE_UNLIMITED_INSTANCES,
            4096,
            4096,
            0,
            std::ptr::null_mut(),
        );

        if read_handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }

        // Open the write end of the pipe
        use windows_sys::Win32::Storage::FileSystem::{
            CreateFileA, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, GENERIC_WRITE, OPEN_EXISTING,
        };

        let write_handle = CreateFileA(
            pipe_name_c.as_ptr() as *const u8,
            GENERIC_WRITE,
            FILE_SHARE_READ,
            std::ptr::null_mut(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        );

        if write_handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }

        // Set non-blocking for write handle if needed
        if matches!(writer_type, WriterType::NonBlocking) {
            use windows_sys::Win32::System::Pipes::SetNamedPipeHandleState;
            use windows_sys::Win32::System::Pipes::PIPE_NOWAIT;
            let mode = PIPE_NOWAIT;
            if SetNamedPipeHandleState(write_handle, &mode, std::ptr::null_mut(), std::ptr::null_mut()) == 0 {
                return Err(io::Error::last_os_error());
            }
        }

        Ok(Pipe {
            reader: OwnedHandle::from_raw_handle(read_handle as *mut _),            writer: OwnedHandle::from_raw_handle(write_handle as *mut _),        })
    }
}
