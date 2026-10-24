//! Local-only, owner-restricted named pipes with bounded nonblocking I/O.
use std::{
    hash::{Hash, Hasher},
    io::{self, Read, Write},
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, GetLastError, LocalFree, ERROR_NO_DATA, ERROR_PIPE_CONNECTED,
        ERROR_PIPE_LISTENING, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
    },
    Security::{
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            GetSecurityInfo, SE_KERNEL_OBJECT,
        },
        EqualSid, GetTokenInformation, TokenUser, OWNER_SECURITY_INFORMATION, SECURITY_ATTRIBUTES,
        TOKEN_QUERY, TOKEN_USER,
    },
    Storage::FileSystem::{
        CreateFileW, ReadFile, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE, OPEN_EXISTING,
        PIPE_ACCESS_DUPLEX, READ_CONTROL, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
    },
    System::{
        Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, SetNamedPipeHandleState,
            PIPE_NOWAIT, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
        },
        Threading::{GetCurrentProcess, OpenProcessToken},
    },
};

struct Pipe(HANDLE);
unsafe impl Send for Pipe {}
unsafe impl Sync for Pipe {}
impl Drop for Pipe {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}
pub(super) struct Listener(Arc<Pipe>);
pub(super) struct Stream {
    pipe: Arc<Pipe>,
    server: bool,
    timeout: Duration,
}
fn name(path: &Path) -> Vec<u16> {
    let mut hash = std::collections::hash_map::DefaultHasher::new();
    path.hash(&mut hash);
    format!(r"\\.\pipe\silvervine-{:016x}", hash.finish())
        .encode_utf16()
        .chain(Some(0))
        .collect()
}
fn current_user() -> io::Result<Vec<usize>> {
    unsafe {
        let mut token = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) == 0 {
            return Err(io::Error::last_os_error());
        }
        let token = Pipe(token);
        let mut size = 0;
        GetTokenInformation(token.0, TokenUser, std::ptr::null_mut(), 0, &raw mut size);
        let mut buffer = vec![0usize; (size as usize).div_ceil(std::mem::size_of::<usize>())];
        if GetTokenInformation(
            token.0,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            size,
            &raw mut size,
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(buffer)
    }
}
impl Listener {
    pub fn bind(path: &Path) -> io::Result<Self> {
        let user = current_user()?;
        let mut sid_text = std::ptr::null_mut();
        let sid = unsafe { (*user.as_ptr().cast::<TOKEN_USER>()).User.Sid };
        if unsafe { ConvertSidToStringSidW(sid, &raw mut sid_text) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut len = 0;
        unsafe {
            while *sid_text.add(len) != 0 {
                len += 1;
            }
        }
        let sid_string =
            unsafe { String::from_utf16_lossy(std::slice::from_raw_parts(sid_text, len)) };
        unsafe {
            LocalFree(sid_text.cast());
        }
        let sddl: Vec<u16> = format!("O:{sid_string}D:P(A;;GA;;;{sid_string})")
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let mut descriptor = std::ptr::null_mut();
        unsafe {
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &raw mut descriptor,
                std::ptr::null_mut(),
            ) == 0
            {
                return Err(io::Error::last_os_error());
            }
            let attributes = SECURITY_ATTRIBUTES {
                nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>())
                    .expect("SECURITY_ATTRIBUTES fits DWORD"),
                lpSecurityDescriptor: descriptor,
                bInheritHandle: 0,
            };
            let handle = CreateNamedPipeW(
                name(path).as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                65536,
                65536,
                0,
                &raw const attributes,
            );
            let error = io::Error::last_os_error();
            LocalFree(descriptor);
            if handle == INVALID_HANDLE_VALUE {
                return Err(error);
            }
            Ok(Self(Arc::new(Pipe(handle))))
        }
    }
    pub fn accept(&self) -> io::Result<(Stream, ())> {
        unsafe {
            if ConnectNamedPipe(self.0 .0, std::ptr::null_mut()) == 0 {
                let error = GetLastError();
                if error == ERROR_NO_DATA {
                    DisconnectNamedPipe(self.0 .0);
                    return Err(io::ErrorKind::WouldBlock.into());
                }
                if error != ERROR_PIPE_CONNECTED {
                    return Err(if error == ERROR_PIPE_LISTENING {
                        io::ErrorKind::WouldBlock.into()
                    } else {
                        io::Error::from_raw_os_error(i32::from_ne_bytes(error.to_ne_bytes()))
                    });
                }
            }
        }
        Ok((
            Stream {
                pipe: Arc::clone(&self.0),
                server: true,
                timeout: Duration::from_secs(5),
            },
            (),
        ))
    }
}
impl Stream {
    pub fn connect(path: &Path) -> io::Result<Self> {
        unsafe {
            let handle = CreateFileW(
                name(path).as_ptr(),
                GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                std::ptr::null_mut(),
            );
            if handle == INVALID_HANDLE_VALUE {
                return Err(io::Error::last_os_error());
            }
            let pipe = Arc::new(Pipe(handle));
            let user = current_user()?;
            let mut owner = std::ptr::null_mut();
            let mut descriptor = std::ptr::null_mut();
            let status = GetSecurityInfo(
                handle,
                SE_KERNEL_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &raw mut owner,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &raw mut descriptor,
            );
            if status != 0 {
                return Err(io::Error::from_raw_os_error(i32::from_ne_bytes(
                    status.to_ne_bytes(),
                )));
            }
            let trusted = EqualSid(owner, (*user.as_ptr().cast::<TOKEN_USER>()).User.Sid) != 0;
            LocalFree(descriptor);
            if !trusted {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "IPC server belongs to another user",
                ));
            }
            let mode = PIPE_READMODE_BYTE | PIPE_NOWAIT;
            if SetNamedPipeHandleState(handle, &raw const mode, std::ptr::null(), std::ptr::null())
                == 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(Self {
                pipe,
                server: false,
                timeout: Duration::from_secs(5),
            })
        }
    }
    // The transport stays nonblocking; Read/Write implement bounded blocking semantics.
    pub fn set_read_timeout(&mut self, value: Option<Duration>) -> io::Result<()> {
        if value == Some(Duration::ZERO) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "timeout must be nonzero",
            ));
        }
        self.timeout = value.unwrap_or(Duration::from_secs(5));
        Ok(())
    }
    pub fn set_write_timeout(&mut self, value: Option<Duration>) -> io::Result<()> {
        self.set_read_timeout(value)
    }
    fn transfer(&self, buffer: *mut u8, len: usize, write: bool) -> io::Result<usize> {
        let deadline = Instant::now() + self.timeout;
        loop {
            let mut transferred = 0;
            let result = unsafe {
                if write {
                    WriteFile(
                        self.pipe.0,
                        buffer,
                        u32::try_from(len).unwrap_or(u32::MAX),
                        &raw mut transferred,
                        std::ptr::null_mut(),
                    )
                } else {
                    ReadFile(
                        self.pipe.0,
                        buffer,
                        u32::try_from(len).unwrap_or(u32::MAX),
                        &raw mut transferred,
                        std::ptr::null_mut(),
                    )
                }
            };
            if result != 0 && transferred != 0 {
                return Ok(transferred as usize);
            }
            if result == 0 {
                let error = unsafe { GetLastError() };
                if error != ERROR_NO_DATA {
                    return Err(io::Error::from_raw_os_error(i32::from_ne_bytes(
                        error.to_ne_bytes(),
                    )));
                }
            }
            if Instant::now() >= deadline {
                return Err(io::ErrorKind::TimedOut.into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
impl Read for Stream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        self.transfer(buffer.as_mut_ptr(), buffer.len(), false)
    }
}
impl Write for Stream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        self.transfer(buffer.as_ptr().cast_mut(), buffer.len(), true)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Drop for Stream {
    fn drop(&mut self) {
        if self.server {
            unsafe {
                DisconnectNamedPipe(self.pipe.0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::*;
    #[test]
    fn windows_pipe_round_trip_and_duplicate_server_rejection() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("ipc");
        let mut server = start_at(&path, |_| IpcResponse::ok(IpcResult::Ack)).unwrap();
        assert!(start_at(&path, |_| IpcResponse::ok(IpcResult::Ack)).is_err());
        assert_eq!(
            send_request(&path, &IpcRequest::Status).unwrap(),
            IpcResponse::ok(IpcResult::Ack)
        );
        server.shutdown();
        assert!(send_request(&path, &IpcRequest::Status).is_err());
    }
}
