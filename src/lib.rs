//! This crate allows you to execute osquery SQL queries using osquery Thrift API. You can execute osquery SQL query using one of the following methods:
//! * Connect to the extension socket for an existing osquery instance
//! * Spawn your own osquery instance and communicate with it using its extension socket
//! Currently this crates only works on Linux. I am still working on Windows version.
mod osquery_binding;
use osquery_binding::{ExtensionResponse, TExtensionManagerSyncClient};
use thrift;

#[cfg(target_os = "windows")]
use named_pipe::PipeClient;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::unix::net::UnixStream;
use std::{
    io::Result,
    ops::Drop,
    process::{Child, Command, Stdio},
    time::Duration,
};
use thrift::protocol::{TBinaryInputProtocol, TBinaryOutputProtocol};

/// A Struct that handles osquery Thrif API comunication
/// # Examples
///
/// ```
/// use osquery_rs::OSQuery;
///
/// fn main () {
///     let res = OSQuery::new()
///             .set_socket("/home/root/.osquery/shell.em")
///             .query(String::from("select * from time"))
///             .unwrap();
///     println!("{:#?}", res);
/// }
/// ```
pub struct OSQuery {
    _socket: String,
    _socket_cleanup: bool,
    osquery_instance: Option<Child>,
}

impl OSQuery {
    pub fn new() -> Self {
        Self {
            #[cfg(target_os = "windows")]
            _socket: String::from(r"\\.\pipe\osquery-rs"),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            _socket: String::from("/tmp/osquery-rs"),
            _socket_cleanup: false,
            osquery_instance: Option::None,
        }
    }

    /// Set the osquery Thrift API socket to be used for comunication with osquery service
    pub fn set_socket(mut self, path: &str) -> Self {
        self._socket = String::from(path);
        self
    }

    /// A getter for socket used for comunication
    pub fn get_socket(&self) -> String {
        self._socket.clone()
    }

    /// Spawn an instance of osquery. This allows the use of osquery in system that does not have osquery installed (standalone)
    /// # Examples
    ///
    /// ```
    /// use osquery_rs::OSQuery;
    ///
    /// fn main() {
    ///     let res = OSQuery::new()
    ///         // Specify the path to the osquery binary
    ///         .spawn_instance("./osqueryd")
    ///         .unwrap()
    ///         .query(String::from("select * from time"))
    ///         .unwrap();
    ///     println!("{:#?}", res);
    /// }
    /// ```
    pub fn spawn_instance(mut self, path: &str) -> Result<Self> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let osquery_instance = Command::new(path)
                .args([
                    "--extensions_socket",
                    &self._socket,
                    "--disable_database",
                    "--disable_watchdog",
                    "--disable_logging",
                    "--ephemeral",
                    "--config_path",
                    "/dev/null",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?;

            // Wait until the socket is ready
            loop {
                match UnixStream::connect(&self._socket) {
                    Ok(_) => break,
                    Err(_) => continue,
                };
            }
            self.osquery_instance = Some(osquery_instance);
        }

        #[cfg(target_os = "windows")]
        {
            println!("{:#?}", &self._socket);
            println!("{:#?}", path);
            let osquery_instance = Command::new(path)
                .arg("--extensions_socket")
                .arg(&self._socket)
                .arg("--disable_database")
                .arg("--disable_watchdog")
                .arg("--disable_logging")
                .arg("--ephemeral")
                .arg("--config_path")
                .arg("/dev/null")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?;

            // Wait until the socket is ready
            loop {
                match PipeClient::connect(&self._socket) {
                    Ok(_) => break,
                    Err(_) => continue,
                };
            }
            self.osquery_instance = Some(osquery_instance);
        }
        self._socket_cleanup = true;
        Ok(self)
    }

    /// Execute an osquery SQL query and retrive the results
    pub fn query(&self, sql: String) -> Result<ExtensionResponse> {
        #[cfg(target_os = "windows")]
        let (reader, writer) = {
            let mut reader = PipeClient::connect(&self._socket)?;
            reader.set_read_timeout(Some(Duration::new(3, 0)));
            reader.set_write_timeout(Some(Duration::new(3, 0)));
            let mut writer = PipeClient::connect(&self._socket)?;
            writer.set_read_timeout(Some(Duration::new(3, 0)));
            writer.set_write_timeout(Some(Duration::new(3, 0)));
            (reader, writer)
        };
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let (reader, writer) = {
            let reader = UnixStream::connect(&self._socket)?;
            reader.set_read_timeout(Some(Duration::new(3, 0)))?;
            reader.set_write_timeout(Some(Duration::new(3, 0)))?;
            let writer = reader.try_clone()?;
            (reader, writer)
        };
        let input_protocol = TBinaryInputProtocol::new(reader, false);
        let output_protocol = TBinaryOutputProtocol::new(writer, false);
        let mut extention_manager_client =
            osquery_binding::ExtensionManagerSyncClient::new(input_protocol, output_protocol);
        extention_manager_client.query(sql.clone()).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Unable to execute the query '{}', ERROR: {}", sql, e),
            )
        })
    }
}

impl Drop for OSQuery {
    fn drop(&mut self) {
        match &mut self.osquery_instance {
            Some(p) => {
                p.kill()
                    .expect(&format!("Unable to kill child process {}", p.id()));
            }
            None => {}
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            if self._socket_cleanup {
                std::fs::remove_file(&self._socket)
                    .expect(&format!("Unable to remove socket '{}'", &self._socket));
            }
        }
    }
}
