# osquery-rs

This crate allows you to execute osquery SQL queries using osquery Thrift API. You can execute osquery SQL query using one of the following methods:

* Connect to the extension socket for an existing osquery instance

* Spawn your own osquery instance and communicate with it using its extension socket

Currently this crates only works on Linux. I am still working on Windows version.

## Usage

* Add it to your dependencies

  ```toml
  [dependencies]
  osquery-rs = { git = "https://github.com/AbdulRhmanAlfaifi/osquery-rs"}
  ```

* Start executing queries !

## Examples

### Connect to extension socket for an existing osquery instance

```rust
use osquery_rs::OSQuery;

fn main () {
    let res = OSQuery::new()
            .set_socket("/home/root/.osquery/shell.em")
            .query(String::from("select * from time"))
            .unwrap();
    println!("{:#?}", res);
}
```

### Spawn your own osquery instance (standalone)

```rust
use osquery_rs::OSQuery;

fn main() {
    let res = OSQuery::new()
        // Specify the path to the osquery binary
        .spawn_instance("./osqueryd")
        .unwrap()
        .query(String::from("select * from time"))
        .unwrap();
    println!("{:#?}", res);
}
```

by default the socket path is `/tmp/osquery-rs`, you can change it by calling the function `set_socket`:

```rust
use osquery_rs::OSQuery;

fn main() {
    let res = OSQuery::new()
        .set_socket("/tmp/mysocket")
        // Specify the path to the osquery binary
        .spawn_instance("./osqueryd")
        .unwrap()
        .query(String::from("select * from time"))
        .unwrap();
    println!("{:#?}", res);
}
```

