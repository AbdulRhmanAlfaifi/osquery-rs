#[cfg(test)]
mod tests {
    use osquery_rs::OSQuery;
    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn linux_time_test() {
        use dirs;
        let res = OSQuery::new()
            .set_socket(&format!(
                "{}/.osquery/shell.em",
                dirs::home_dir().unwrap().to_string_lossy()
            ))
            .query(String::from("select * from time"))
            .unwrap();
        println!("{:#?}", res);
        assert_eq!(res.status.unwrap().code.unwrap(), 0);
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn linux_time_test_span_instance() {
        let osquery_bin_path = &format!(
            "{}/{}/{}",
            env!("CARGO_MANIFEST_DIR"),
            "osquery",
            "osqueryd"
        );
        let osquery_instance = OSQuery::new().spawn_instance(osquery_bin_path).unwrap();
        let res = osquery_instance
            .query(String::from("select * from time"))
            .unwrap();
        println!("{:#?}", res);
        assert_eq!(res.status.unwrap().code.unwrap(), 0);
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn windows_time_test() {
        let res = OSQuery::new()
            .set_socket(r"\\.\pipe\osquery_test")
            .query(String::from("select * from time"))
            .unwrap();
        println!("{:#?}", res);
        assert_ne!(res.status.unwrap().code.unwrap(), 0);
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn windows_time_test_span_instance() {
        let osquery_bin_path = &format!(
            "{}\\{}\\{}",
            env!("CARGO_MANIFEST_DIR"),
            "osquery",
            "osqueryd.exe"
        );
        let res = OSQuery::new()
            .spawn_instance(osquery_bin_path)
            .unwrap()
            .query(String::from("select * from time"))
            .unwrap();
        println!("{:#?}", res);
        assert_ne!(res.status.unwrap().code.unwrap(), 0);
    }
}
