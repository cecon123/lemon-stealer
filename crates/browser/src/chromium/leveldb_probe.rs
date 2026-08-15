#[cfg(test)]
mod probe {
    use crate::chromium::leveldb::tests as ldb;

    #[test]
    fn probe_crc() {
        let block = vec![1u8, 2, 3, 4, 5, 0, 0, 0, 0, 1, 0, 0, 0];
        let mask = |crc: u32| crc.rotate_right(15).wrapping_add(0xa282_ead8);
        for snappy in [false, true] {
            let out = ldb::compress_type(&block, snappy);
            let end = out.len() - 5;
            let stored =
                u32::from_le_bytes([out[end + 1], out[end + 2], out[end + 3], out[end + 4]]);
            let expect = mask(crc32c::crc32c(&out[..=end]));
            assert_eq!(stored, expect, "snappy={snappy} crc mismatch");
            let ctype = out[end];
            assert_eq!(ctype, if snappy { 1 } else { 0 });
        }
    }

    #[test]
    fn probe_table_roundtrip() {
        let bytes = ldb::table_bytes(&[(b"a", 10, 1, b"1"), (b"b", 10, 1, b"2")], true);
        use crate::chromium::leveldb::read_table;
        let dir = std::env::temp_dir().join(format!("hbd-probe-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("000001.ldb");
        std::fs::write(&p, &bytes).unwrap();
        let entries = read_table(&p).unwrap();
        println!(
            "{:?}",
            entries
                .iter()
                .map(|e| (&e.key, &e.value))
                .collect::<Vec<_>>()
        );
        assert!(entries.len() == 2);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
