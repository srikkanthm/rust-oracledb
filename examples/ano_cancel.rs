//! Throwaway manual probe for cancellation over an ANO-encrypted session.
//!
//!   ORACLE_PORT=1522 cargo run --example ano_cancel

use std::time::{Duration, Instant};

fn main() {
    let host = std::env::var("ORACLE_HOST")
        .unwrap_or_else(|_| "localhost".to_string());
    let port =
        std::env::var("ORACLE_PORT").unwrap_or_else(|_| "1522".to_string());
    let service = std::env::var("ORACLE_SERVICE")
        .unwrap_or_else(|_| "highlandpdb".to_string());
    let user =
        std::env::var("ORACLE_USER").unwrap_or_else(|_| "system".to_string());
    let password =
        std::env::var("ORACLE_PWD").unwrap_or_else(|_| "test".to_string());
    let connect_string = format!("{host}:{port}/{service}");

    let config = oracledb::Config::default()
        .set_credentials(&user, &password)
        .set_connect_string(&connect_string)
        .expect("connect string");
    let conn = oracledb::connect(config).expect("connect");
    println!("CONNECTED to {connect_string}");
    let cancel = conn.cancel_handle().expect("cancel handle");

    let worker = std::thread::spawn(move || {
        let started = Instant::now();
        let result = conn.execute("BEGIN dbms_lock.sleep(15); END;", &[]);
        (conn, result, started.elapsed())
    });
    std::thread::sleep(Duration::from_secs(2));
    cancel.cancel().expect("cancel request");
    let (conn, result, elapsed) = worker.join().expect("worker");
    println!("statement returned in {elapsed:?}");
    match result {
        Ok(exec) => {
            println!("UNEXPECTED SUCCESS ({} rows)", exec.rows_affected())
        }
        Err(e) => println!("error kind {:?}: {e}", e.kind()),
    }
    match conn.query("SELECT 1 FROM dual", &[]) {
        Ok(mut c) => {
            let _ = c.next();
            println!("connection reusable: OK");
        }
        Err(e) => println!("connection NOT reusable: {e}"),
    }
}
