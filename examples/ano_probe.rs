//! Throwaway manual probe for the ANO/NNE work. Connects with env-provided
//! credentials and runs a trivial query, printing success/failure.
//!
//!   ORACLE_PORT=1522 cargo run --example ano_probe

fn main() {
    let host = std::env::var("ORACLE_HOST")
        .unwrap_or_else(|_| "localhost".to_string());
    let port =
        std::env::var("ORACLE_PORT").unwrap_or_else(|_| "1521".to_string());
    let service = std::env::var("ORACLE_SERVICE")
        .unwrap_or_else(|_| "highlandpdb".to_string());
    let user =
        std::env::var("ORACLE_USER").unwrap_or_else(|_| "system".to_string());
    let password =
        std::env::var("ORACLE_PWD").unwrap_or_else(|_| "test".to_string());
    let connect_string = format!("{host}:{port}/{service}");
    println!("connecting to {connect_string} as {user}");

    let config = oracledb::Config::default()
        .set_credentials(&user, &password)
        .set_connect_string(&connect_string)
        .expect("connect string");
    match oracledb::connect(config) {
        Ok(conn) => {
            println!("CONNECTED");
            match conn.query("SELECT 1 AS one FROM dual", &[]) {
                Ok(mut cursor) => match cursor.next() {
                    Some(Ok(row)) => println!("ROW: {:?}", row.get::<i64>(0)),
                    Some(Err(e)) => println!("ROW ERROR: {e}"),
                    None => println!("NO ROWS"),
                },
                Err(e) => println!("QUERY ERROR: {e}"),
            }
        }
        Err(e) => println!("CONNECT ERROR: {e}"),
    }
}
