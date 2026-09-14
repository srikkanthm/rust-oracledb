// -----------------------------------------------------------------------------
// Oracle Native Network Encryption (ANO / NNE) handshake.
//
// Ported from the pure-Go driver `sijms/go-ora` (`v2/advanced_nego`). The
// exchange runs over plain TNS DATA packets immediately after the ACCEPT,
// before any TTC protocol/auth message: the client offers its service lists,
// the server replies with the chosen encryption algorithm and the
// Diffie-Hellman group, and the client returns its public key. Thereafter all
// DATA packets are encrypted with the derived session key.
// -----------------------------------------------------------------------------

use rand::RngExt;
use std::time::Duration;

use crate::constants;
use crate::encryption::{
    AesCryptor, EncryptAlgo, Integrity, IntegrityAlgo, dh_public_key,
    dh_shared_key,
};
use crate::error::Error;
use crate::transport::Transport;

/// Where the ANO handshake trace is written so it can be shared for debugging.
fn ano_log_path() -> std::path::PathBuf {
    let home = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    home.join("sqlhighland-ano-debug.log")
}

/// Compact hex dump for the trace.
fn hex_dump(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 3);
    for byte in bytes.iter().take(256) {
        out.push_str(&format!("{byte:02x} "));
    }
    if bytes.len() > 256 {
        out.push_str("...");
    }
    out
}

/// Whether the handshake trace is currently being recorded.
static ANO_TRACE_ON: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Whether the ANO debug trace is enabled. It is opt-in (set
/// `SQLHIGHLAND_ANO_TRACE`) so normal use never writes to the home directory.
fn ano_trace_enabled() -> bool {
    std::env::var_os("SQLHIGHLAND_ANO_TRACE").is_some()
}

/// Starts a fresh handshake trace (called at the beginning of ANO setup).
pub(crate) fn ano_trace_start() {
    let enabled = ano_trace_enabled();
    if enabled {
        let _ = std::fs::write(ano_log_path(), b"");
    }
    ANO_TRACE_ON.store(enabled, std::sync::atomic::Ordering::Relaxed);
}

/// Stops recording (called once the connection is fully established).
pub(crate) fn ano_trace_stop() {
    ANO_TRACE_ON.store(false, std::sync::atomic::Ordering::Relaxed);
}

/// Appends a line to the handshake trace while it is enabled.
pub(crate) fn ano_trace(message: &str) {
    if !ANO_TRACE_ON.load(std::sync::atomic::Ordering::Relaxed) {
        return;
    }
    use std::io::Write;
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(ano_log_path())
    {
        let _ = writeln!(file, "{message}");
    }
}

const ANO_MAGIC: u32 = 0xDEAD_BEEF;
const ANO_VERSION: u32 = 0x0B20_0200;

const SERVICE_AUTH: u16 = 1;
const SERVICE_ENCRYPT: u16 = 2;
const SERVICE_INTEGRITY: u16 = 3;
const SERVICE_SUPERVISOR: u16 = 4;

const SUB_BYTES: u16 = 1;
const SUB_UB1: u16 = 2;
const SUB_UB2: u16 = 3;
const SUB_VERSION: u16 = 5;
const SUB_STATUS: u16 = 6;

/// AES algorithm ids offered in the "encrypt" service.
const AES_ALGOS: [u8; 3] = [15, 16, 17]; // AES128, AES192, AES256

fn ano_err(message: &str) -> Error {
    Error::advanced_negotiation(message.to_string())
}

/// Little byte-buffer builder for the ANO framing.
#[derive(Default)]
struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    fn u8(&mut self, value: u8) {
        self.buf.push(value);
    }

    fn u16(&mut self, value: u16) {
        self.buf.extend_from_slice(&value.to_be_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.buf.extend_from_slice(&value.to_be_bytes());
    }

    fn raw(&mut self, value: &[u8]) {
        self.buf.extend_from_slice(value);
    }

    /// Writes a sub-packet: `[payload length u16][type u16][payload]`.
    fn sub(&mut self, sub_type: u16, payload: &[u8]) {
        self.u16(payload.len() as u16);
        self.u16(sub_type);
        self.raw(payload);
    }

    fn sub_version(&mut self) {
        self.sub(SUB_VERSION, &ANO_VERSION.to_be_bytes());
    }

    fn sub_ub1(&mut self, value: u8) {
        self.sub(SUB_UB1, &[value]);
    }

    fn sub_ub2(&mut self, value: u16) {
        self.sub(SUB_UB2, &value.to_be_bytes());
    }

    fn sub_bytes(&mut self, value: &[u8]) {
        self.sub(SUB_BYTES, value);
    }

    fn sub_status(&mut self, value: u16) {
        self.sub(SUB_STATUS, &value.to_be_bytes());
    }

    /// `writeUB2Array`: a length-prefixed u16 array in a bytes sub-packet.
    fn sub_u16_array(&mut self, values: &[u16]) {
        let mut payload = Writer::default();
        payload.u32(ANO_MAGIC);
        payload.u16(3);
        payload.u32(values.len() as u32);
        for value in values {
            payload.u16(*value);
        }
        self.sub(SUB_BYTES, &payload.buf);
    }
}

/// Wraps a service body in its 8-byte service header.
fn service(service_type: u16, sub_packets: u16, body: &[u8]) -> Vec<u8> {
    let mut writer = Writer::default();
    writer.u16(service_type);
    writer.u16(sub_packets);
    writer.u32(0); // status
    writer.raw(body);
    writer.buf
}

fn build_supervisor() -> Vec<u8> {
    let mut body = Writer::default();
    body.sub_version();
    body.sub_bytes(&[0, 0, 16, 28, 102, 236, 40, 234]); // connection id
    body.sub_u16_array(&[4, 1, 2, 3]);
    service(SERVICE_SUPERVISOR, 3, &body.buf)
}

fn build_auth() -> Vec<u8> {
    let mut body = Writer::default();
    body.sub_version();
    body.sub_ub2(0xE0E1);
    body.sub_status(0xFCFF);
    service(SERVICE_AUTH, 3, &body.buf)
}

fn build_encrypt() -> Vec<u8> {
    let mut body = Writer::default();
    body.sub_version();
    body.sub_bytes(&AES_ALGOS);
    body.sub_ub1(1); // "selected driver"
    service(SERVICE_ENCRYPT, 3, &body.buf)
}

fn build_integrity() -> Vec<u8> {
    let mut body = Writer::default();
    body.sub_version();
    // Offer "none" as well as the checksums. A server that only ACCEPTS
    // checksums (the common default) then skips it; otherwise it can pick a
    // hash. (Oracle re-keys the checksum on a reset, which the client cannot
    // currently track, so avoiding a negotiated checksum is preferable.)
    body.sub_bytes(&[0, 5, 4, 6]);
    service(SERVICE_INTEGRITY, 2, &body.buf)
}

/// The initial client request carrying all four service lists.
fn build_client_request() -> Vec<u8> {
    let services = [
        build_supervisor(),
        build_auth(),
        build_encrypt(),
        build_integrity(),
    ];
    let size: usize = services.iter().map(Vec::len).sum();
    let mut writer = Writer::default();
    writer.u32(ANO_MAGIC);
    writer.u16((13 + size) as u16);
    writer.u32(ANO_VERSION);
    writer.u16(services.len() as u16);
    writer.u8(0); // error flags
    for service in &services {
        writer.raw(service);
    }
    writer.buf
}

/// The reply carrying the client's Diffie-Hellman public key.
fn build_client_public_key(public_key: &[u8]) -> Vec<u8> {
    let mut body = Writer::default();
    body.sub_bytes(public_key);
    let service = service(SERVICE_INTEGRITY, 1, &body.buf);

    let mut writer = Writer::default();
    writer.u32(ANO_MAGIC);
    writer.u16((13 + service.len()) as u16);
    writer.u32(ANO_VERSION);
    writer.u16(1);
    writer.u8(0);
    writer.raw(&service);
    writer.buf
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], Error> {
        if self.pos + count > self.buf.len() {
            return Err(ano_err("truncated server response"));
        }
        let slice = &self.buf[self.pos..self.pos + count];
        self.pos += count;
        Ok(slice)
    }

    fn u16(&mut self) -> Result<u16, Error> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes(bytes.try_into().expect("2 bytes")))
    }

    fn u32(&mut self) -> Result<u32, Error> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes(bytes.try_into().expect("4 bytes")))
    }

    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }

    /// Reads `[length u16][type u16][payload]`.
    fn sub(&mut self) -> Result<(u16, Vec<u8>), Error> {
        let length = self.u16()? as usize;
        let sub_type = self.u16()?;
        Ok((sub_type, self.take(length)?.to_vec()))
    }
}

struct DhParams {
    generator: Vec<u8>,
    prime: Vec<u8>,
    server_public: Vec<u8>,
    iv: Vec<u8>,
    byte_len: usize,
}

struct ServerInfo {
    encrypt_algo: Option<EncryptAlgo>,
    /// Raw integrity algorithm id from the server (0 = none).
    integrity_algo: Option<u8>,
    dh: Option<DhParams>,
}

fn parse_server_response(buf: &[u8]) -> Result<ServerInfo, Error> {
    let mut reader = Reader::new(buf);
    if reader.u32()? != ANO_MAGIC {
        return Err(ano_err("missing ANO magic in server response"));
    }
    let _length = reader.u16()?;
    let _version = reader.u32()?;
    let service_count = reader.u16()?;
    let _error_flags = reader.u8()?;

    let mut info = ServerInfo {
        encrypt_algo: None,
        integrity_algo: None,
        dh: None,
    };
    for _ in 0..service_count {
        let service_type = reader.u16()?;
        let sub_packets = reader.u16()?;
        let status = reader.u32()?;
        if status != 0 {
            return Err(ano_err(&format!(
                "service {service_type} returned status {status}"
            )));
        }
        match service_type {
            SERVICE_ENCRYPT => {
                for _ in 0..sub_packets {
                    let (sub_type, payload) = reader.sub()?;
                    if sub_type == SUB_UB1 && !payload.is_empty() {
                        info.encrypt_algo = EncryptAlgo::from_id(payload[0]);
                    }
                }
            }
            SERVICE_INTEGRITY => {
                let mut subs = Vec::new();
                for _ in 0..sub_packets {
                    subs.push(reader.sub()?);
                }
                // sub-packet 1 is the chosen integrity algorithm id.
                if let Some(payload) = subs.get(1).map(|(_, p)| p)
                    && !payload.is_empty()
                {
                    info.integrity_algo = Some(payload[0]);
                }
                // DH is sent only when encryption is being negotiated, as
                // eight sub-packets: version, ub1, ub2, ub2, bytes x4.
                if sub_packets == 8 && subs.len() == 8 {
                    let dh_gen_len = u16::from_be_bytes(
                        subs[2].1[..2].try_into().expect("ub2"),
                    ) as usize;
                    let generator = subs[4].1.clone();
                    let prime = subs[5].1.clone();
                    let server_public = subs[6].1.clone();
                    let iv = subs[7].1.clone();
                    let byte_len = dh_gen_len.div_ceil(8);
                    if server_public.len() != byte_len
                        || prime.len() != byte_len
                    {
                        return Err(ano_err(
                            "Diffie-Hellman negotiation out of sync",
                        ));
                    }
                    info.dh = Some(DhParams {
                        generator,
                        prime,
                        server_public,
                        iv,
                        byte_len,
                    });
                }
            }
            _ => {
                for _ in 0..sub_packets {
                    let _ = reader.sub()?;
                }
            }
        }
    }
    Ok(info)
}

fn send_ano_data(transport: &mut Transport, data: &[u8]) -> Result<(), Error> {
    transport.send_packets(constants::PACKET_TYPE_DATA, 0, 0, data)
}

fn receive_ano_data(
    transport: &mut Transport,
    trace: &mut String,
) -> Result<Vec<u8>, Error> {
    loop {
        let packet = match transport.receive_packet() {
            Ok(packet) => packet,
            Err(e) => {
                trace.push_str(&format!("recv error: {e}\n"));
                return Err(e);
            }
        };
        trace.push_str(&format!(
            "recv type={} flags={} len={} hex={}\n",
            packet.packet_type,
            packet.packet_flags,
            packet.buf.len(),
            hex_dump(&packet.buf)
        ));
        match packet.packet_type {
            constants::PACKET_TYPE_DATA => return Ok(packet.buf),
            // Control packets (in-band notifications) are not part of the ANO
            // exchange, but may carry an ORA error worth surfacing instead of
            // silently hanging.
            constants::PACKET_TYPE_CONTROL => {
                if packet.buf.len() >= 10
                    && u16::from_be_bytes(
                        packet.buf[0..2].try_into().expect("2"),
                    ) == constants::TTC_CONTROL_TYPE_INBAND_NOTIF
                {
                    let err = u32::from_be_bytes(
                        packet.buf[6..10].try_into().expect("4"),
                    );
                    if err != 0 {
                        return Err(ano_err(&format!(
                            "server reported ORA-{err:05} during the ANO \
                             handshake"
                        )));
                    }
                }
                continue;
            }
            constants::PACKET_TYPE_MARKER => continue,
            other => {
                return Err(ano_err(&format!(
                    "expected a DATA packet, got type {other}"
                )));
            }
        }
    }
}

/// The negotiated ANO session: AES encryption and (optionally) a checksum.
pub(crate) struct AnoSession {
    pub crypt: Option<AesCryptor>,
    pub integrity: Option<Integrity>,
}

/// Runs the ANO handshake and returns the negotiated crypto, if any. Both
/// fields are `None` when the server did not enable ANO.
pub(crate) fn negotiate(
    transport: &mut Transport,
) -> Result<AnoSession, Error> {
    // Bound the handshake so a misbehaving server cannot hang the app, and
    // record a trace for debugging (only when tracing is enabled).
    let traced = ano_trace_enabled();
    let _ = transport.set_read_timeout(Some(Duration::from_secs(20)));
    let mut trace = String::new();
    let result = negotiate_inner(transport, &mut trace);
    let _ = transport.set_read_timeout(None);
    if let Err(e) = &result {
        trace.push_str(&format!("error: {e}\n"));
    }
    // Append (ano_trace_start already cleared the file at connect start).
    ano_trace(trace.trim_end());
    match result {
        Ok(session) => Ok(session),
        Err(e) => {
            let suffix = if traced {
                format!(
                    " (handshake trace written to {})",
                    ano_log_path().display()
                )
            } else {
                String::new()
            };
            Err(ano_err(&format!("{e}{suffix}")))
        }
    }
}

fn negotiate_inner(
    transport: &mut Transport,
    trace: &mut String,
) -> Result<AnoSession, Error> {
    let request = build_client_request();
    trace.push_str(&format!(
        "send len={} hex={}\n",
        request.len(),
        hex_dump(&request)
    ));
    send_ano_data(transport, &request)?;
    let response = receive_ano_data(transport, trace)?;
    trace.push_str(&format!("recv ANO response len={}\n", response.len()));
    let info = parse_server_response(&response)?;

    let Some(dh) = info.dh else {
        // No Diffie-Hellman exchange means no encryption was negotiated.
        return Ok(AnoSession {
            crypt: None,
            integrity: None,
        });
    };

    let mut private_key = vec![0u8; dh.byte_len];
    rand::rng().fill(&mut private_key);
    let public_key =
        dh_public_key(&dh.generator, &dh.prime, &private_key, dh.byte_len);
    let shared_key =
        dh_shared_key(&dh.server_public, &private_key, &dh.prime, dh.byte_len);

    trace.push_str(&format!(
        "negotiated encrypt={:?} integrity={:?} dh_byte_len={} shared_len={} public_len={}\n",
        info.encrypt_algo,
        info.integrity_algo,
        dh.byte_len,
        shared_key.len(),
        public_key.len()
    ));
    send_ano_data(transport, &build_client_public_key(&public_key))?;

    let crypt = match info.encrypt_algo {
        Some(algo) => {
            Some(AesCryptor::new(algo, &shared_key).map_err(|e| ano_err(&e))?)
        }
        None => None,
    };
    let integrity = match info.integrity_algo {
        Some(id) if id != 0 => {
            let algo = IntegrityAlgo::from_id(id).ok_or_else(|| {
                ano_err(&format!("unsupported integrity algorithm {id}"))
            })?;
            Some(
                Integrity::new(algo, &shared_key, &dh.iv)
                    .map_err(|e| ano_err(&e))?,
            )
        }
        _ => None,
    };
    trace.push_str(&format!(
        "crypt={} integrity={}\n",
        crypt.is_some(),
        integrity.is_some()
    ));
    Ok(AnoSession { crypt, integrity })
}
