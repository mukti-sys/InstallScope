//! Decoding primitives for strace output.
//!
//! Everything here is a pure function over `&str`, which is what makes the Phase 1 parser testable
//! on any host — including the Windows machine this was written on, where the recorder itself cannot
//! run. Process orchestration is the only Linux-gated part of this crate.
//!
//! The Phase 0 harness proved these decodings against 50 real installs (Memory.md); this is the
//! Rust rewrite Phases.md:17 calls for, not a new design.

/// Result of reading a quoted strace string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Quoted {
    /// Decoded bytes. Binary, because DNS payloads are not text.
    pub bytes: Vec<u8>,
    /// Byte index just past the closing quote (and past any `...` marker).
    pub end: usize,
    /// strace cut the buffer short at its `-s` limit.
    pub truncated: bool,
}

/// Decodes strace's C-style string escaping into raw bytes.
///
/// strace renders buffers with printable characters literal and everything else escaped: `\n`, `\t`,
/// `\r`, `\f`, `\v`, `\b`, `\a`, `\\`, `\"`, octal `\NNN`, or hex `\xNN` under `-x`. Returns bytes
/// rather than a `String` because callers decide whether the content is text.
#[must_use]
pub fn decode_escaped(raw: &str) -> Vec<u8> {
    let src = raw.as_bytes();
    let mut out = Vec::with_capacity(src.len());
    let mut i = 0;
    while i < src.len() {
        if src[i] != b'\\' {
            out.push(src[i]);
            i += 1;
            continue;
        }
        if i + 1 >= src.len() {
            out.push(b'\\');
            break;
        }
        let next = src[i + 1];
        match next {
            b'n' => {
                out.push(b'\n');
                i += 2;
            }
            b't' => {
                out.push(b'\t');
                i += 2;
            }
            b'r' => {
                out.push(b'\r');
                i += 2;
            }
            b'f' => {
                out.push(0x0c);
                i += 2;
            }
            b'v' => {
                out.push(0x0b);
                i += 2;
            }
            b'b' => {
                out.push(0x08);
                i += 2;
            }
            b'a' => {
                out.push(0x07);
                i += 2;
            }
            b'\\' => {
                out.push(b'\\');
                i += 2;
            }
            b'"' => {
                out.push(b'"');
                i += 2;
            }
            b'x' => {
                let mut value: u32 = 0;
                let mut digits = 0;
                let mut j = i + 2;
                while j < src.len() && digits < 2 {
                    let Some(d) = (src[j] as char).to_digit(16) else {
                        break;
                    };
                    value = value * 16 + d;
                    digits += 1;
                    j += 1;
                }
                if digits == 0 {
                    out.push(b'\\');
                    i += 1;
                } else {
                    out.push(u8::try_from(value & 0xff).unwrap_or(0));
                    i = j;
                }
            }
            b'0'..=b'7' => {
                let mut value: u32 = 0;
                let mut digits = 0;
                let mut j = i + 1;
                while j < src.len() && digits < 3 {
                    let Some(d) = (src[j] as char).to_digit(8) else {
                        break;
                    };
                    value = value * 8 + d;
                    digits += 1;
                    j += 1;
                }
                out.push(u8::try_from(value & 0xff).unwrap_or(0));
                i = j;
            }
            _ => {
                out.push(b'\\');
                i += 1;
            }
        }
    }
    out
}

/// Reads a double-quoted strace string beginning at `start`, which must index the opening quote.
///
/// Returns `None` when the quote is unterminated, which means strace's own line was cut — a case
/// that must be reported rather than half-decoded.
#[must_use]
pub fn read_quoted(s: &str, start: usize) -> Option<Quoted> {
    let bytes = s.as_bytes();
    if start >= bytes.len() || bytes[start] != b'"' {
        return None;
    }
    let mut i = start + 1;
    let content_start = i;
    let mut escaped = false;
    loop {
        if i >= bytes.len() {
            return None;
        }
        if escaped {
            escaped = false;
            i += 1;
            continue;
        }
        match bytes[i] {
            b'\\' => {
                escaped = true;
                i += 1;
            }
            b'"' => break,
            _ => i += 1,
        }
    }
    let raw = s.get(content_start..i)?;
    let mut end = i + 1;
    let mut truncated = false;
    if s.get(end..end + 3) == Some("...") {
        truncated = true;
        end += 3;
    }
    Some(Quoted {
        bytes: decode_escaped(raw),
        end,
        truncated,
    })
}

/// Splits a syscall argument list on top-level commas, respecting quotes and nesting.
#[must_use]
pub fn split_args(s: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut current = String::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => {
                if let Some(q) = read_quoted(s, i) {
                    if let Some(slice) = s.get(i..q.end) {
                        current.push_str(slice);
                    }
                    i = q.end;
                } else {
                    if let Some(slice) = s.get(i..) {
                        current.push_str(slice);
                    }
                    break;
                }
            }
            b'(' | b'[' | b'{' => {
                depth += 1;
                current.push(bytes[i] as char);
                i += 1;
            }
            b')' | b']' | b'}' => {
                depth -= 1;
                current.push(bytes[i] as char);
                i += 1;
            }
            b',' if depth == 0 => {
                parts.push(current.trim().to_string());
                current.clear();
                i += 1;
            }
            _ => {
                // Push the whole UTF-8 char, not the byte, so non-ASCII paths survive.
                let ch_start = i;
                let mut ch_end = i + 1;
                while ch_end < bytes.len() && (bytes[ch_end] & 0xc0) == 0x80 {
                    ch_end += 1;
                }
                if let Some(slice) = s.get(ch_start..ch_end) {
                    current.push_str(slice);
                }
                i = ch_end;
            }
        }
    }
    let trimmed = current.trim();
    if !trimmed.is_empty() {
        parts.push(trimmed.to_string());
    }
    parts
}

/// Interprets a quoted argument as a filesystem path.
///
/// Returns `None` for a non-quoted argument (e.g. `NULL`), and lossily converts invalid UTF-8 —
/// paths on Linux are bytes, and refusing to display a mojibake filename would hide evidence. The
/// lossy conversion is confined to display; matching uses the same string, so a crafted non-UTF-8
/// path cannot evade a rule by being unreadable.
#[must_use]
pub fn quoted_to_path(arg: &str) -> Option<String> {
    let q = read_quoted(arg, 0)?;
    Some(String::from_utf8_lossy(&q.bytes).into_owned())
}

/// Extracts the annotation from an strace `-yy` file descriptor argument.
///
/// `-yy` renders descriptors as `3</abs/path>` or `4<TCP:[1.2.3.4:80]>`.
#[must_use]
pub fn fd_annotation(arg: &str) -> Option<&str> {
    let open = arg.find('<')?;
    let close = arg.rfind('>')?;
    if close <= open + 1 {
        return None;
    }
    let digits = arg.get(..open)?;
    let numeric = digits.strip_prefix('-').unwrap_or(digits);
    if numeric.is_empty() || !numeric.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    arg.get(open + 1..close)
}

/// Parses the numeric file descriptor from an argument like `3</tmp/x>` or plain `3`.
#[must_use]
pub fn fd_number(arg: &str) -> Option<i32> {
    let head = arg.split('<').next()?;
    head.trim().parse::<i32>().ok()
}

/// The return portion of a traced syscall.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RetInfo {
    /// `Some(true)` on success, `Some(false)` on a known failure, `None` when undeterminable.
    pub ok: Option<bool>,
    /// Numeric return value, when present.
    pub value: Option<i64>,
    /// Errno symbol on failure.
    pub error: Option<String>,
    /// `-yy` annotation on the returned descriptor, e.g. the resolved path of an opened file.
    pub annotation: Option<String>,
}

/// Parses the ` = 3</tmp/x>` / ` = -1 ENOENT (…)` / ` = ? <unavailable>` tail of a trace line.
///
/// The numeric value is taken as a *prefix*, not as a whitespace-delimited token: under `-yy` the
/// annotation is glued directly to the number (`= 3</tmp/x>`), so splitting on space would leave
/// `3</tmp/x>` unparseable and lose both the value and the resolved path.
///
/// `EINPROGRESS` on a non-blocking `connect` is treated as success: the connection attempt genuinely
/// happened, and scoring it as a failure would under-report network behavior.
#[must_use]
pub fn parse_ret(tail: &str) -> RetInfo {
    let trimmed = tail.trim_start();
    let Some(rest) = trimmed.strip_prefix('=') else {
        return RetInfo::default();
    };
    let rest = rest.trim_start();

    let (value, remainder) = if let Some(after) = rest.strip_prefix('?') {
        (None, after)
    } else {
        let digits_end = {
            let bytes = rest.as_bytes();
            let mut i = usize::from(bytes.first() == Some(&b'-'));
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            // A lone "-" is not a number.
            if i == usize::from(bytes.first() == Some(&b'-')) {
                0
            } else {
                i
            }
        };
        let token = rest.get(..digits_end).unwrap_or("");
        (
            token.parse::<i64>().ok(),
            rest.get(digits_end..).unwrap_or(""),
        )
    };

    // The annotation is immediately after the value when present: `3</tmp/x>`. Terminated on the
    // LAST '>' rather than the first, because a socket annotation contains one:
    // `7<TCP:[10.1.0.4:50001->104.16.0.1:443]>`.
    let annotation = remainder
        .strip_prefix('<')
        .and_then(|r| r.rfind('>').and_then(|i| r.get(..i)))
        .map(ToString::to_string);

    let after_annotation = if annotation.is_some() {
        remainder
            .rfind('>')
            .and_then(|i| remainder.get(i + 1..))
            .unwrap_or("")
    } else {
        remainder
    };

    let error = after_annotation
        .trim_start()
        .split(|c: char| !(c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'))
        .next()
        .filter(|token| token.len() >= 2 && token.starts_with(|c: char| c.is_ascii_uppercase()))
        .map(ToString::to_string);

    let ok = value.map(|v| v >= 0 || error.as_deref() == Some("EINPROGRESS"));

    RetInfo {
        ok,
        value,
        error,
        annotation,
    }
}

/// A socket address as rendered by strace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SockAddr {
    /// Address family.
    pub family: SockFamily,
    /// Destination address, for inet families.
    pub ip: Option<String>,
    /// Destination port, for inet families.
    pub port: Option<u16>,
    /// Socket path, for `AF_UNIX`.
    pub unix_path: Option<String>,
}

/// Address families this decoder distinguishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SockFamily {
    /// `AF_INET`.
    Inet,
    /// `AF_INET6`.
    Inet6,
    /// `AF_UNIX`.
    Unix,
    /// Anything else (netlink, packet, …).
    Other,
}

/// Extracts a value from a `key=…` field inside a strace struct rendering.
fn struct_field<'a>(s: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("{key}=");
    let start = s.find(&needle)? + needle.len();
    let rest = s.get(start..)?;
    let end = rest.find([',', '}']).unwrap_or(rest.len());
    rest.get(..end).map(str::trim)
}

/// Pulls the numeric argument out of a wrapper like `htons(443)` or `inet_addr("1.2.3.4")`.
fn unwrap_call(s: &str) -> Option<&str> {
    let open = s.find('(')?;
    let close = s.rfind(')')?;
    if close <= open {
        return None;
    }
    Some(s.get(open + 1..close)?.trim().trim_matches('"'))
}

/// Parses a strace-rendered `sockaddr` struct.
#[must_use]
pub fn parse_sockaddr(struct_text: &str) -> Option<SockAddr> {
    let family = struct_field(struct_text, "sa_family")?;
    match family {
        "AF_INET" => Some(SockAddr {
            family: SockFamily::Inet,
            ip: struct_field(struct_text, "sin_addr")
                .and_then(unwrap_call)
                .map(ToString::to_string),
            port: struct_field(struct_text, "sin_port")
                .and_then(unwrap_call)
                .and_then(|p| p.parse::<u16>().ok()),
            unix_path: None,
        }),
        "AF_INET6" => Some(SockAddr {
            family: SockFamily::Inet6,
            // strace renders v6 addresses as inet_pton(AF_INET6, "::1", …); take the quoted literal.
            ip: struct_field(struct_text, "sin6_addr")
                .and_then(|f| f.split('"').nth(1).map(ToString::to_string))
                .or_else(|| {
                    struct_text
                        .split("inet_pton(AF_INET6, \"")
                        .nth(1)
                        .and_then(|r| r.split('"').next())
                        .map(ToString::to_string)
                }),
            port: struct_field(struct_text, "sin6_port")
                .and_then(unwrap_call)
                .and_then(|p| p.parse::<u16>().ok()),
            unix_path: None,
        }),
        "AF_UNIX" => Some(SockAddr {
            family: SockFamily::Unix,
            ip: None,
            port: None,
            unix_path: struct_field(struct_text, "sun_path")
                .map(|p| p.trim_matches('"').to_string()),
        }),
        _ => Some(SockAddr {
            family: SockFamily::Other,
            ip: None,
            port: None,
            unix_path: None,
        }),
    }
}

/// True for loopback addresses.
#[must_use]
pub fn is_loopback(ip: &str) -> bool {
    ip == "::1" || ip.starts_with("127.")
}

/// True for addresses that are not routable on the public internet.
///
/// Includes loopback, RFC1918, link-local, carrier-grade NAT, and IPv6 unique-local. Used to keep
/// runner-internal traffic (metadata services, local resolvers) out of network findings.
#[must_use]
pub fn is_private(ip: &str) -> bool {
    if is_loopback(ip) {
        return true;
    }
    if ip.starts_with("10.") || ip.starts_with("192.168.") || ip.starts_with("169.254.") {
        return true;
    }
    if let Some(rest) = ip.strip_prefix("172.") {
        if let Some(octet) = rest.split('.').next().and_then(|o| o.parse::<u8>().ok()) {
            if (16..=31).contains(&octet) {
                return true;
            }
        }
    }
    // Carrier-grade NAT 100.64.0.0/10.
    if let Some(rest) = ip.strip_prefix("100.") {
        if let Some(octet) = rest.split('.').next().and_then(|o| o.parse::<u8>().ok()) {
            if (64..=127).contains(&octet) {
                return true;
            }
        }
    }
    let lower = ip.to_ascii_lowercase();
    lower.starts_with("fe80:") || lower.starts_with("fc") || lower.starts_with("fd")
}

/// A decoded DNS question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    /// Fully-qualified name from the question section.
    pub qname: String,
    /// Record type, when the payload extended far enough to include it.
    pub qtype: Option<u16>,
}

/// Extracts the first question from a DNS query payload.
///
/// Returns `None` on anything unexpected — a compression pointer in the question section, a payload
/// cut mid-label, or a label with bytes that cannot appear in a hostname. Rules.md §5: a guessed
/// hostname is fabricated evidence, so a partial decode yields nothing at all.
#[must_use]
pub fn parse_dns_question(payload: &[u8]) -> Option<DnsQuestion> {
    // 12-byte header + at least one length byte and the root label.
    if payload.len() < 13 {
        return None;
    }
    let qdcount = u16::from_be_bytes([*payload.get(4)?, *payload.get(5)?]);
    if qdcount < 1 {
        return None;
    }
    let mut labels: Vec<String> = Vec::new();
    let mut offset = 12usize;
    for _ in 0..64 {
        let len = usize::from(*payload.get(offset)?);
        if len == 0 {
            offset += 1;
            break;
        }
        // Top two bits set marks a compression pointer, which cannot legally appear here.
        if len & 0xc0 != 0 {
            return None;
        }
        let start = offset + 1;
        let end = start + len;
        let label_bytes = payload.get(start..end)?;
        if !label_bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_' || *b == b'*')
        {
            return None;
        }
        labels.push(String::from_utf8_lossy(label_bytes).into_owned());
        offset = end;
    }
    if labels.is_empty() {
        return None;
    }
    let qtype = payload
        .get(offset..offset + 2)
        .map(|b| u16::from_be_bytes([b[0], b[1]]));
    Some(DnsQuestion {
        qname: labels.join("."),
        qtype,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_escape_sequences() {
        assert_eq!(decode_escaped("abc"), b"abc");
        assert_eq!(decode_escaped(r"a\nb"), b"a\nb");
        assert_eq!(decode_escaped(r"a\tb"), b"a\tb");
        assert_eq!(decode_escaped(r"\\"), b"\\");
        assert_eq!(decode_escaped(r#"\""#), b"\"");
        // Octal, the form strace uses for arbitrary bytes.
        assert_eq!(decode_escaped(r"\001\002"), vec![1, 2]);
        assert_eq!(decode_escaped(r"\0"), vec![0]);
        // Hex, used under -x.
        assert_eq!(decode_escaped(r"\x41\x42"), b"AB");
        // A lone backslash is preserved rather than swallowed.
        assert_eq!(decode_escaped(r"a\"), b"a\\");
    }

    #[test]
    fn reads_quoted_strings_and_detects_truncation() {
        let q = read_quoted(r#""hello", 42"#, 0).expect("quoted");
        assert_eq!(q.bytes, b"hello");
        assert!(!q.truncated);
        assert_eq!(q.end, 7);

        let t = read_quoted(r#""hello"..., 42"#, 0).expect("quoted");
        assert!(t.truncated, "trailing ... marks a cut buffer");

        // An escaped quote must not terminate the string.
        let e = read_quoted(r#""a\"b""#, 0).expect("quoted");
        assert_eq!(e.bytes, b"a\"b");

        // Unterminated means strace's own line was cut; must not be half-decoded.
        assert!(read_quoted(r#""unterminated"#, 0).is_none());
    }

    #[test]
    fn splits_args_respecting_quotes_and_nesting() {
        let args = split_args(r#"AT_FDCWD, "/a,b/c", O_RDONLY|O_CLOEXEC"#);
        assert_eq!(
            args.len(),
            3,
            "comma inside quotes must not split: {args:?}"
        );
        assert_eq!(args[1], r#""/a,b/c""#);

        let nested = split_args("3, {sa_family=AF_INET, sin_port=htons(53)}, 16");
        assert_eq!(nested.len(), 3, "braces must nest: {nested:?}");
        assert_eq!(nested[2], "16");

        let argv_parts = split_args(r#"["sh", "-c", "a, b"]"#);
        assert_eq!(
            argv_parts.len(),
            1,
            "whole array is one arg: {argv_parts:?}"
        );
    }

    #[test]
    fn extracts_fd_annotations() {
        assert_eq!(fd_annotation("3</tmp/x>"), Some("/tmp/x"));
        assert_eq!(
            fd_annotation("4<TCP:[1.2.3.4:80]>"),
            Some("TCP:[1.2.3.4:80]")
        );
        assert_eq!(fd_annotation("AT_FDCWD"), None);
        assert_eq!(fd_annotation("3"), None);
        assert_eq!(fd_number("3</tmp/x>"), Some(3));
        assert_eq!(fd_number("AT_FDCWD"), None);
    }

    #[test]
    fn parses_return_values() {
        // Under -yy the annotation is glued to the number, with no space to split on.
        let ok = parse_ret("= 3</tmp/x>");
        assert_eq!(ok.ok, Some(true));
        assert_eq!(ok.value, Some(3));
        assert_eq!(ok.annotation.as_deref(), Some("/tmp/x"));

        let socket = parse_ret("= 7<TCP:[10.1.0.4:50001->104.16.0.1:443]>");
        assert_eq!(socket.value, Some(7));
        assert_eq!(
            socket.annotation.as_deref(),
            Some("TCP:[10.1.0.4:50001->104.16.0.1:443]")
        );
        assert_eq!(socket.error, None, "an annotation is not an errno");

        let plain = parse_ret("= 0");
        assert_eq!(plain.ok, Some(true));
        assert_eq!(plain.value, Some(0));
        assert_eq!(plain.annotation, None);

        let enoent = parse_ret("= -1 ENOENT (No such file or directory)");
        assert_eq!(enoent.ok, Some(false));
        assert_eq!(enoent.value, Some(-1));
        assert_eq!(enoent.error.as_deref(), Some("ENOENT"));

        // A non-blocking connect in progress is a real connection attempt.
        let einprogress = parse_ret("= -1 EINPROGRESS (Operation now in progress)");
        assert_eq!(
            einprogress.ok,
            Some(true),
            "EINPROGRESS must not be scored as a failed connect"
        );

        let unknown = parse_ret("= ? <unavailable>");
        assert_eq!(unknown.ok, None);
        assert_eq!(unknown.value, None);

        assert_eq!(parse_ret("no equals sign"), RetInfo::default());
    }

    #[test]
    fn parses_ipv4_sockaddr() {
        let sa = parse_sockaddr(
            r#"{sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("104.16.0.1")}"#,
        )
        .expect("sockaddr");
        assert_eq!(sa.family, SockFamily::Inet);
        assert_eq!(sa.ip.as_deref(), Some("104.16.0.1"));
        assert_eq!(sa.port, Some(443));
    }

    #[test]
    fn parses_ipv6_and_unix_sockaddr() {
        let v6 = parse_sockaddr(
            r#"{sa_family=AF_INET6, sin6_port=htons(80), inet_pton(AF_INET6, "2606:4700::1", &sin6_addr)}"#,
        )
        .expect("sockaddr");
        assert_eq!(v6.family, SockFamily::Inet6);
        assert_eq!(v6.ip.as_deref(), Some("2606:4700::1"));
        assert_eq!(v6.port, Some(80));

        let unix = parse_sockaddr(r#"{sa_family=AF_UNIX, sun_path="/var/run/nscd/socket"}"#)
            .expect("sockaddr");
        assert_eq!(unix.family, SockFamily::Unix);
        assert_eq!(unix.unix_path.as_deref(), Some("/var/run/nscd/socket"));
    }

    #[test]
    fn classifies_private_and_loopback_addresses() {
        assert!(is_loopback("127.0.0.53"));
        assert!(is_loopback("::1"));
        assert!(!is_loopback("8.8.8.8"));

        for ip in [
            "10.1.0.4",
            "192.168.1.1",
            "172.16.0.1",
            "172.31.255.255",
            "169.254.169.254",
            "100.64.0.1",
            "fd00::1",
            "fe80::1",
        ] {
            assert!(is_private(ip), "{ip} must be classified private");
        }
        for ip in [
            "8.8.8.8",
            "104.16.0.1",
            "172.15.0.1",
            "172.32.0.1",
            "100.63.0.1",
            "2606:4700::1",
        ] {
            assert!(!is_private(ip), "{ip} must be classified public");
        }
    }

    /// Builds a minimal DNS query packet for `name`.
    fn dns_packet(name: &str, qtype: u16) -> Vec<u8> {
        let mut p = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            p.push(u8::try_from(label.len()).unwrap_or(0));
            p.extend_from_slice(label.as_bytes());
        }
        p.push(0);
        p.extend_from_slice(&qtype.to_be_bytes());
        p.extend_from_slice(&1u16.to_be_bytes());
        p
    }

    #[test]
    fn decodes_dns_questions() {
        let q = parse_dns_question(&dns_packet("registry.npmjs.org", 1)).expect("question");
        assert_eq!(q.qname, "registry.npmjs.org");
        assert_eq!(q.qtype, Some(1));
    }

    #[test]
    fn refuses_to_guess_a_truncated_dns_name() {
        // The single most important negative case: a payload cut mid-label must yield nothing, never
        // a shortened hostname that would appear in a report as fact.
        let full = dns_packet("registry.npmjs.org", 1);
        let cut = &full[..20];
        assert!(
            parse_dns_question(cut).is_none(),
            "a truncated payload must not produce a partial hostname"
        );

        // A compression pointer in the question section is malformed; bail rather than decode.
        let mut pointer = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        pointer.extend_from_slice(&[0xc0, 0x0c]);
        assert!(parse_dns_question(&pointer).is_none());

        // Non-hostname bytes in a label mean this is not a plain query.
        let mut binary = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        binary.extend_from_slice(&[3, 0x00, 0x01, 0x02, 0]);
        assert!(parse_dns_question(&binary).is_none());

        assert!(parse_dns_question(&[]).is_none());
        assert!(parse_dns_question(&[0; 12]).is_none());
    }
}
