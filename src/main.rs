// Imports and Dependencies
use crossterm::{
    cursor,
    event::{self, Event, KeyCode},
    style::{Color, ResetColor, SetForegroundColor},
    terminal::{
        disable_raw_mode, enable_raw_mode, Clear, ClearType, EnterAlternateScreen,
        LeaveAlternateScreen,
    },
    ExecutableCommand,
};

use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color as TuiColor, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Row as TuiRow, Table as TuiTable, Wrap},
    Terminal,
};
use terminal_size::{Height, Width};

use std::{
    fs::File,
    io::{self, BufRead, Read, Write},
    path::Path,
    process::{Command, Stdio},
    time::Duration,
};

use bip39;
use bitcoin::{
    bip32::{DerivationPath, Xpriv},
    secp256k1::{PublicKey, Secp256k1},
    Address, Network, PrivateKey,
};
use bs58;
use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use slip10::{derive_key_from_path, BIP32Path, Curve};
use sskr::{sskr_combine, sskr_generate, GroupSpec, Secret, Spec};
use tiny_keccak::Hasher;

use rand::{rngs::OsRng, Rng};

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize, Serializer};
use std::error::Error;
use zeroize::Zeroizing;

#[derive(Debug)]
struct Slip10ErrorWrapper(slip10::Error);

impl std::fmt::Display for Slip10ErrorWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl Error for Slip10ErrorWrapper {}

fn serialize_secret_string<S>(secret: &SecretString, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(secret.expose_secret())
}

fn expand_tilde(path: &str) -> String {
    if path == "~" || path.starts_with("~/") {
        if let Some(home) = dirs::home_dir() {
            if path == "~" {
                return home.to_string_lossy().to_string();
            }
            if let Some(rest) = path.strip_prefix("~/") {
                let mut expanded = home;
                expanded.push(rest);
                return expanded.to_string_lossy().to_string();
            }
        }
    }
    path.to_string()
}

fn read_age_recipient_from_file(path: &str) -> Result<String, String> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read recipient file '{}': {}", path, e))?;
    let mut recipients = Vec::new();
    for raw_line in contents.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('#') {
            let marker = "# public key:";
            if line.starts_with(marker) {
                let key = line[marker.len()..].trim();
                if key.starts_with("age1") {
                    recipients.push(key.to_string());
                }
            }
            continue;
        }
        if line.starts_with("AGE-SECRET-KEY-") {
            continue;
        }
        if line.starts_with("age1") {
            recipients.push(line.to_string());
        }
    }
    if recipients.is_empty() {
        return Err("No age recipient found in file".to_string());
    }
    if recipients.len() > 1 {
        return Err(
            "Multiple recipients found; provide a file with a single recipient".to_string(),
        );
    }
    Ok(recipients.remove(0))
}

use image::Luma;
use qrcode::QrCode;
use tempfile;
use viuer;

// Structs and Data Types
#[derive(Serialize, Deserialize)]
struct SeedBackup {
    language: String,
    #[serde(serialize_with = "serialize_secret_string")]
    seed_phrase: SecretString,
    #[serde(serialize_with = "serialize_secret_string")]
    passphrase: SecretString,
    sskr: SskrBackup,
    #[serde(serialize_with = "serialize_secret_string")]
    entropy: SecretString,
    #[serde(serialize_with = "serialize_secret_string")]
    bip39_seed: SecretString,
    #[serde(serialize_with = "serialize_secret_string")]
    bip32_root_key: SecretString,
    recovery_info: String,
}

#[derive(Serialize, Deserialize)]
struct SskrBackup {
    groups: Vec<Vec<Share>>,
}

#[derive(Serialize, Deserialize)]
struct Share {
    #[serde(serialize_with = "serialize_secret_string")]
    share_hex: SecretString,
    #[serde(serialize_with = "serialize_secret_string")]
    mnemonic: SecretString,
}

#[derive(Clone)]
struct ThemeColors {
    header: Color,
    highlighted: Color,
    final_output: Color,
    candidate_header: Color,
    position_label: Color,
    input_prompt: Color,
    random_message: Color,
    error: Color,
}

#[derive(Debug)]
struct AddressEntry {
    index: u32,
    address: String,
    pubkey: String,
    privkey: Option<SecretString>,
    derivation_path: String,
}

struct TerminalCleanup;

impl Drop for TerminalCleanup {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let mut stdout = io::stdout();
        let _ = stdout.execute(LeaveAlternateScreen);
        let _ = stdout.execute(cursor::Show);
    }
}

fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let _ = disable_raw_mode();
        let mut stdout = io::stdout();
        let _ = stdout.execute(LeaveAlternateScreen);
        let _ = stdout.execute(cursor::Show);
        eprintln!("Panic: {}", info);
    }));
}

// Theming & Color Conversion
fn get_catppuccin_mocha_theme() -> ThemeColors {
    ThemeColors {
        header: Color::Rgb {
            r: 198,
            g: 160,
            b: 246,
        },
        highlighted: Color::Rgb {
            r: 255,
            g: 140,
            b: 0,
        },
        final_output: Color::Rgb {
            r: 166,
            g: 218,
            b: 149,
        },
        candidate_header: Color::Rgb {
            r: 183,
            g: 189,
            b: 248,
        },
        position_label: Color::Rgb {
            r: 238,
            g: 212,
            b: 159,
        },
        input_prompt: Color::Rgb {
            r: 145,
            g: 215,
            b: 227,
        },
        random_message: Color::Rgb {
            r: 138,
            g: 173,
            b: 244,
        },
        error: Color::Rgb {
            r: 237,
            g: 135,
            b: 150,
        },
    }
}

fn convert_color(color: Color) -> TuiColor {
    match color {
        Color::Rgb { r, g, b } => TuiColor::Rgb(r, g, b),
        _ => TuiColor::Reset,
    }
}

// Bit Manipulation Helpers
fn bits_from_u16(num: u16, bits: usize) -> Vec<bool> {
    let mut bits_vec = Vec::with_capacity(bits);
    for i in (0..bits).rev() {
        bits_vec.push((num >> i) & 1 == 1);
    }
    bits_vec
}

fn bits_to_u16(bits: &[bool]) -> u16 {
    bits.iter()
        .fold(0, |acc, &bit| (acc << 1) | if bit { 1 } else { 0 })
}

fn bits_to_bytes(bits: &[bool]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for chunk in bits.chunks(8) {
        let mut byte = 0u8;
        for &bit in chunk {
            byte = (byte << 1) | if bit { 1 } else { 0 };
        }
        if chunk.len() < 8 {
            byte <<= 8 - chunk.len();
        }
        bytes.push(byte);
    }
    bytes
}

// Encryption, Decryption & Security Functions
fn encrypt_data(plaintext: &SecretString, recipient: &str) -> Result<Vec<u8>, String> {
    let recipient = recipient.trim();
    if recipient.is_empty() {
        return Err("Recipient cannot be empty".to_string());
    }
    let mut child = Command::new("age")
        .args(["-r", recipient])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                "Failed to spawn age: binary not found in PATH".to_string()
            } else {
                format!("Failed to spawn age: {}", e)
            }
        })?;

    {
        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| "Failed to open stdin for age".to_string())?;
        stdin
            .write_all(plaintext.expose_secret().as_bytes())
            .map_err(|e| format!("Failed to write to age stdin: {}", e))?;
    }

    let output = child
        .wait_with_output()
        .map_err(|e| format!("Failed to read age output: {}", e))?;
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        return Err(err.trim().to_string());
    }
    Ok(output.stdout)
}

fn decrypt_data(ciphertext: &[u8], identity_input: &str) -> Result<SecretString, String> {
    let identity_input = expand_tilde(identity_input.trim());
    if identity_input.is_empty() {
        return Err("Identity input cannot be empty".to_string());
    }
    let (identity_path, _temp_identity) = if Path::new(&identity_input).exists() {
        (identity_input, None)
    } else {
        let mut temp = tempfile::NamedTempFile::new()
            .map_err(|e| format!("Failed to create temp identity file: {}", e))?;
        temp.write_all(identity_input.as_bytes())
            .map_err(|e| format!("Failed to write identity: {}", e))?;
        if !identity_input.ends_with('\n') {
            temp.write_all(b"\n")
                .map_err(|e| format!("Failed to finalize identity: {}", e))?;
        }
        temp.as_file()
            .sync_all()
            .map_err(|e| format!("Failed to sync identity: {}", e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(temp.path())
                .map_err(|e| format!("Failed to stat identity file: {}", e))?
                .permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(temp.path(), perms)
                .map_err(|e| format!("Failed to set identity permissions: {}", e))?;
        }
        (temp.path().to_string_lossy().to_string(), Some(temp))
    };

    let mut child = Command::new("age")
        .args(["-d", "-i", &identity_path])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                "Failed to spawn age: binary not found in PATH".to_string()
            } else {
                format!("Failed to spawn age: {}", e)
            }
        })?;

    {
        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| "Failed to open stdin for age".to_string())?;
        stdin
            .write_all(ciphertext)
            .map_err(|e| format!("Failed to write to age stdin: {}", e))?;
    }

    let output = child
        .wait_with_output()
        .map_err(|e| format!("Failed to read age output: {}", e))?;
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        return Err(err.trim().to_string());
    }
    let decrypted = String::from_utf8(output.stdout)
        .map_err(|_| "Decrypted data is not valid UTF-8".to_string())?;
    Ok(SecretString::new(decrypted.into()))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn lock_sensitive_data(data: &mut [u8]) {
    use memsec::mlock;
    let locked = unsafe { mlock(data.as_mut_ptr(), data.len()) };
    if !locked {
        eprintln!("Warning: Failed to lock memory");
    }
}

#[cfg(target_os = "windows")]
fn lock_sensitive_data(data: &mut [u8]) {
    use std::ptr::null_mut;
    use winapi::shared::minwindef::LPVOID;
    use winapi::um::memoryapi::VirtualLock;
    let ret = unsafe { VirtualLock(data.as_mut_ptr() as LPVOID, data.len()) };
    if ret == 0 {
        eprintln!("Warning: Failed to lock memory using VirtualLock");
    }
}

// Blockchain Address Generation Functions
fn ethereum_address_from_pubkey(pubkey: &PublicKey) -> String {
    let uncompressed = pubkey.serialize_uncompressed();
    let pubkey_bytes = &uncompressed[1..];
    let mut keccak = tiny_keccak::Keccak::v256();
    let mut hash = [0u8; 32];
    keccak.update(pubkey_bytes);
    keccak.finalize(&mut hash);
    let address_bytes = &hash[12..];
    let address = hex::encode(address_bytes);
    to_checksum_address(&address)
}

fn to_checksum_address(address: &str) -> String {
    let address_lower = address.to_lowercase();
    let mut keccak = tiny_keccak::Keccak::v256();
    let mut hash = [0u8; 32];
    keccak.update(address_lower.as_bytes());
    keccak.finalize(&mut hash);
    let mut checksum_address = String::from("0x");
    for (i, ch) in address_lower.chars().enumerate() {
        let hash_byte = hash[i / 2];
        let nibble = if i % 2 == 0 {
            (hash_byte >> 4) & 0xF
        } else {
            hash_byte & 0xF
        };
        if nibble >= 8 {
            checksum_address.push(ch.to_ascii_uppercase());
        } else {
            checksum_address.push(ch);
        }
    }
    checksum_address
}

fn xrp_address_from_pubkey(pubkey: &PublicKey) -> String {
    let pubkey_bytes = pubkey.serialize();
    let sha256_hash = Sha256::digest(&pubkey_bytes);
    use bitcoin::hashes::{ripemd160, Hash};
    let ripemd_hash = ripemd160::Hash::hash(&sha256_hash);
    let mut payload = Vec::with_capacity(21);
    payload.push(0x00);
    payload.extend_from_slice(&ripemd_hash[..]);
    let double_hash = Sha256::digest(&Sha256::digest(&payload));
    let checksum = &double_hash[0..4];
    payload.extend_from_slice(checksum);
    let alphabet =
        bs58::Alphabet::new(b"rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz").unwrap();
    bs58::encode(payload).with_alphabet(&alphabet).into_string()
}

// Mnemonic & SSKR Helpers
fn share_to_mnemonic(share: &[u8], language: bip39::Language) -> String {
    let share_len = share.len() as u16;
    let mut payload = Vec::with_capacity(2 + share.len() + 4);
    payload.extend_from_slice(&share_len.to_be_bytes());
    payload.extend_from_slice(share);
    let checksum = Sha256::digest(&payload);
    payload.extend_from_slice(&checksum[..4]);

    let mut bit_vec = Vec::with_capacity(payload.len() * 8);
    for &byte in &payload {
        for i in (0..8).rev() {
            bit_vec.push((byte >> i) & 1 == 1);
        }
    }
    while bit_vec.len() % 11 != 0 {
        bit_vec.push(false);
    }
    let wordlist = language.word_list();
    let mut mnemonic_words = Vec::new();
    for chunk in bit_vec.chunks(11) {
        let index = bits_to_u16(chunk) as usize;
        mnemonic_words.push(wordlist[index]);
    }
    mnemonic_words.join(" ")
}

fn mnemonic_to_share(mnemonic: &str, language: bip39::Language) -> Option<Vec<u8>> {
    let words: Vec<&str> = mnemonic.split_whitespace().collect();
    let wordlist = language.word_list();
    let mut bits = Vec::new();
    for word in words {
        let index = wordlist.iter().position(|&w| w == word)?;
        let index_bits = bits_from_u16(index as u16, 11);
        bits.extend(index_bits);
    }
    if bits.len() < 16 {
        return None;
    }
    let share_len_bits = &bits[0..16];
    let share_len = bits_to_u16(share_len_bits) as usize;
    let required_bytes = 2 + share_len + 4;
    let required_bits = required_bytes * 8;
    if bits.len() < required_bits {
        return None;
    }
    let payload = bits_to_bytes(&bits[..required_bits]);
    let (len_bytes, rest) = payload.split_at(2);
    let expected_len = u16::from_be_bytes([len_bytes[0], len_bytes[1]]) as usize;
    if expected_len != share_len {
        return None;
    }
    let (share_bytes, checksum_bytes) = rest.split_at(share_len);
    let mut check_payload = Vec::with_capacity(2 + share_len);
    check_payload.extend_from_slice(len_bytes);
    check_payload.extend_from_slice(share_bytes);
    let checksum = Sha256::digest(&check_payload);
    if checksum_bytes != &checksum[..4] {
        return None;
    }
    Some(share_bytes.to_vec())
}

fn validate_mnemonic(mnemonic: &str, language: bip39::Language) -> Result<(), String> {
    let wordlist = language.word_list();
    for (i, word) in mnemonic.split_whitespace().enumerate() {
        if !wordlist.contains(&word) {
            return Err(format!(
                "Mnemonic contains an unknown word at position {}: {}",
                i + 1,
                word
            ));
        }
    }
    Ok(())
}

fn language_from_choice(choice: u8) -> bip39::Language {
    match choice {
        1 => bip39::Language::English,
        2 => bip39::Language::SimplifiedChinese,
        3 => bip39::Language::TraditionalChinese,
        4 => bip39::Language::Japanese,
        5 => bip39::Language::Korean,
        6 => bip39::Language::Spanish,
        7 => bip39::Language::French,
        8 => bip39::Language::Italian,
        9 => bip39::Language::Czech,
        10 => bip39::Language::Portuguese,
        _ => bip39::Language::English,
    }
}

// User Input & UI Functions
fn prompt_user_input(prompt: &str, color: Color) -> io::Result<String> {
    let mut stdout = io::stdout();
    stdout.execute(SetForegroundColor(color))?;
    print!("{}", prompt);
    stdout.execute(ResetColor)?;
    io::stdout().flush()?;
    let stdin = io::stdin();
    let mut handle = stdin.lock();
    let mut buffer = Vec::new();
    handle.read_until(b'\n', &mut buffer)?;
    Ok(String::from_utf8_lossy(&buffer).trim().to_string())
}

fn prompt_single_key(prompt: &str, color: Color) -> io::Result<char> {
    let mut stdout = io::stdout();
    enable_raw_mode()?;
    stdout.execute(Clear(ClearType::All))?;
    stdout.execute(cursor::MoveTo(0, 0))?;
    stdout.execute(SetForegroundColor(color))?;
    let lines: Vec<&str> = prompt.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        stdout.execute(Clear(ClearType::CurrentLine))?;
        stdout.execute(cursor::MoveToColumn(0))?;
        if i == lines.len() - 1 {
            print!("{}", line);
        } else {
            println!("{}", line);
        }
    }
    stdout.execute(ResetColor)?;
    stdout.flush()?;
    let key = loop {
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key_event) = event::read()? {
                match key_event.code {
                    KeyCode::Char(c) => break c,
                    _ => break '?',
                }
            }
        }
    };
    disable_raw_mode()?;
    Ok(key)
}

fn hidden_input(prompt: &str, color: Color) -> io::Result<SecretString> {
    use crossterm::{
        cursor,
        event::{self, KeyCode},
        style::{ResetColor, SetForegroundColor},
        terminal::{disable_raw_mode, enable_raw_mode},
    };
    let mut stdout = io::stdout();
    stdout.execute(SetForegroundColor(color))?;
    print!("{}", prompt);
    stdout.execute(ResetColor)?;
    stdout.flush()?;

    enable_raw_mode()?;
    let mut password = String::new();
    loop {
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key_event) = event::read()? {
                match key_event.code {
                    KeyCode::Enter => break,
                    KeyCode::Char(c) => {
                        password.push(c);
                        print!("*");
                        stdout.flush()?;
                    }
                    KeyCode::Backspace => {
                        if !password.is_empty() {
                            password.pop();
                            stdout.execute(cursor::MoveLeft(1))?;
                            print!(" ");
                            stdout.execute(cursor::MoveLeft(1))?;
                            stdout.flush()?;
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    disable_raw_mode()?;
    println!();
    Ok(SecretString::new(password.into()))
}

fn run_backup_text_ui(
    backup: SeedBackup,
    theme_colors: ThemeColors,
    title: &str,
    show_save: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    enable_raw_mode()?;
    let _cleanup = TerminalCleanup;
    let mut stdout = io::stdout();
    stdout.execute(EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let mut mask_state = true;
    loop {
        terminal.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints([Constraint::Percentage(90), Constraint::Percentage(10)].as_ref())
                .split(f.area());
            let styled_text = format_backup_styled(&backup, mask_state, theme_colors.final_output);
            let paragraph = Paragraph::new(styled_text)
                .block(
                    Block::default()
                        .borders(Borders::NONE)
                        .title(title),
                )
                .wrap(Wrap { trim: false });
            f.render_widget(paragraph, chunks[0]);
            let note_text = if show_save {
                "Press [Tab] to toggle sensitive value visibility, [s] to save JSON file, [q] to exit."
            } else {
                "Press [Tab] to toggle sensitive value visibility, [q] to exit."
            };
            let note = Paragraph::new(note_text)
                .style(Style::default().fg(TuiColor::White));
            f.render_widget(note, chunks[1]);
        })?;
        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(key_event) = event::read()? {
                match key_event.code {
                    KeyCode::Tab => mask_state = !mask_state,
                    KeyCode::Char('q') => break,
                    KeyCode::Char('s') if show_save => {
                        disable_raw_mode()?;
                        terminal.backend_mut().execute(LeaveAlternateScreen)?;
                        terminal.show_cursor()?;
                        let mut stdout = io::stdout();
                        stdout.execute(Clear(ClearType::All))?;
                        stdout.execute(cursor::MoveTo(0, 0))?;
                        let recipient = loop {
                            let input = prompt_user_input(
                                "\nEnter the age recipient file path (e.g., /path/to/pq-key.txt): ",
                                theme_colors.input_prompt,
                            )?;
                            let trimmed = input.trim();
                            if trimmed.is_empty() {
                                stdout.execute(SetForegroundColor(theme_colors.error))?;
                                println!("Recipient file path cannot be empty. Please try again.");
                                stdout.execute(ResetColor)?;
                                continue;
                            }
                            let expanded = expand_tilde(trimmed);
                            match read_age_recipient_from_file(&expanded) {
                                Ok(recipient) => break recipient,
                                Err(e) => {
                                    stdout.execute(SetForegroundColor(theme_colors.error))?;
                                    println!("{}", e);
                                    stdout.execute(ResetColor)?;
                                    continue;
                                }
                            }
                        };
                        let file_path = loop {
                            let file_path = prompt_user_input(
                                "\nEnter the full path to save the encrypted JSON file (e.g., /path/to/seed_backup.json.age): ",
                                theme_colors.input_prompt,
                            )?;
                            let file_path = expand_tilde(&file_path);
                            let path = Path::new(&file_path);
                            if let Ok(metadata) = std::fs::symlink_metadata(path) {
                                if metadata.file_type().is_symlink() {
                                    stdout.execute(SetForegroundColor(theme_colors.error))?;
                                    println!(
                                        "Refusing to write to a symlink. Choose a different path."
                                    );
                                    stdout.execute(ResetColor)?;
                                    continue;
                                }
                                if metadata.is_file() {
                                    stdout.execute(SetForegroundColor(theme_colors.error))?;
                                    println!("Refusing to overwrite an existing file. Choose a new path.");
                                    stdout.execute(ResetColor)?;
                                    continue;
                                }
                                if metadata.is_dir() {
                                    stdout.execute(SetForegroundColor(theme_colors.error))?;
                                    println!(
                                        "Path points to a directory. Choose a file path instead."
                                    );
                                    stdout.execute(ResetColor)?;
                                    continue;
                                }
                            }
                            let parent = path.parent().unwrap_or_else(|| Path::new("."));
                            if !parent.is_dir() {
                                stdout.execute(SetForegroundColor(theme_colors.error))?;
                                println!("Parent directory does not exist. Please try again.");
                                stdout.execute(ResetColor)?;
                                continue;
                            }
                            if let Ok(parent_meta) = std::fs::symlink_metadata(parent) {
                                if parent_meta.file_type().is_symlink() {
                                    stdout.execute(SetForegroundColor(theme_colors.error))?;
                                    println!("Parent directory is a symlink. Choose a different location.");
                                    stdout.execute(ResetColor)?;
                                    continue;
                                }
                            }
                            break file_path;
                        };
                        let json_data = serde_json::to_string_pretty(&backup)?;
                        let encrypted_json =
                            match encrypt_data(&SecretString::new(json_data.into()), &recipient) {
                                Ok(data) => data,
                                Err(e) => {
                                    stdout.execute(SetForegroundColor(theme_colors.error))?;
                                    println!("Encryption failed: {}", e);
                                    stdout.execute(ResetColor)?;
                                    println!("Press any key to exit.");
                                    enable_raw_mode()?;
                                    let _ = event::read()?;
                                    disable_raw_mode()?;
                                    return Ok(());
                                }
                            };

                        let parent_dir = Path::new(&file_path)
                            .parent()
                            .unwrap_or_else(|| Path::new("."));
                        let mut temp_file = tempfile::NamedTempFile::new_in(parent_dir)?;
                        temp_file.write_all(&encrypted_json)?;
                        temp_file.as_file().sync_all()?;

                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            let mut perms = std::fs::metadata(temp_file.path())?.permissions();
                            perms.set_mode(0o600);
                            std::fs::set_permissions(temp_file.path(), perms)?;
                        }

                        temp_file.persist(&file_path)?;

                        stdout.execute(Clear(ClearType::All))?;
                        stdout.execute(cursor::MoveTo(0, 0))?;
                        print!("Encrypted JSON file saved as ");
                        stdout.execute(SetForegroundColor(theme_colors.final_output))?;
                        print!("'{}'", file_path);
                        stdout.execute(ResetColor)?;
                        println!();
                        println!("Press any key to exit.");
                        enable_raw_mode()?;
                        let _ = event::read()?;
                        disable_raw_mode()?;
                        return Ok(());
                    }
                    _ => {}
                }
            }
        }
    }
    disable_raw_mode()?;
    terminal.backend_mut().execute(LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

fn format_backup_styled(
    backup: &SeedBackup,
    mask_state: bool,
    output_color: Color,
) -> Vec<Line<'static>> {
    let out_color = convert_color(output_color);
    let mask = |s: &str| {
        if !mask_state {
            return s.to_string();
        }
        if s.is_empty() {
            return String::new();
        }
        "*".repeat(32)
    };

    let mut lines = Vec::new();
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::raw("Seed Phrase: "),
        Span::styled(
            mask(backup.seed_phrase.expose_secret()),
            Style::default().fg(out_color),
        ),
    ]));
    lines.push(Line::from(vec![
        Span::raw("Passphrase: "),
        Span::styled(
            mask(backup.passphrase.expose_secret()),
            Style::default().fg(out_color),
        ),
    ]));
    lines.push(Line::from(""));
    if !backup.sskr.groups.is_empty() {
        lines.push(Line::from("SSKR Backup:"));
        for (group_index, group_shares) in backup.sskr.groups.iter().enumerate() {
            lines.push(Line::from(format!("Group {} Shares:", group_index + 1)));
            for (share_index, share) in group_shares.iter().enumerate() {
                lines.push(Line::from(vec![
                    Span::raw(format!("  Share {}: Hex:      ", share_index + 1)),
                    Span::styled(
                        mask(share.share_hex.expose_secret()),
                        Style::default().fg(out_color),
                    ),
                ]));
                lines.push(Line::from(vec![
                    Span::raw("           Mnemonic: "),
                    Span::styled(
                        mask(share.mnemonic.expose_secret()),
                        Style::default().fg(out_color),
                    ),
                ]));
            }
        }
    }
    if !backup.recovery_info.is_empty() && !backup.sskr.groups.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(backup.recovery_info.clone()));
        lines.push(Line::from(""));
    }
    lines.push(Line::from(vec![
        Span::raw("Entropy: "),
        Span::styled(
            mask(backup.entropy.expose_secret()),
            Style::default().fg(out_color),
        ),
    ]));
    lines.push(Line::from(vec![
        Span::raw("BIP-39 Seed: "),
        Span::styled(
            mask(backup.bip39_seed.expose_secret()),
            Style::default().fg(out_color),
        ),
    ]));
    lines.push(Line::from(vec![
        Span::raw("BIP-32 Root Key (xprv): "),
        Span::styled(
            mask(backup.bip32_root_key.expose_secret()),
            Style::default().fg(out_color),
        ),
    ]));
    lines
}

fn run_address_table_ui(
    address_entries: &mut Vec<AddressEntry>,
    addr_type: u8,
    theme_colors: &ThemeColors,
    master_xprv: &Xpriv,
    seed: &[u8],
) -> Result<bool, Box<dyn std::error::Error>> {
    enable_raw_mode()?;
    let _cleanup = TerminalCleanup;
    let mut stdout = io::stdout();
    stdout.execute(EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let mut mask_state = true;
    let mut selected_row: usize = 0;

    loop {
        terminal.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints([Constraint::Percentage(90), Constraint::Percentage(10)].as_ref())
                .split(f.area());
            let rows = address_entries.iter().enumerate().map(|(i, entry)| {
                let priv_display = if let Some(privkey) = &entry.privkey {
                    if mask_state { "*".repeat(privkey.expose_secret().len()) } else { privkey.expose_secret().to_string() }
                } else {
                    "N/A".to_string()
                };
                let row = TuiRow::new(vec![
                    entry.index.to_string(),
                    entry.address.clone(),
                    entry.pubkey.clone(),
                    priv_display,
                ]);
                if i == selected_row {
                    row.style(Style::default().bg(convert_color(theme_colors.highlighted)))
                } else {
                    row
                }
            });
            let table = TuiTable::new(rows, vec![
                    Constraint::Percentage(5),
                    Constraint::Percentage(25),
                    Constraint::Percentage(35),
                    Constraint::Percentage(35),
                ])
                .header(TuiRow::new(vec!["Index", "Address", "Public Key", "Private Key"])
                    .bottom_margin(1))
                .block(Block::default()
                    .borders(Borders::NONE)
                    .title(match addr_type {
                        1 => "Derived Bitcoin Addresses",
                        2 => "Derived Ethereum Addresses",
                        3 => "Derived XRP Addresses",
                        4 => "Derived Solana Addresses",
                        _ => "Derived Addresses",
                    }));
            f.render_widget(table, chunks[0]);
            let note = Paragraph::new("Use arrow keys to navigate, [Tab] to toggle private key visibility, [p] to derive private key, [Enter] to show address QR, [k] to show private-key QR, [r] to return, [q] to exit.")
                .style(Style::default().fg(TuiColor::White));
            f.render_widget(note, chunks[1]);
        })?;
        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(key_event) = event::read()? {
                match key_event.code {
                    KeyCode::Tab => mask_state = !mask_state,
                    KeyCode::Char('r') => {
                        disable_raw_mode()?;
                        terminal.backend_mut().execute(LeaveAlternateScreen)?;
                        terminal.show_cursor()?;
                        return Ok(true);
                    }
                    KeyCode::Char('q') => {
                        disable_raw_mode()?;
                        terminal.backend_mut().execute(LeaveAlternateScreen)?;
                        terminal.show_cursor()?;
                        return Ok(false);
                    }
                    KeyCode::Up => {
                        if selected_row > 0 {
                            selected_row -= 1;
                        }
                    }
                    KeyCode::Down => {
                        if selected_row < address_entries.len() - 1 {
                            selected_row += 1;
                        }
                    }
                    KeyCode::Char('p') => {
                        let entry = &mut address_entries[selected_row];
                        if entry.privkey.is_none() {
                            let path_str = entry.derivation_path.as_str();
                            if addr_type == 4 {
                                let path =
                                    path_str.parse::<BIP32Path>().map_err(Slip10ErrorWrapper)?;
                                let derived = derive_key_from_path(seed, Curve::Ed25519, &path)
                                    .map_err(Slip10ErrorWrapper)?;
                                let signing_key = SigningKey::from_bytes(&derived.key);
                                let privkey_hex = hex::encode(signing_key.to_bytes());
                                entry.privkey = Some(SecretString::new(privkey_hex.into()));
                            } else {
                                let secp = Secp256k1::new();
                                let path = path_str.parse::<DerivationPath>()?;
                                let child_xprv = master_xprv.derive_priv(&secp, &path)?;
                                if addr_type == 1 {
                                    let wif =
                                        PrivateKey::new(child_xprv.private_key, Network::Bitcoin)
                                            .to_wif();
                                    entry.privkey = Some(SecretString::new(wif.into()));
                                } else {
                                    let mut privkey_hex =
                                        hex::encode(child_xprv.private_key.secret_bytes());
                                    if addr_type == 2 {
                                        privkey_hex = format!("0x{}", privkey_hex);
                                    }
                                    entry.privkey = Some(SecretString::new(privkey_hex.into()));
                                }
                            }
                        }
                    }
                    KeyCode::Char('k') => {
                        if let Some(privkey) = &address_entries[selected_row].privkey {
                            show_qr_popup(privkey.expose_secret())?;
                            terminal.draw(|_f| {})?;
                        }
                    }
                    KeyCode::Enter => {
                        let entry = &address_entries[selected_row];
                        show_qr_popup(&entry.address)?;
                        terminal.draw(|_f| {})?;
                    }
                    _ => {}
                }
            }
        }
    }
}

fn show_qr_popup(data: &str) -> Result<(), Box<dyn std::error::Error>> {
    let code = QrCode::new(data.as_bytes())?;
    let image = code.render::<Luma<u8>>().min_dimensions(38, 38).build();

    let dynamic_image = image::DynamicImage::ImageLuma8(image);

    let (term_width, term_height) =
        if let Some((Width(w), Height(h))) = terminal_size::terminal_size() {
            (w, h)
        } else {
            (80, 24)
        };
    let center_x = (term_width.saturating_sub(38)) / 2;
    let center_y = (term_height.saturating_sub(38)) / 2;

    let config = viuer::Config {
        width: Some(38),
        height: Some(38),
        x: center_x as u16,
        y: center_y as i16,
        transparent: true,
        ..Default::default()
    };

    let mut stdout = io::stdout();
    stdout.execute(Clear(ClearType::All))?;
    stdout.execute(cursor::MoveTo(0, 0))?;
    viuer::print(&dynamic_image, &config)?;

    loop {
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key_event) = event::read()? {
                if key_event.code == KeyCode::Esc {
                    break;
                }
            }
        }
    }

    stdout.execute(Clear(ClearType::All))?;
    stdout.execute(cursor::MoveTo(0, 0))?;

    Ok(())
}

fn get_manual_seed(theme_colors: &ThemeColors) -> io::Result<(bip39::Mnemonic, Vec<u8>)> {
    let mut stdout = io::stdout();
    println!("\nSelect language of the seed phrase:");
    println!("  1: English");
    println!("  2: Simplified Chinese");
    println!("  3: Traditional Chinese");
    println!("  4: Japanese");
    println!("  5: Korean");
    println!("  6: Spanish");
    println!("  7: French");
    println!("  8: Italian");
    println!("  9: Czech");
    println!(" 10: Portuguese");
    let language_choice = loop {
        let input = prompt_user_input("Enter your selection (1-10): ", theme_colors.input_prompt)?;
        match input.parse::<u8>() {
            Ok(num) if num >= 1 && num <= 10 => break num,
            _ => {
                stdout.execute(SetForegroundColor(theme_colors.error))?;
                println!("Invalid selection. Please enter a number between 1 and 10.");
                stdout.execute(ResetColor)?;
            }
        }
    };
    let language = language_from_choice(language_choice);

    loop {
        let input_value = Zeroizing::new(prompt_user_input(
            "\nEnter your entropy (hex encoded) or seed phrase (BIP-39 mnemonic): ",
            theme_colors.input_prompt,
        )?);
        let trimmed_input = input_value.trim();
        let passphrase_input = hidden_input(
            "\nEnter your optional passphrase (leave blank for none): ",
            theme_colors.input_prompt,
        )?;

        if trimmed_input.contains(' ') {
            match validate_mnemonic(trimmed_input, language) {
                Ok(()) => {
                    let mnemonic = bip39::Mnemonic::parse_in_normalized(language, trimmed_input)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
                    let mut seed = mnemonic.to_seed(passphrase_input.expose_secret()).to_vec();
                    lock_sensitive_data(&mut seed);
                    return Ok((mnemonic, seed));
                }
                Err(e) => {
                    let mut stdout = io::stdout();
                    stdout.execute(SetForegroundColor(theme_colors.error))?;
                    println!("{}", e);
                    stdout.execute(ResetColor)?;
                    continue;
                }
            }
        } else {
            match hex::decode(trimmed_input) {
                Ok(entropy_bytes) => {
                    let mut entropy_bytes = Zeroizing::new(entropy_bytes);
                    if ![16, 20, 24, 28, 32].contains(&entropy_bytes.len()) {
                        let mut stdout = io::stdout();
                        stdout.execute(SetForegroundColor(theme_colors.error))?;
                        println!("Invalid entropy length. Expected 128, 160, 192, 224, or 256 bits. Please try again.");
                        stdout.execute(ResetColor)?;
                        continue;
                    }
                    lock_sensitive_data(entropy_bytes.as_mut_slice());
                    match bip39::Mnemonic::from_entropy_in(language, entropy_bytes.as_slice()) {
                        Ok(mnemonic) => {
                            let mut seed =
                                mnemonic.to_seed(passphrase_input.expose_secret()).to_vec();
                            lock_sensitive_data(&mut seed);
                            return Ok((mnemonic, seed));
                        }
                        Err(e) => {
                            let mut stdout = io::stdout();
                            stdout.execute(SetForegroundColor(theme_colors.error))?;
                            println!(
                                "Failed to create mnemonic from entropy: {}. Please try again.",
                                e
                            );
                            stdout.execute(ResetColor)?;
                            continue;
                        }
                    }
                }
                Err(e) => {
                    let mut stdout = io::stdout();
                    stdout.execute(SetForegroundColor(theme_colors.error))?;
                    println!("Hex decode error: {}. Please try again.", e);
                    stdout.execute(ResetColor)?;
                    continue;
                }
            }
        }
    }
}

// Main Function
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut stdout = io::stdout();
    install_panic_hook();
    let theme_colors = get_catppuccin_mocha_theme();

    loop {
        print!("\x1B[3J");
        stdout.execute(Clear(ClearType::All))?;
        stdout.execute(cursor::MoveTo(0, 0))?;
        stdout.flush()?;

        stdout.execute(SetForegroundColor(theme_colors.header))?;
        println!("BIP-39 Tool");
        stdout.execute(ResetColor)?;
        println!("
        \x1b[37mThis tool offers several functionalities for managing your cryptocurrency seed:
        1: Generate a new seed.
        2: Recover an existing seed from SSKR shares.
        3: Derive wallet addresses from a provided BIP-32 Extended Private Key (xprv).
        4: Decrypt and read a saved encrypted JSON backup.\x1b[0m

        \x1b[1;37mSeed Phrase Language Support:\x1b[0m
        \x1b[37m- This tool supports BIP-39 seed phrases in multiple languages, including English, French, Spanish, Italian, Japanese, Chinese (Simplified and Traditional), and more.
        - When selecting a language, the wordlist for seed phrase generation and validation will be based on that language.
        - The language setting does not translate words between different languages; it simply ensures that generated seed words conform to the selected wordlist.
        - If recovering an existing seed, ensure you select the correct language to match the original wordlist.\x1b[0m

        \x1b[1;37mSSKR (Sharded Secret Key Recovery):\x1b[0m
        \x1b[37m- SSKR splits your secret (seed) into multiple shares for enhanced security.
        - These shares can be distributed to different locations or entrusted to different parties.
        - To recover your seed, simply enter the required SSKR shares when prompted.
        - The program validates each share and securely reconstructs your original seed.\x1b[0m

        \x1b[1;37mStandard & Fully Hardened Address Generation:\x1b[0m
        \x1b[37m  - The tool supports generating addresses with both **standard** and **fully hardened** derivation paths.\x1b[0m

        \x1b[37m    Standard Derivation (m/Purpose'/CoinType'/Account'/ChainIndex):\x1b[0m
        \x1b[37m        - The first three levels (`Purpose'`, `CoinType'`, `Account'`) are \x1b[4;32mhardened\x1b[24m\x1b[37m, but the final `ChainIndex` is \x1b[4;32mnon-hardened\x1b[24m\x1b[37m.
         \x1b[37m       - Allows \x1b[4;32mpublic key derivation\x1b[24m\x1b[37m, meaning an extended public key (xpub) \x1b[4;32mcan\x1b[24m\x1b[37m be used to generate child public addresses.\x1b[0m\x1b[37m
        \x1b[37m        - This facilitates features like \x1b[4;32mwatch-only wallets\x1b[24m\x1b[37m, where public keys can be monitored without needing the private key.\x1b[0m
        \x1b[37m        - While convenient, they are slightly less secure since an exposed xpub could reveal multiple addresses, increasing risk if the xpub is leaked.\x1b[0m

        \x1b[37m    Fully Hardened Derivation (m/Purpose'/CoinType'/Account'/ChainIndex'\x1b[1;31;5m[!]\x1b[0m\x1b[37m):\x1b[0m
        \x1b[37m        - \x1b[4;32mEvery level is hardened\x1b[24m\x1b[37m, including the final `ChainIndex'`, preventing public key derivation beyond this point.\x1b[0m
        \x1b[37m        - Even if an extended public key (xpub) is exposed, an attacker \x1b[4;32mcannot\x1b[24m\x1b[37m derive sibling addresses or the parent private key.\x1b[0m
        \x1b[37m        - Provides \x1b[4;32man extra layer of security\x1b[24m\x1b[37m, as child keys are completely isolated from their parent structure.\x1b[0m

        \x1b[1;37mSeed Backup & JSON Encryption:\x1b[0m
        \x1b[37m- The JSON backup is encrypted to secure your seed data.
        - When entering your seed phrase, you can input one or multiple words separated by spaces.
        - Each word is automatically validated; once a valid word is entered, the prompt will advance to the next.
        - For a complete 24-word seed, the final (24th) word is computed automatically based on the required checksum.\x1b[0m

        ");

        let seed_option = loop {
            let input =
                prompt_user_input("Enter your selection (1-5): ", theme_colors.input_prompt)?;
            match input.parse::<u8>() {
                Ok(1) | Ok(2) | Ok(3) | Ok(4) | Ok(5) => break input.parse::<u8>()?,
                _ => {
                    stdout.execute(SetForegroundColor(theme_colors.error))?;
                    println!("Invalid selection. Please enter 1, 2, 3, 4, or 5.");
                    stdout.execute(ResetColor)?;
                }
            }
        };

        if seed_option == 5 {
            break;
        }

        if seed_option == 4 {
            stdout.execute(Clear(ClearType::All))?;
            stdout.execute(cursor::MoveTo(0, 0))?;
            let file_path = "seed_backup.json.age";
            let file_path = if Path::new(file_path).exists() {
                stdout.execute(Clear(ClearType::All))?;
                stdout.execute(cursor::MoveTo(0, 0))?;
                println!();
                stdout.execute(SetForegroundColor(theme_colors.header))?;
                println!("Found backup file: {}", file_path);
                stdout.execute(ResetColor)?;
                file_path.to_string()
            } else {
                prompt_user_input(
                "\nEnter the full path to the encrypted JSON file (e.g., /path/to/seed_backup.json.age): ",
                theme_colors.input_prompt,
            )?
            };
            let file_path = expand_tilde(&file_path);

            let mut file = match File::open(&file_path) {
                Ok(f) => f,
                Err(e) => {
                    stdout.execute(SetForegroundColor(theme_colors.error))?;
                    println!("Error opening file {}: {}", file_path, e);
                    stdout.execute(ResetColor)?;
                    continue;
                }
            };

            let mut encrypted_data = Vec::new();
            if let Err(e) = file.read_to_end(&mut encrypted_data) {
                stdout.execute(SetForegroundColor(theme_colors.error))?;
                println!("Error reading file {}: {}", file_path, e);
                stdout.execute(ResetColor)?;
                continue;
            }

            loop {
                let identity_input = hidden_input(
                    "\nEnter age identity file path or AGE-SECRET-KEY-...: ",
                    theme_colors.input_prompt,
                )?;

                match decrypt_data(&encrypted_data, identity_input.expose_secret()) {
                    Ok(decrypted_json) => {
                        match serde_json::from_str::<SeedBackup>(decrypted_json.expose_secret()) {
                            Ok(backup) => {
                                run_backup_text_ui(
                                    backup,
                                    theme_colors.clone(),
                                    "Decrypted Seed Backup ",
                                    false,
                                )?;
                                break;
                            }
                            Err(e) => {
                                stdout.execute(SetForegroundColor(theme_colors.error))?;
                                println!("Error parsing JSON: {}", e);
                                stdout.execute(ResetColor)?;
                            }
                        }
                    }
                    Err(e) => {
                        stdout.execute(SetForegroundColor(theme_colors.error))?;
                        println!("Decryption failed: {}", e);
                        stdout.execute(ResetColor)?;
                    }
                }
                let try_again = prompt_single_key("Try again? (y/n): ", theme_colors.input_prompt)?;
                if try_again.to_ascii_lowercase() != 'y' {
                    break;
                }
            }
        } else if seed_option == 3 {
            stdout.execute(Clear(ClearType::All))?;
            stdout.execute(cursor::MoveTo(0, 0))?;
            println!();
            stdout.execute(SetForegroundColor(theme_colors.header))?;
            println!("You have chosen to derive wallet addresses from entropy or seed phrase.");
            stdout.execute(ResetColor)?;

            let (_mnemonic, seed_vec): (bip39::Mnemonic, Vec<u8>) = if Path::new(
                "seed_backup.json.age",
            )
            .exists()
            {
                let backup_choice = prompt_single_key(
                "A backup file 'seed_backup.json.age' was detected.\nPress [d] to decrypt it for address derivation, or any other key to enter manually: ",
                theme_colors.input_prompt,
            )?;
                if backup_choice.to_ascii_lowercase() == 'd' {
                    let mut file = File::open("seed_backup.json.age")?;
                    let mut encrypted_data = Vec::new();
                    file.read_to_end(&mut encrypted_data)?;
                    let identity_input = hidden_input(
                        "\nEnter age identity file path or AGE-SECRET-KEY-...: ",
                        theme_colors.input_prompt,
                    )?;
                    match decrypt_data(&encrypted_data, identity_input.expose_secret()) {
                        Ok(decrypted_json) => {
                            match serde_json::from_str::<SeedBackup>(decrypted_json.expose_secret())
                            {
                                Ok(backup) => {
                                    stdout
                                        .execute(SetForegroundColor(theme_colors.final_output))?;
                                    println!("\nBackup successfully decrypted.");
                                    stdout.execute(ResetColor)?;
                                    let mut seed_bytes =
                                        hex::decode(backup.bip39_seed.expose_secret())?;
                                    lock_sensitive_data(&mut seed_bytes);
                                    let language = match backup.language.as_str() {
                                        "English" => bip39::Language::English,
                                        "SimplifiedChinese" => bip39::Language::SimplifiedChinese,
                                        "TraditionalChinese" => bip39::Language::TraditionalChinese,
                                        "Japanese" => bip39::Language::Japanese,
                                        "Korean" => bip39::Language::Korean,
                                        "Spanish" => bip39::Language::Spanish,
                                        "French" => bip39::Language::French,
                                        "Italian" => bip39::Language::Italian,
                                        "Czech" => bip39::Language::Czech,
                                        "Portuguese" => bip39::Language::Portuguese,
                                        _ => bip39::Language::English,
                                    };
                                    (
                                        bip39::Mnemonic::parse_in_normalized(
                                            language,
                                            backup.seed_phrase.expose_secret(),
                                        )?,
                                        seed_bytes,
                                    )
                                }
                                Err(e) => {
                                    stdout.execute(SetForegroundColor(theme_colors.error))?;
                                    println!(
                                    "Error parsing backup JSON: {}. Falling back to manual entry.",
                                    e
                                );
                                    stdout.execute(ResetColor)?;
                                    get_manual_seed(&theme_colors)?
                                }
                            }
                        }
                        Err(e) => {
                            stdout.execute(SetForegroundColor(theme_colors.error))?;
                            println!("Decryption failed: {}. Falling back to manual entry.", e);
                            stdout.execute(ResetColor)?;
                            get_manual_seed(&theme_colors)?
                        }
                    }
                } else {
                    get_manual_seed(&theme_colors)?
                }
            } else {
                get_manual_seed(&theme_colors)?
            };

            let mut seed = Zeroizing::new(seed_vec);
            lock_sensitive_data(seed.as_mut_slice());
            let master_xprv = Xpriv::new_master(Network::Bitcoin, seed.as_slice())?;

            loop {
                stdout.execute(Clear(ClearType::All))?;
                stdout.execute(cursor::MoveTo(0, 0))?;
                stdout.execute(SetForegroundColor(theme_colors.header))?;
                println!("Select address type:");
                stdout.execute(ResetColor)?;
                print!("  1: Bitcoin ");
                stdout.execute(SetForegroundColor(theme_colors.final_output))?;
                println!("(Native SegWit P2WPKH - m/84'/0'/0'/0/i)");
                stdout.execute(ResetColor)?;
                print!("  2: Ethereum/EVM ");
                stdout.execute(SetForegroundColor(theme_colors.final_output))?;
                println!("(BIP-44 - m/44'/60'/0'/0/i)");
                stdout.execute(ResetColor)?;
                print!("  3: XRP ");
                stdout.execute(SetForegroundColor(theme_colors.final_output))?;
                println!("(BIP-44 - m/44'/144'/0'/0/i)");
                stdout.execute(ResetColor)?;
                print!("  4: Solana ");
                stdout.execute(SetForegroundColor(theme_colors.final_output))?;
                println!("(BIP-44 - m/44'/501'/0'/0')");
                stdout.execute(ResetColor)?;
                println!("  5: Back to main menu");

                let addr_type = loop {
                    let input = prompt_user_input(
                        "\nEnter your selection (1-5): ",
                        theme_colors.input_prompt,
                    )?;
                    match input.parse::<u8>() {
                        Ok(1) | Ok(2) | Ok(3) | Ok(4) => break input.parse::<u8>()?,
                        Ok(5) => break 5,
                        _ => {
                            stdout.execute(SetForegroundColor(theme_colors.error))?;
                            println!("Invalid selection. Please enter 1, 2, 3, 4, or 5.");
                            stdout.execute(ResetColor)?;
                        }
                    }
                };

                if addr_type == 5 {
                    break;
                }

                let use_hardened_index = if addr_type == 1 || addr_type == 2 {
                    stdout.execute(Clear(ClearType::All))?;
                    stdout.execute(cursor::MoveTo(0, 0))?;
                    println!("\nSelect derivation index type for the final component:");
                    print!("  1: Fully Hardened Derivation ");
                    stdout.execute(SetForegroundColor(theme_colors.final_output))?;
                    print!("(e.g., i') ");
                    stdout.execute(ResetColor)?;
                    print!("\x1b[1;31;5m[!]\x1b[0m");
                    println!();
                    print!("  2: Standard Derivation ");
                    stdout.execute(SetForegroundColor(theme_colors.final_output))?;
                    println!("(e.g., i)");
                    stdout.execute(ResetColor)?;
                    let index_choice = loop {
                        let input = prompt_user_input(
                            "\nEnter your selection (1 or 2): ",
                            theme_colors.input_prompt,
                        )?;
                        match input.parse::<u8>() {
                            Ok(1) | Ok(2) => break input.parse::<u8>()?,
                            _ => {
                                stdout.execute(SetForegroundColor(theme_colors.error))?;
                                println!("Invalid selection. Please enter 1 or 2.");
                                stdout.execute(ResetColor)?;
                            }
                        }
                    };
                    index_choice == 1
                } else if addr_type == 3 {
                    false
                } else {
                    true
                };

                let range_input = prompt_user_input(
                    "\nEnter address index range (e.g., 5-100): ",
                    theme_colors.input_prompt,
                )?;
                let parts: Vec<&str> = range_input.trim().split('-').collect();
                if parts.len() != 2 {
                    println!(
                        "Invalid input format. Please use the format start-end (e.g., 5-100)."
                    );
                    continue;
                }
                let start_index = parts[0].trim().parse::<u32>()?;
                let end_index = parts[1].trim().parse::<u32>()?;
                if start_index > end_index {
                    println!("Start index cannot be greater than end index.");
                    continue;
                }
                if end_index - start_index > 1000 {
                    println!(
                        "The range is too large. Please specify a range of at most 1000 addresses."
                    );
                    continue;
                }

                let secp = Secp256k1::new();
                let mut address_entries = Vec::new();

                match addr_type {
                    1 => {
                        for i in start_index..=end_index {
                            let path_str = if use_hardened_index {
                                format!("m/84'/0'/0'/0/{}'", i)
                            } else {
                                format!("m/84'/0'/0'/0/{}", i)
                            };
                            let path = path_str.parse::<DerivationPath>()?;
                            let child_xprv = master_xprv.derive_priv(&secp, &path)?;
                            let child_pubkey_secp =
                                PublicKey::from_secret_key(&secp, &child_xprv.private_key);
                            let child_bitcoin_pubkey = bitcoin::PublicKey {
                                compressed: true,
                                inner: child_pubkey_secp,
                            };
                            let comp_pubkey = bitcoin::key::CompressedPublicKey::from_slice(
                                &child_bitcoin_pubkey.to_bytes(),
                            )?;
                            let addr_btc = Address::p2wpkh(&comp_pubkey, Network::Bitcoin);
                            let pubkey_hex = hex::encode(child_pubkey_secp.serialize());

                            address_entries.push(AddressEntry {
                                index: i,
                                address: addr_btc.to_string(),
                                pubkey: pubkey_hex,
                                privkey: None,
                                derivation_path: path_str,
                            });
                        }
                    }
                    2 => {
                        for i in start_index..=end_index {
                            let path_str = if use_hardened_index {
                                format!("m/44'/60'/0'/0/{}'", i)
                            } else {
                                format!("m/44'/60'/0'/0/{}", i)
                            };
                            let path = path_str.parse::<DerivationPath>()?;
                            let child_xprv = master_xprv.derive_priv(&secp, &path)?;
                            let child_pubkey =
                                PublicKey::from_secret_key(&secp, &child_xprv.private_key);
                            let eth_address = ethereum_address_from_pubkey(&child_pubkey);
                            let pubkey_hex =
                                format!("0x{}", hex::encode(child_pubkey.serialize_uncompressed()));

                            address_entries.push(AddressEntry {
                                index: i,
                                address: eth_address,
                                pubkey: pubkey_hex,
                                privkey: None,
                                derivation_path: path_str,
                            });
                        }
                    }
                    3 => {
                        for i in start_index..=end_index {
                            let path_str = if use_hardened_index {
                                format!("m/44'/144'/0'/0/{}'", i)
                            } else {
                                format!("m/44'/144'/0'/0/{}", i)
                            };
                            let path = path_str.parse::<DerivationPath>()?;
                            let child_xprv = master_xprv.derive_priv(&secp, &path)?;
                            let child_pubkey =
                                PublicKey::from_secret_key(&secp, &child_xprv.private_key);
                            let xrp_addr = xrp_address_from_pubkey(&child_pubkey);
                            let pubkey_hex = hex::encode(child_pubkey.serialize());

                            address_entries.push(AddressEntry {
                                index: i,
                                address: xrp_addr,
                                pubkey: pubkey_hex,
                                privkey: None,
                                derivation_path: path_str,
                            });
                        }
                    }
                    4 => {
                        for i in start_index..=end_index {
                            let path_str = format!("m/44'/501'/0'/0'/{}'", i);
                            let path = path_str.parse::<BIP32Path>().map_err(Slip10ErrorWrapper)?;
                            let derived = derive_key_from_path(&seed, Curve::Ed25519, &path)
                                .map_err(Slip10ErrorWrapper)?;
                            let signing_key = SigningKey::from_bytes(&derived.key);
                            let verifying_key = VerifyingKey::from(&signing_key);

                            let sol_address = bs58::encode(verifying_key.to_bytes()).into_string();
                            let pubkey_hex = hex::encode(verifying_key.to_bytes());

                            address_entries.push(AddressEntry {
                                index: i,
                                address: sol_address,
                                pubkey: pubkey_hex,
                                privkey: None,
                                derivation_path: path_str,
                            });
                        }
                    }
                    _ => {
                        println!("Address type not supported!");
                    }
                }

                let return_to_menu = run_address_table_ui(
                    &mut address_entries,
                    addr_type,
                    &theme_colors,
                    &master_xprv,
                    seed.as_slice(),
                )?;
                if !return_to_menu {
                    break;
                }
            }
        } else if seed_option == 2 {
            stdout.execute(Clear(ClearType::All))?;
            stdout.execute(cursor::MoveTo(0, 0))?;
            println!();
            stdout.execute(SetForegroundColor(theme_colors.header))?;
            println!("You have chosen to recover an existing seed from SSKR shares.");
            stdout.execute(ResetColor)?;

            println!("\nSelect language of the SSKR shares:");
            println!("  1: English");
            println!("  2: Simplified Chinese");
            println!("  3: Traditional Chinese");
            println!("  4: Japanese");
            println!("  5: Korean");
            println!("  6: Spanish");
            println!("  7: French");
            println!("  8: Italian");
            println!("  9: Czech");
            println!(" 10: Portuguese");
            let language_choice = loop {
                let input =
                    prompt_user_input("Enter your selection (1-10): ", theme_colors.input_prompt)?;
                match input.parse::<u8>() {
                    Ok(num) if num >= 1 && num <= 10 => break num,
                    _ => {
                        stdout.execute(SetForegroundColor(theme_colors.error))?;
                        println!("Invalid selection. Please enter a number between 1 and 10.");
                        stdout.execute(ResetColor)?;
                    }
                }
            };
            let language = language_from_choice(language_choice);

            println!("Enter SSKR shares in either ");
            stdout.execute(SetForegroundColor(theme_colors.final_output))?;
            print!("hexadecimal");
            stdout.execute(ResetColor)?;
            print!(" or ");
            stdout.execute(SetForegroundColor(theme_colors.final_output))?;
            println!("mnemonic form.");
            stdout.execute(ResetColor)?;

            println!("The system will automatically detect the input format and combine shares when enough valid ones are provided.");

            print!("Do not enter duplicate shares. ");
            stdout.execute(SetForegroundColor(theme_colors.error))?;
            print!("\x1b[1;31;5m[!]\x1b[0m");
            stdout.execute(ResetColor)?;
            println!();

            let mut all_shares: Vec<Vec<u8>> = Vec::new();
            loop {
                let input = prompt_user_input(
                    "\nEnter share (hex or mnemonic): ",
                    theme_colors.input_prompt,
                )?;
                if input.trim().is_empty() {
                    stdout.execute(SetForegroundColor(theme_colors.error))?;
                    println!("Empty input; please enter a valid share.");
                    stdout.execute(ResetColor)?;
                    continue;
                }
                let share_bytes = if input.contains(' ') {
                    match mnemonic_to_share(&input, language) {
                        Some(bytes) => bytes,
                        None => {
                            stdout.execute(SetForegroundColor(theme_colors.error))?;
                            println!("Invalid mnemonic share input.");
                            stdout.execute(ResetColor)?;
                            continue;
                        }
                    }
                } else {
                    match hex::decode(&input) {
                        Ok(bytes) => bytes,
                        Err(e) => {
                            stdout.execute(SetForegroundColor(theme_colors.error))?;
                            println!("Error decoding hex: {}", e);
                            stdout.execute(ResetColor)?;
                            continue;
                        }
                    }
                };
                if all_shares.contains(&share_bytes) {
                    stdout.execute(SetForegroundColor(theme_colors.error))?;
                    println!("Duplicate share detected; please enter a new share.");
                    stdout.execute(ResetColor)?;
                    continue;
                }
                all_shares.push(share_bytes);
                match sskr_combine(&all_shares) {
                    Ok(secret) => {
                        println!("\nSufficient shares provided. Secret successfully recovered.");
                        let mut entropy = Zeroizing::new(secret.as_ref().to_vec());
                        lock_sensitive_data(entropy.as_mut_slice());
                        let mnemonic =
                            bip39::Mnemonic::from_entropy_in(language, entropy.as_slice())?;
                        let passphrase = hidden_input(
                            "\nEnter an optional passphrase for seed derivation (leave blank to skip): ",
                            theme_colors.input_prompt,
                        )?;
                        let mut seed =
                            Zeroizing::new(mnemonic.to_seed(passphrase.expose_secret()).to_vec());
                        lock_sensitive_data(seed.as_mut_slice());
                        let master_xprv = Xpriv::new_master(Network::Bitcoin, seed.as_slice())?;

                        let backup = SeedBackup {
                            language: format!("{:?}", language),
                            seed_phrase: mnemonic.to_string().into(),
                            passphrase: passphrase.into(),
                            sskr: SskrBackup { groups: vec![] },
                            entropy: hex::encode(entropy.as_slice()).into(),
                            bip39_seed: hex::encode(seed.as_slice()).into(),
                            bip32_root_key: format!("{}", master_xprv).into(),
                            recovery_info: String::from("Recovered via SSKR shares"),
                        };

                        run_backup_text_ui(
                            backup,
                            theme_colors.clone(),
                            "SSKR Shares Recovery",
                            false,
                        )?;
                        break;
                    }
                    Err(_) => {
                        println!("Not enough valid shares yet. Please enter another share.");
                    }
                }
            }
        } else if seed_option == 1 {
            stdout.execute(Clear(ClearType::All))?;
            stdout.execute(cursor::MoveTo(0, 0))?;
            stdout.execute(SetForegroundColor(theme_colors.error))?;
            println!("\nSecurity Warning: Manual Mnemonic Creation \x1b[1;31;5m[!]\x1b[0m");
            stdout.execute(ResetColor)?;
            println!("Creating a mnemonic by choosing your own words (even randomly) is strongly discouraged.");
            println!("Human-selected words often have biases and patterns that dramatically reduce the effective security of your seed.");
            println!("A compromised seed can lead to a total loss of funds.");
            println!("\nIt is HIGHLY recommended to generate a new seed using a trusted hardware wallet or a secure offline software wallet.");
            println!("\nThis 'vanity' feature should only be used for educational purposes or with a clear understanding of the risks.");

            let creation_mode = loop {
                let input = prompt_user_input(
                    "\nSelect seed creation mode:\n  1: Manual (vanity, risky)\n  2: Generate true random seed (recommended)\nEnter 1 or 2: ",
                    theme_colors.input_prompt,
                )?;
                match input.trim() {
                    "1" => break 1,
                    "2" => break 2,
                    _ => {
                        stdout.execute(SetForegroundColor(theme_colors.error))?;
                        println!("Invalid selection. Please enter 1 or 2.");
                        stdout.execute(ResetColor)?;
                    }
                }
            };

            stdout.execute(Clear(ClearType::All))?;
            stdout.execute(cursor::MoveTo(0, 0))?;
            stdout.execute(SetForegroundColor(theme_colors.header))?;
            println!("\nSelect language:");
            stdout.execute(ResetColor)?;
            println!("  1: English");
            println!("  2: Simplified Chinese");
            println!("  3: Traditional Chinese");
            println!("  4: Japanese");
            println!("  5: Korean");
            println!("  6: Spanish");
            println!("  7: French");
            println!("  8: Italian");
            println!("  9: Czech");
            println!(" 10: Portuguese");
            let language_choice = loop {
                let input =
                    prompt_user_input("Enter your selection (1-10): ", theme_colors.input_prompt)?;
                match input.parse::<u8>() {
                    Ok(num) if num >= 1 && num <= 10 => break num,
                    _ => {
                        stdout.execute(SetForegroundColor(theme_colors.error))?;
                        println!("Invalid selection. Please enter a number between 1 and 10.");
                        stdout.execute(ResetColor)?;
                    }
                }
            };
            let language = language_from_choice(language_choice);
            let mut rng = OsRng;
            let (mnemonic, mnemonic_phrase) = if creation_mode == 2 {
                let mut entropy_bytes = [0u8; 32];
                rng.fill(&mut entropy_bytes);
                let mnemonic = bip39::Mnemonic::from_entropy_in(language, &entropy_bytes)?;
                let mnemonic_phrase = SecretString::new(mnemonic.to_string().into());
                (mnemonic, mnemonic_phrase)
            } else {
                let wordlist = language.word_list();
                let total_user_defined_positions = 23;
                let mut selected_indices: Vec<u16> = Vec::new();
                let mut error_message: Option<String> = None;
                while selected_indices.len() < total_user_defined_positions {
                    let current_position = selected_indices.len() + 1;
                    stdout.execute(Clear(ClearType::All))?;
                    stdout.execute(cursor::MoveTo(0, 0))?;
                    stdout.execute(SetForegroundColor(theme_colors.header))?;
                    println!("BIP-39 Tool");
                    stdout.execute(ResetColor)?;
                    stdout.execute(SetForegroundColor(theme_colors.position_label))?;
                    println!(
                        "Position {} of {}:",
                        current_position, total_user_defined_positions
                    );
                    stdout.execute(ResetColor)?;
                    if !selected_indices.is_empty() {
                        print!("Selected words so far: ");
                        for &index in &selected_indices {
                            print!("{} ", wordlist[index as usize]);
                        }
                        println!();
                    }
                    if let Some(ref msg) = error_message {
                        stdout.execute(SetForegroundColor(theme_colors.error))?;
                        println!("{}", msg);
                        stdout.execute(ResetColor)?;
                    }
                    println!();
                    let input = prompt_user_input("Enter your desired mnemonic word(s) for this position (or press Enter for a random word): ", theme_colors.input_prompt)?;
                    if input.is_empty() {
                        let random_index = rng.gen_range(0..wordlist.len() as u16);
                        stdout.execute(SetForegroundColor(theme_colors.random_message))?;
                        println!(
                            "No input provided. Selecting a random word: {}",
                            wordlist[random_index as usize]
                        );
                        stdout.execute(ResetColor)?;
                        selected_indices.push(random_index);
                        error_message = None;
                    } else {
                        let mut tokens: Vec<&str> = input.split_whitespace().collect();
                        let remaining_positions =
                            total_user_defined_positions - selected_indices.len();
                        if tokens.len() > remaining_positions {
                            stdout.execute(SetForegroundColor(theme_colors.error))?;
                            println!("More words were entered than required; only the first {} word(s) will be used.", remaining_positions);
                            stdout.execute(ResetColor)?;
                            tokens.truncate(remaining_positions);
                        }
                        let mut is_valid = true;
                        let mut indices_to_add = Vec::new();
                        for token in tokens.iter() {
                            match wordlist.iter().position(|&w| w == *token) {
                                Some(idx) => {
                                    indices_to_add.push(idx as u16);
                                }
                                None => {
                                    error_message = Some(format!(
                                        "Error: The word '{}' is not found in the BIP-39 wordlist.",
                                        token
                                    ));
                                    is_valid = false;
                                    break;
                                }
                            }
                        }
                        if !is_valid {
                            continue;
                        }
                        selected_indices.extend(indices_to_add);
                        error_message = None;
                    }
                }
                print_dashed_line();
                println!(
                    "All 23 words have been finalized, representing {} bits of entropy.",
                    selected_indices.len() * 11
                );
                let fixed_bits: Vec<bool> = selected_indices
                    .iter()
                    .flat_map(|&index| bits_from_u16(index, 11))
                    .collect();
                let mut final_word_candidates = Vec::new();
                for candidate in 0..8 {
                    let candidate_bits = bits_from_u16(candidate, 3);
                    let mut entropy_bits = fixed_bits.clone();
                    entropy_bits.extend(candidate_bits.clone());
                    let entropy_bytes = bits_to_bytes(&entropy_bits);
                    let hash = Sha256::digest(&entropy_bytes);
                    let hash_byte = hash[0];
                    let mut checksum_bits: Vec<bool> = Vec::with_capacity(8);
                    for i in (0..8).rev() {
                        checksum_bits.push(((hash_byte >> i) & 1) != 0);
                    }
                    let mut final_word_bits = candidate_bits.clone();
                    final_word_bits.extend(checksum_bits);
                    let final_index = bits_to_u16(&final_word_bits);
                    final_word_candidates.push(final_index);
                }
                stdout.execute(SetForegroundColor(theme_colors.candidate_header))?;
                println!();
                println!("Based on your input, the following candidate words have been computed for the final (24th) position:");
                stdout.execute(ResetColor)?;
                for (i, &candidate_index) in final_word_candidates.iter().enumerate() {
                    println!("  Option {}: {}", i + 1, wordlist[candidate_index as usize]);
                }
                let final_choice = loop {
                    let input = prompt_user_input(
                        "Please select an option (1-8) for the final word: ",
                        theme_colors.input_prompt,
                    )?;
                    match input.parse::<usize>() {
                        Ok(n) if n >= 1 && n <= final_word_candidates.len() => break n - 1,
                        _ => {
                            stdout.execute(SetForegroundColor(theme_colors.error))?;
                            println!(
                                "Invalid selection. Enter a number between 1 and {}.",
                                final_word_candidates.len()
                            );
                            stdout.execute(ResetColor)?;
                        }
                    }
                };
                let final_word_index = final_word_candidates[final_choice];
                selected_indices.push(final_word_index);
                let mnemonic_words: Vec<&str> = selected_indices
                    .iter()
                    .map(|&idx| wordlist[idx as usize])
                    .collect();
                let mnemonic_phrase = SecretString::new(mnemonic_words.join(" ").into());
                let mnemonic = bip39::Mnemonic::parse_in_normalized(
                    language,
                    mnemonic_phrase.expose_secret(),
                )?;
                (mnemonic, mnemonic_phrase)
            };
            stdout.execute(Clear(ClearType::All))?;
            stdout.execute(cursor::MoveTo(0, 0))?;
            println!("\nYour seed phrase is:");
            stdout.execute(SetForegroundColor(theme_colors.final_output))?;
            println!("{}", mnemonic_phrase.expose_secret());
            stdout.execute(ResetColor)?;
            let mut recovered_entropy = Zeroizing::new(mnemonic.to_entropy().to_vec());
            lock_sensitive_data(recovered_entropy.as_mut_slice());

            let passphrase = loop {
                let pass1 = hidden_input(
                    "\nEnter an optional passphrase for seed derivation (leave blank for none): ",
                    theme_colors.input_prompt,
                )?;
                let pass2 = hidden_input(
                    "Re-enter passphrase to confirm: ",
                    theme_colors.input_prompt,
                )?;
                if pass1.expose_secret() == pass2.expose_secret() {
                    break pass1;
                } else {
                    stdout.execute(SetForegroundColor(theme_colors.error))?;
                    println!("Passphrases do not match. Please try again.");
                    stdout.execute(ResetColor)?;
                }
            };

            let mut seed = Zeroizing::new(mnemonic.to_seed(passphrase.expose_secret()).to_vec());
            lock_sensitive_data(seed.as_mut_slice());
            let master_xprv = Xpriv::new_master(Network::Bitcoin, seed.as_slice())?;
            println!();
            print!("Entropy: ");
            stdout.execute(SetForegroundColor(theme_colors.final_output))?;
            println!("{}", hex::encode(recovered_entropy.as_slice()));
            stdout.execute(ResetColor)?;
            print!("BIP-39 Seed: ");
            stdout.execute(SetForegroundColor(theme_colors.final_output))?;
            println!("{}", hex::encode(seed.as_slice()));
            stdout.execute(ResetColor)?;
            print!("BIP-32 Root Key (xprv): ");
            stdout.execute(SetForegroundColor(theme_colors.final_output))?;
            println!("{}", master_xprv);
            stdout.execute(ResetColor)?;

            if seed_option == 1 {
                let backup_choice = prompt_user_input(
                    "\nWould you like to create an SSKR backup of your mnemonic entropy? (y/n): ",
                    theme_colors.input_prompt,
                )?;
                if backup_choice.trim().eq_ignore_ascii_case("y") {
                    let secret = Secret::new(recovered_entropy.as_slice())?;
                    let num_groups = loop {
                        let input = prompt_user_input(
                            "Enter the number of backup groups: ",
                            theme_colors.input_prompt,
                        )?;
                        if let Ok(n) = input.parse::<u8>() {
                            if n > 0 {
                                break n;
                            }
                        }
                        stdout.execute(SetForegroundColor(theme_colors.error))?;
                        println!("Invalid entry. Please enter a positive number.");
                        stdout.execute(ResetColor)?;
                    };
                    let mut group_specs = Vec::new();
                    for group in 1..=num_groups {
                        println!("\nFor backup group {}:", group);
                        let total_shares = loop {
                            let input = prompt_user_input(
                                &format!("Enter the total number of shares for group {}: ", group),
                                theme_colors.input_prompt,
                            )?;
                            if let Ok(n) = input.parse::<u8>() {
                                if n > 0 {
                                    break n;
                                }
                            }
                            stdout.execute(SetForegroundColor(theme_colors.error))?;
                            println!("Please enter a valid positive number.");
                            stdout.execute(ResetColor)?;
                        };
                        let required_shares = loop {
                            let input = prompt_user_input(
                                &format!(
                                    "Enter the number of shares required to recover group {}: ",
                                    group
                                ),
                                theme_colors.input_prompt,
                            )?;
                            if let Ok(n) = input.parse::<u8>() {
                                if n > 0 && n <= total_shares {
                                    break n;
                                }
                            }
                            stdout.execute(SetForegroundColor(theme_colors.error))?;
                            println!(
                                "Please enter a valid number (must be >0 and ≤ total shares)."
                            );
                            stdout.execute(ResetColor)?;
                        };
                        match GroupSpec::new(required_shares as usize, total_shares as usize) {
                            Ok(spec) => group_specs.push(spec),
                            Err(e) => {
                                stdout.execute(SetForegroundColor(theme_colors.error))?;
                                println!("Error creating group spec: {:?}", e);
                                stdout.execute(ResetColor)?;
                                continue;
                            }
                        }
                    }
                    let quorum_threshold = if num_groups > 1 {
                        loop {
                            let input = prompt_user_input(&format!("Enter the number of groups required to recover the secret (1-{}): ", num_groups), theme_colors.input_prompt)?;
                            if let Ok(n) = input.parse::<u8>() {
                                if n >= 1 && n <= num_groups {
                                    break n;
                                }
                            }
                            stdout.execute(SetForegroundColor(theme_colors.error))?;
                            println!(
                                "Invalid entry. Please enter a number between 1 and {}.",
                                num_groups
                            );
                            stdout.execute(ResetColor)?;
                        }
                    } else {
                        1
                    };
                    let spec = match Spec::new(quorum_threshold as usize, group_specs) {
                        Ok(s) => s,
                        Err(e) => {
                            stdout.execute(SetForegroundColor(theme_colors.error))?;
                            println!("Error creating SSKR spec: {:?}", e);
                            stdout.execute(ResetColor)?;
                            continue;
                        }
                    };
                    let shares: Vec<Vec<Vec<u8>>> = sskr_generate(&spec, &secret)?;
                    let recovery_info = format!(
                        "In total, a minimum of {} out of {} group{} {} needed to recover your secret.",
                        quorum_threshold,
                        num_groups,
                        if num_groups == 1 { "" } else { "s" },
                        if quorum_threshold == 1 { "is" } else { "are" }
                    );
                    let mut sskr_backup: Vec<Vec<Share>> = Vec::new();
                    for group_shares in shares.iter() {
                        let mut group_vec = Vec::new();
                        for share in group_shares.iter() {
                            let share_hex = hex::encode(share);
                            let mnemonic = share_to_mnemonic(share, language);
                            group_vec.push(Share {
                                share_hex: share_hex.into(),
                                mnemonic: mnemonic.into(),
                            });
                        }
                        sskr_backup.push(group_vec);
                    }
                    let backup = SeedBackup {
                        language: format!("{:?}", language),
                        seed_phrase: mnemonic_phrase.clone(),
                        passphrase: SecretString::new(
                            passphrase.expose_secret().to_string().into(),
                        ),
                        sskr: SskrBackup {
                            groups: sskr_backup,
                        },
                        entropy: hex::encode(recovered_entropy.as_slice()).into(),
                        bip39_seed: hex::encode(seed.as_slice()).into(),
                        bip32_root_key: format!("{}", master_xprv).into(),
                        recovery_info,
                    };

                    run_backup_text_ui(
                        backup,
                        theme_colors.clone(),
                        "SENSITIVE INFORMATION",
                        true,
                    )?;
                } else {
                    let backup = SeedBackup {
                        language: format!("{:?}", language),
                        seed_phrase: mnemonic_phrase,
                        passphrase: SecretString::new(
                            passphrase.expose_secret().to_string().into(),
                        ),
                        sskr: SskrBackup { groups: vec![] },
                        entropy: hex::encode(recovered_entropy.as_slice()).into(),
                        bip39_seed: hex::encode(seed.as_slice()).into(),
                        bip32_root_key: format!("{}", master_xprv).into(),
                        recovery_info: String::new(),
                    };
                    run_backup_text_ui(
                        backup,
                        theme_colors.clone(),
                        "SENSITIVE INFORMATION",
                        true,
                    )?;
                }
            }
        }

        let continue_choice =
            prompt_single_key("\nReturn to main menu? (y/n): ", theme_colors.input_prompt)?;
        if continue_choice.to_ascii_lowercase() != 'y' {
            break;
        }
    }
    Ok(())
}

fn print_dashed_line() {
    if let Some((width, _)) = terminal_size::terminal_size() {
        println!("{}", "─".repeat(width.0 as usize));
    } else {
        println!("{}", "─".repeat(40));
    }
}
