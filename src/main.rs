use std::env;
use std::fs::{File, read};
use std::io::{self, prelude::*, BufReader};
use std::sync::atomic::{AtomicU64, Ordering};
use rayon::prelude::*;
use sha1::Sha1;
use hmac::Hmac;
use stopwatch::{Stopwatch};

const PRINT_INTERVAL: u64 = 10000000;

fn main() -> io::Result<()> {
	let args: Vec<String> = env::args().collect();
	if args.len() < 6 {
		println!("args: <num_threads> <salt (hex string)> <iterations = 20> <compare_key (hex string)> <word_list_path>");
		return Ok(())
	}
	let num_threads = args[1].parse::<usize>().unwrap();
	let salt = parse_hex(&args[2]);
	let iterations = args[3].parse::<u32>().unwrap();
	let compare_key = &parse_hex(&args[4])[..];
	let word_list_path = &args[5];

	let file = File::open(word_list_path)?;
	let reader = BufReader::new(file);

	rayon::ThreadPoolBuilder::new().num_threads(num_threads).build_global().unwrap();
	
	let num_checked: AtomicU64 = AtomicU64::new(0);
	let sw = Stopwatch::start_new();
	
	reader.lines().par_bridge().for_each(|line| -> () {
		match line {
			Ok(pass) => {
				let mut try_key: [u8; 16] = [0; 16];
				pbkdf2::pbkdf2::<Hmac<Sha1>>(pass.as_bytes(), &salt[..], iterations, &mut try_key);
				//println!("{}", pass);
				//num_checked.fetch_add(1, Ordering::SeqCst);
				let num_checked_now = num_checked.fetch_add(1, Ordering::SeqCst) + 1;
				if num_checked_now % PRINT_INTERVAL == 0 {
					println!("Checked: {} words - at \"{}\"", num_checked_now, pass);
				}
				if try_key.eq(compare_key) {
					println!("Password: {}", pass);
					panic!("Checked {} total words in {}ms.", num_checked.load(Ordering::SeqCst), sw.elapsed_ms())
				}
			}
			_ => {}
		}
	});
	
	println!("Checked {} total words in {}ms.", num_checked.load(Ordering::SeqCst), sw.elapsed_ms());
	Ok(())
}

// Written by Jake Goulding
// https://codereview.stackexchange.com/a/201699
fn parse_hex(hex_asm: &str) -> Vec<u8> {
	let mut hex_bytes = hex_asm.as_bytes().iter().filter_map(|b| {
		match b {
			b'0'..=b'9' => Some(b - b'0'),
			b'a'..=b'f' => Some(b - b'a' + 10),
			b'A'..=b'F' => Some(b - b'A' + 10),
			_ => None,
		}
	}).fuse();

	let mut bytes = Vec::new();
	while let (Some(h), Some(l)) = (hex_bytes.next(), hex_bytes.next()) {
		bytes.push(h << 4 | l)
	}
	bytes
}
