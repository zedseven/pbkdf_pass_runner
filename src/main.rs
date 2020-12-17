use hmac::Hmac;
use rayon::current_num_threads;
use rayon::prelude::*;
use sha1::Sha1;
use std::env;
use std::fs::File;
use std::io::{self, prelude::*, BufReader};
use std::sync::atomic::{AtomicU64, Ordering};
use stopwatch::Stopwatch;

//const PRINT_INTERVAL: u64 = 10000000;

fn main() -> io::Result<()> {
	let args: Vec<String> = env::args().collect();
	if args.len() < 7 {
		println!("args: <num_threads> <salt (hex string)> <iterations = 20> <compare_key (hex string)> <delimiter = 0a> <word_list_path>");
		return Ok(());
	}
	let num_threads = args[1].parse::<usize>().unwrap();
	let salt = &parse_hex(&args[2])[..];
	let iterations = args[3].parse::<u32>().unwrap();
	let compare_key = &parse_hex(&args[4])[..];
	let delimiter = parse_hex(&args[5])[0];
	let word_list_path = &args[6];

	let file = File::open(word_list_path)?;
	let reader = BufReader::new(file);

	rayon::ThreadPoolBuilder::new()
		.num_threads(num_threads)
		.build_global()
		.unwrap();

	let num_checked = AtomicU64::new(0);
	let sw = Stopwatch::start_new();

	let mut passes = Passes::new(delimiter, reader);
	match passes.par_bridge().find_any(|line| -> bool {
		match line {
			Ok(pass) => {
				let mut try_key = [0u8; 16];
				pbkdf2::pbkdf2::<Hmac<Sha1>>(pass, &salt, iterations, &mut try_key);
				num_checked.fetch_add(1, Ordering::Relaxed);
				/*let num_checked_now = num_checked.fetch_add(1, Ordering::SeqCst) + 1;
				if num_checked_now % PRINT_INTERVAL == 0 {
					println!("Checked: {} words", num_checked_now);
				}*/
				return try_key.eq(compare_key);
			}
			_ => false,
		}
	}) {
		Some(pass) => {
			let pass_res = pass.unwrap();
			let mut renderable = true;
			for i in pass_res.iter() {
				if *i < b'0' || *i > b'z' {
					renderable = false;
					break;
				}
			}
			if renderable {
				println!("Password: {}", String::from_utf8_lossy(&pass_res));
			} else {
				println!("Password: {:?}", pass_res);
			}
		}
		_ => (),
	}

	let total_checked = num_checked.load(Ordering::SeqCst);
	let elapsed_time = sw.elapsed_ms() as u64;
	if elapsed_time > 0 {
		println!(
			"Checked {} total words in {}ms, for an average speed of ~{} words/second.",
			total_checked,
			elapsed_time,
			1000 * total_checked / elapsed_time
		);
	} else {
		println!(
			"Checked {} total words in {}ms.",
			total_checked, elapsed_time
		);
	}
	Ok(())
}

struct Passes<B> {
	delimiter: u8,
	buf: B,
	pool: Vec<Vec<u8>>,
}

impl<B: BufRead> Passes<B> {
	pub fn new(delimiter: u8, buf: B) -> Passes<B> {
		Passes {
			delimiter,
			buf,
			pool: vec![],
		}
	}

	pub fn add_to_pool(&mut self) -> io::Result<u8> {
		let mut buf = Vec::new();
		match self.buf.read_until(self.delimiter, &mut buf) {
			Ok(0) => Ok(0),
			Ok(_n) => {
				if buf.ends_with(&[self.delimiter]) {
					buf.pop();
					/*// Not too pleased with this, but it means massive 100+GB dictionaries don't have to be converted to Unix line endings
					if buf.ends_with(&[b'\r']) {
						buf.pop();
					}*/
				}
				self.pool.push(buf);
				Ok(1)
			}
			Err(e) => Err(e),
		}
	}
}

impl<B: BufRead> Iterator for Passes<B> {
	type Item = io::Result<Vec<u8>>;

	fn next(&mut self) -> Option<io::Result<Vec<u8>>> {
		if self.pool.len() == 0 {
			let num_threads = current_num_threads();
			for _ in 0..(num_threads * 2) {
				self.add_to_pool();
			}
		}

		match self.pool.pop() {
			Some(res) => Some(Ok(res)),
			None => None,
		}
	}
}

// Written by Jake Goulding
// https://codereview.stackexchange.com/a/201699
fn parse_hex(hex_asm: &str) -> Vec<u8> {
	let mut hex_bytes = hex_asm
		.as_bytes()
		.iter()
		.filter_map(|b| match b {
			b'0'..=b'9' => Some(b - b'0'),
			b'a'..=b'f' => Some(b - b'a' + 10),
			b'A'..=b'F' => Some(b - b'A' + 10),
			_ => None,
		})
		.fuse();

	let mut bytes = Vec::new();
	while let (Some(h), Some(l)) = (hex_bytes.next(), hex_bytes.next()) {
		bytes.push(h << 4 | l)
	}
	bytes
}
