//! Minimal CS 104 master demo: print a STARTDT_ACT frame to stdout and
//! exit. Real implementations would wire this into a tokio TCP stack.
//!
//! ```text
//! cargo run -p fegrid-iec60870-tokio --example echo_master
//! ```

// stdout is the example's intended output (one-shot demo).
#![allow(clippy::print_stdout)]
use fegrid_iec60870_cs104::apci::{UFrame, u_frame_bytes};

fn main() {
    let frame = u_frame_bytes(UFrame::StartDtAct);
    for b in frame.iter() {
        print!("{b:02x} ");
    }
    println!();
}
