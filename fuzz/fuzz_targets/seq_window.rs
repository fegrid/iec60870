// Fuzz target: sequence-window state machine must hold its window invariant.

#![cfg_attr(feature = "libfuzzer", no_main)]
#![allow(dead_code)]

#[cfg(not(feature = "libfuzzer"))]
fn main() {
    use std::io::Read;
    let mut data = Vec::new();
    std::io::stdin().read_to_end(&mut data).unwrap();
    fuzz(&data);
}

use fegrid_iec60870_cs104::apci::SeqNo;
use fegrid_iec60870_cs104::sequence::SequenceState;

const K: u16 = 12;

pub fn fuzz(data: &[u8]) {
    let mut s = SequenceState::new();
    for (i, b) in data.iter().enumerate() {
        match i % 4 {
            0 => {
                let _ = s.next_send(K);
            }
            1 => {
                let seq = SeqNo(u16::from(*b));
                let _ = s.on_i_received(seq);
            }
            2 => {
                let seq = SeqNo(u16::from(*b));
                s.on_s_received(seq);
                debug_assert!(s.unacked_count() <= K);
            }
            _ => {}
        }
    }
    debug_assert!(s.unacked_count() <= K);
}
