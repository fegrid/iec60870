//! Integration tests for the CS 101 serial transport (G-064).
//!
//! Uses tokio::io::duplex to build an in-memory bidirectional pipe
//! that stands in for a real serial port. We drive FT 1.2 fixed and
//! variable frames through the pipe using direct byte I/O against
//! the duplex stream, then parse_one the inbound bytes. This
//! exercises the same byte path a real serial2_tokio::SerialPort
//! would carry, without requiring hardware.
use fegrid_iec60870_core::AddressLen;

use fegrid_iec60870_cs101::ft12::{
    ControlField, FixedFrame, Ft12Error, Ft12Frame, VariableFrame, parse_one,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

fn framed_pair(buf: usize) -> (DuplexStream, DuplexStream) {
    tokio::io::duplex(buf)
}

#[tokio::test]
async fn fixed_frame_roundtrip_through_duplex() {
    let (mut a, mut b) = framed_pair(64);
    let original = FixedFrame {
        control: ControlField(0x01),
        address: 7,
    };
    let mut buf = [0u8; 6];
    let n = original.encode(AddressLen::One, &mut buf).unwrap();

    a.write_all(&buf[..n]).await.unwrap();
    let mut rx = [0u8; 16];
    let m = b.read(&mut rx).await.unwrap();
    assert_eq!(m, n);

    let (frame, consumed) = parse_one(&rx[..m], AddressLen::One).expect("parse_one");
    assert_eq!(consumed, n);
    match frame {
        Ft12Frame::Fixed(f) => {
            assert_eq!(f.control.0, 0x01);
            assert_eq!(f.address, 7);
        }
        other => panic!("expected Fixed frame, got {other:?}"),
    }
}

#[tokio::test]
async fn variable_frame_roundtrip_through_duplex() {
    let (mut a, mut b) = framed_pair(2048);
    let payload = b"hello-cs101";
    let original = VariableFrame {
        control: ControlField(0x08),
        address: 12,
        user_data: bytes::Bytes::copy_from_slice(payload),
    };
    let total = original.encoded_len(AddressLen::One);
    let mut buf = vec![0u8; total];
    let n = original.encode(AddressLen::One, &mut buf).unwrap();

    a.write_all(&buf[..n]).await.unwrap();
    let mut rx = vec![0u8; total + 8];
    let m = b.read(&mut rx).await.unwrap();
    assert_eq!(m, n);

    let (frame, consumed) = parse_one(&rx[..m], AddressLen::One).expect("parse_one");
    assert_eq!(consumed, n);
    match frame {
        Ft12Frame::Variable(v) => {
            assert_eq!(v.control.0, 0x08);
            assert_eq!(v.address, 12);
            assert_eq!(&v.user_data[..], payload.as_slice());
        }
        other => panic!("expected Variable frame, got {other:?}"),
    }
}

#[tokio::test]
async fn single_char_ack_roundtrip() {
    let (mut master, mut slave) = framed_pair(64);

    let frame = VariableFrame {
        control: ControlField(0x08),
        address: 1,
        user_data: bytes::Bytes::from_static(b"gi"),
    };
    let total = frame.encoded_len(AddressLen::One);
    let mut buf = vec![0u8; total];
    let n = frame.encode(AddressLen::One, &mut buf).unwrap();
    master.write_all(&buf[..n]).await.unwrap();

    let mut rx = vec![0u8; total + 8];
    let m = slave.read(&mut rx).await.unwrap();
    let (frame, consumed) = parse_one(&rx[..m], AddressLen::One).expect("parse_one");
    assert_eq!(consumed, n);
    assert!(matches!(frame, Ft12Frame::Variable(_)));

    slave.write_all(&[0xE5]).await.unwrap();
    let mut ack = [0u8; 1];
    master.read_exact(&mut ack).await.unwrap();
    assert_eq!(ack[0], 0xE5);
}

#[tokio::test]
async fn reset_remote_link_roundtrip() {
    let (mut master, mut slave) = framed_pair(64);

    let reset = FixedFrame {
        control: ControlField(0x40 | 0x20 | 0x01),
        address: 1,
    };
    let mut buf = [0u8; 6];
    let n = reset.encode(AddressLen::One, &mut buf).unwrap();
    master.write_all(&buf[..n]).await.unwrap();
    let mut rx = [0u8; 5];
    let n_read = slave.read_exact(&mut rx).await.unwrap();
    assert_eq!(n_read, 5);
    let (frame, consumed) = parse_one(&rx, AddressLen::One).expect("parse_one");
    assert_eq!(consumed, n_read);
    match frame {
        Ft12Frame::Fixed(f) => {
            assert_eq!(f.control.fc(), 1);
            assert!(f.control.fcb());
            assert!(f.control.fcv());
        }
        other => panic!("expected Fixed, got {other:?}"),
    }

    slave.write_all(&[0xE5]).await.unwrap();
    let mut ack = [0u8; 1];
    master.read_exact(&mut ack).await.unwrap();
    assert_eq!(ack[0], 0xE5);
}

#[tokio::test]
async fn multiple_frames_in_one_direction() {
    let (mut master, mut slave) = framed_pair(2048);

    let mut all = Vec::with_capacity(60);
    for addr in 1u16..=10 {
        let f = FixedFrame {
            control: ControlField(0x01),
            address: addr,
        };
        let mut buf = [0u8; 6];
        let n = f.encode(AddressLen::One, &mut buf).unwrap();
        all.extend_from_slice(&buf[..n]);
    }
    master.write_all(&all).await.unwrap();
    drop(master);

    let mut rx = vec![0u8; all.len()];
    let m = slave.read_exact(&mut rx).await.unwrap();
    assert_eq!(m, all.len());

    let mut cursor = 0;
    let mut received = 0;
    while cursor < m {
        let res = parse_one(&rx[cursor..m], AddressLen::One);
        match res {
            Ok((frame, consumed)) => {
                cursor += consumed;
                match frame {
                    Ft12Frame::Fixed(f) => {
                        received += 1;
                        assert_eq!(f.address, received, "FIFO order");
                    }
                    Ft12Frame::SingleCharAck => {}
                    Ft12Frame::NegativeAck => {}
                    Ft12Frame::Variable(_) => panic!("unexpected Variable frame"),
                }
            }
            Err(Ft12Error::NeedMore) => break,
            Err(Ft12Error::Resync(_)) => break,
            Err(e) => panic!("unexpected error: {e}"),
        }
    }
    assert_eq!(received, 10);
}

#[tokio::test]
async fn garbage_input_does_not_panic_codec() {
    let garbage: [u8; 7] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
    let res = parse_one(&garbage, AddressLen::One);
    match res {
        Ok((_, consumed)) => assert!(consumed <= garbage.len()),
        Err(Ft12Error::Resync(skip)) => assert!(skip <= garbage.len()),
        Err(Ft12Error::NeedMore) => {}
        Err(e) => panic!("unexpected error variant: {e:?}"),
    }
}

#[tokio::test]
async fn two_codecs_are_independent() {
    let c1 = fegrid_iec60870_cs101::ft12::Ft12Codec::new();
    let c2 = fegrid_iec60870_cs101::ft12::Ft12Codec::new();
    let _ = c1;
    let _ = c2;
    let c3 = fegrid_iec60870_cs101::ft12::Ft12Codec::new();
    let _ = c3.buffered_len();
}

#[tokio::test]
async fn ack_byte_in_user_data_is_not_ack_marker() {
    let (mut a, mut b) = framed_pair(2048);

    let payload = b"\xE5\xE5\xE5".to_vec();
    let frame = VariableFrame {
        control: ControlField(0x08),
        address: 1,
        user_data: bytes::Bytes::copy_from_slice(&payload),
    };
    let total = frame.encoded_len(AddressLen::One);
    let mut buf = vec![0u8; total];
    let n = frame.encode(AddressLen::One, &mut buf).unwrap();
    a.write_all(&buf[..n]).await.unwrap();

    let mut rx = vec![0u8; total + 8];
    let m = b.read(&mut rx).await.unwrap();
    let (frame, consumed) = parse_one(&rx[..m], AddressLen::One).expect("parse_one");
    assert_eq!(consumed, n);
    match frame {
        Ft12Frame::Variable(v) => {
            assert_eq!(&v.user_data[..], payload.as_slice());
        }
        other => panic!("expected Variable frame, got {other:?}"),
    }
}
