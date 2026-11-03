//! Per-packet splitting of the MTProto TCP stream into WS frames
//! (mirror of upstream `MsgSplitter`).

use crate::obfuscation::{PROTO_ABRIDGED, PROTO_INTERMEDIATE, PROTO_PADDED};

pub struct PacketSplitter {
    proto: u32,
    cipher_buf: Vec<u8>,
    plain_buf: Vec<u8>,
    disabled: bool,
}

impl PacketSplitter {
    pub fn new(proto: u32) -> Option<Self> {
        if !matches!(proto, PROTO_ABRIDGED | PROTO_INTERMEDIATE | PROTO_PADDED) {
            return None;
        }
        Some(Self {
            proto,
            cipher_buf: Vec::new(),
            plain_buf: Vec::new(),
            disabled: false,
        })
    }

    /// Feed one chunk of (cipher, plain) stream; returns complete packets.
    pub fn split(&mut self, chunk: &[u8], plain: &[u8]) -> Vec<Vec<u8>> {
        if chunk.is_empty() {
            return vec![];
        }
        if self.disabled {
            return vec![chunk.to_vec()];
        }
        self.cipher_buf.extend_from_slice(chunk);
        self.plain_buf.extend_from_slice(plain);

        let mut parts = Vec::new();
        let mut offset = 0usize;
        while offset < self.cipher_buf.len() {
            let avail = self.cipher_buf.len() - offset;
            match self.next_packet_len(offset, avail) {
                None => break,                                  // need more data
                Some(0) => {
                    // unknown framing -> passthrough everything, disable
                    if offset == 0 {
                        parts.push(self.cipher_buf.clone());
                    } else {
                        parts.push(self.cipher_buf[offset..].to_vec());
                    }
                    offset = self.cipher_buf.len();
                    self.disabled = true;
                    break;
                }
                Some(packet_len) => {
                    if offset == 0 && packet_len == self.cipher_buf.len() {
                        parts.push(self.cipher_buf.clone());
                    } else {
                        parts.push(self.cipher_buf[offset..offset + packet_len].to_vec());
                    }
                    offset += packet_len;
                }
            }
        }
        if offset > 0 {
            self.cipher_buf.drain(..offset);
            self.plain_buf.drain(..offset);
        }
        parts
    }

    fn next_packet_len(&self, offset: usize, avail: usize) -> Option<usize> {
        if avail == 0 {
            return None;
        }
        match self.proto {
            PROTO_ABRIDGED => self.abridged_len(offset, avail),
            PROTO_INTERMEDIATE | PROTO_PADDED => self.intermediate_len(offset, avail),
            _ => Some(0),
        }
    }

    fn abridged_len(&self, offset: usize, avail: usize) -> Option<usize> {
        let first = self.plain_buf[offset];
        if first == 0x7F || first == 0xFF {
            if avail < 4 {
                return None;
            }
            let payload_len = u32::from_le_bytes([
                self.plain_buf[offset + 1],
                self.plain_buf[offset + 2],
                self.plain_buf[offset + 3],
                0,
            ]) as usize * 4;
            let packet = 4 + payload_len;
            if payload_len == 0 {
                return Some(0);
            }
            if avail < packet {
                return None;
            }
            Some(packet)
        } else {
            let payload_len = (first & 0x7F) as usize * 4;
            if payload_len == 0 {
                return Some(0);
            }
            let packet = 1 + payload_len;
            if avail < packet {
                return None;
            }
            Some(packet)
        }
    }

    fn intermediate_len(&self, offset: usize, avail: usize) -> Option<usize> {
        if avail < 4 {
            return None;
        }
        let raw = u32::from_le_bytes(
            self.plain_buf[offset..offset + 4].try_into().unwrap(),
        );
        let payload_len = (raw & 0x7FFF_FFFF) as usize;
        if payload_len == 0 {
            return Some(0);
        }
        let packet = 4 + payload_len;
        if avail < packet {
            return None;
        }
        Some(packet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn abridged(payload: &[u8]) -> Vec<u8> {
        let words = payload.len() / 4;
        let mut out = Vec::new();
        if words < 0x7F {
            out.push(words as u8);
        } else {
            out.push(0x7F);
            out.extend_from_slice(&(words as u32).to_le_bytes()[0..3]);
        }
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn splits_single_packet() {
        let mut s = PacketSplitter::new(PROTO_ABRIDGED).unwrap();
        let stream = abridged(&[1u8; 40]);
        let parts = s.split(&stream, &stream);
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0], stream);
    }

    #[test]
    fn splits_two_packets() {
        let mut s = PacketSplitter::new(PROTO_ABRIDGED).unwrap();
        let p1 = abridged(&[1u8; 40]);
        let p2 = abridged(&[2u8; 80]);
        let stream = [p1.clone(), p2.clone()].concat();
        let parts = s.split(&stream, &stream);
        assert_eq!(parts, vec![p1, p2]);
    }

    #[test]
    fn waits_for_incomplete_packet() {
        let mut s = PacketSplitter::new(PROTO_ABRIDGED).unwrap();
        let full = abridged(&[1u8; 40]);
        let (head, tail) = full.split_at(10);
        assert!(s.split(head, head).is_empty());
        let parts = s.split(tail, tail);
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0], full);
    }

    #[test]
    fn intermediate_len() {
        let mut s = PacketSplitter::new(PROTO_INTERMEDIATE).unwrap();
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&24u32.to_le_bytes());
        pkt.extend_from_slice(&[3u8; 24]);
        let parts = s.split(&pkt, &pkt);
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0], pkt);
    }
}
