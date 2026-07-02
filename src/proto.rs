use crate::{BitkitError, Bitstream};
use std::collections::HashMap;

/// Three field types
/// Fixed(n) - n bits that are fixed across transmissions
/// Varying (n) - n bits that vary across transmissions
/// Repeat (n, [ProtoField(s)]) - recursive representation of repeated fields
#[derive(Debug, Eq, PartialEq, Hash, Copy, Clone)]
pub enum ProtoField {
    Fixed,
    Varying,
    Ambiguous,
    // TODO: Repeat(u32, Box<ProtoField>) or similar
}
#[derive(Debug)]
pub struct ProtocolStructure {
    protocol: Vec<(ProtoField, u32)>,
    num_fields: usize,
    num_bits: usize,
}

impl ProtocolStructure {
    /// Get the vector of protocol fields
    pub fn get_fields(&self) -> Vec<(ProtoField, u32)> {
        self.protocol.clone()
    }
    pub fn get_num_fields(&self) -> usize {
        self.num_fields
    }
    pub fn get_num_bits(&self) -> usize {
        self.num_bits
    }
    /// Takes a vector of positionwise entropies and uses it to infer the protocol structure.
    /// Bit positions with zero entropy become fixed fields, and bit positions with non-zero
    /// entropy become varying fields.
    pub fn infer_structure(poswise_ents: &[f32]) -> Self {
        Self::infer_structure_tolerance(poswise_ents, -1.0) // set epsilon to -1 to disable tolerance
                                                            // checking
    }
    /// Takes a vector of positionwise entropies and uses it to infer the protocol structure.
    /// Bit positions with an entropy of zero become fixed fields; bit positions with an
    /// entropy larger than epsilon become varying fields; bit positions with an entropy between
    /// zero and the provided epsilon are marked "ambiguous."
    pub fn infer_structure_tolerance(poswise_ents: &[f32], eps: f32) -> Self {
        let mut fields: Vec<(ProtoField, u32)> = vec![];
        if poswise_ents.is_empty() {
            return ProtocolStructure {
                protocol: fields,
                num_fields: 0,
                num_bits: 0,
            };
        }
        let mut bit_count = 0;
        let mut field_type = if poswise_ents[0] == 0.0 {
            ProtoField::Fixed
        } else if poswise_ents[0] < eps {
            ProtoField::Ambiguous
        } else {
            ProtoField::Varying
        };
        let mut count: u32 = 0;
        for ent in poswise_ents {
            let ent_type = if *ent == 0.0 {
                ProtoField::Fixed
            } else if *ent < eps {
                ProtoField::Ambiguous
            } else {
                ProtoField::Varying
            };
            if ent_type == field_type {
                count += 1;
            } else {
                bit_count += count;
                fields.push((field_type, count));
                count = 1;
                field_type = ent_type;
            }
        }
        bit_count += count;
        fields.push((field_type, count));
        let field_count = fields.len();
        ProtocolStructure {
            protocol: fields,
            num_fields: field_count,
            num_bits: bit_count as usize,
        }
    }
    /// Returns a summary in a HashMap with the count of each type of field
    pub fn summarize(&self) -> HashMap<ProtoField, u32> {
        let mut summary = HashMap::from([
            (ProtoField::Fixed, 0),
            (ProtoField::Varying, 0),
            (ProtoField::Ambiguous, 0),
        ]);
        for (fd, ct) in self.protocol.iter() {
            summary.entry(*fd).and_modify(|t| *t += ct);
        }
        summary
    }
} // impl ProtocolStructure
/// Pull out only the varying/ambiguous bits from a Bitstream
pub fn extract_varying(bs: &Bitstream, ps: &ProtocolStructure) -> Result<String, BitkitError> {
    if bs.len() != ps.get_num_bits() {
        return Err(BitkitError::LengthMismatch(bs.len(), ps.get_num_bits()));
    }
    let num_varying: u32 = ps
        .summarize()
        .iter()
        .filter(|(fd, _)| **fd == ProtoField::Varying || **fd == ProtoField::Ambiguous)
        .map(|(_, ct)| ct)
        .sum();
    let mut locs: Vec<usize> = Vec::with_capacity(num_varying as usize);
    let mut idx_ctr = 0;
    for (field, count) in ps.get_fields().iter() {
        match field {
            ProtoField::Fixed => idx_ctr += count,
            ProtoField::Ambiguous | ProtoField::Varying => {
                for idx in idx_ctr..idx_ctr + count {
                    locs.push(idx as usize);
                }
                idx_ctr += count;
            }
        } // end match
    }
    Ok(locs
        .iter()
        .map(|&ii| {
            let bit = bs.bit_at(ii);
            if bit == 1 {
                '1'
            } else {
                '0'
            }
        })
        .collect::<String>())
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_infer_struct() {
        use crate::positionwise_entropy;
        let bits = vec![
            Bitstream::new("1000101110".to_string()).unwrap(),
            Bitstream::new("1001100010".to_string()).unwrap(),
            Bitstream::new("1001100010".to_string()).unwrap(),
            Bitstream::new("1000101110".to_string()).unwrap(),
            Bitstream::new("1000101110".to_string()).unwrap(),
            Bitstream::new("1000101110".to_string()).unwrap(),
            Bitstream::new("1001100010".to_string()).unwrap(),
            Bitstream::new("1000101110".to_string()).unwrap(),
            Bitstream::new("1000101110".to_string()).unwrap(),
            Bitstream::new("1001100010".to_string()).unwrap(),
            Bitstream::new("1000101110".to_string()).unwrap(),
            Bitstream::new("1001100010".to_string()).unwrap(),
            Bitstream::new("1001100010".to_string()).unwrap(),
            Bitstream::new("1000101110".to_string()).unwrap(),
            Bitstream::new("1000101110".to_string()).unwrap(),
        ];
        let ents = positionwise_entropy(&bits);
        let ps = ProtocolStructure::infer_structure(&ents);
        let expected = vec![
            (ProtoField::Fixed, 3),
            (ProtoField::Varying, 1),
            (ProtoField::Fixed, 2),
            (ProtoField::Varying, 2),
            (ProtoField::Fixed, 2),
        ];
        assert_eq!(ps.get_fields(), expected);
        assert_eq!(
            ps.summarize(),
            HashMap::from([
                (ProtoField::Fixed, 7),
                (ProtoField::Varying, 3),
                (ProtoField::Ambiguous, 0)
            ])
        );
        let varying = extract_varying(&bits[0], &ps);
        assert!(varying.is_ok());
        assert_eq!(varying.unwrap(), "011".to_string());
    }
} // mod tests
