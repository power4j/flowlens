//! Bounded capture-only TCP prefix recovery. Sequence arithmetic is modulo 2^32.
use crate::domain_parse::DomainReason;

pub(crate) const RAW_BUDGET: usize = 128 * 1024;
const MAX_INTERVALS: usize = 64;

struct Segment {
    offset: i32,
    bytes: Box<[u8]>,
}

#[derive(Default)]
pub(crate) struct TcpPrefix {
    origin: Option<u32>,
    fixed_origin: bool,
    segments: Vec<Segment>,
    contiguous: usize,
    parsed_contiguous: usize,
}

impl TcpPrefix {
    pub(crate) fn origin_unset(&self) -> bool {
        self.origin.is_none()
    }
    pub(crate) fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }
    pub(crate) fn is_tls(&self) -> bool {
        self.segments
            .first()
            .is_some_and(|segment| segment.offset == 0 && segment.bytes.first() == Some(&22))
    }
    pub(crate) fn with_origin(origin: Option<u32>) -> Self {
        Self {
            origin,
            fixed_origin: origin.is_some(),
            ..Self::default()
        }
    }

    /// Includes reserved parser scratch: contiguous copy and handshake body copy.
    /// Reserving all three together prevents transient allocations bypassing limits.
    pub(crate) fn allocation(&self) -> usize {
        self.segments
            .iter()
            .map(|segment| segment.bytes.len())
            .sum::<usize>()
            * 3
            + self.segments.capacity() * std::mem::size_of::<Segment>()
    }

    pub(crate) fn has_gap(&self) -> bool {
        self.segments
            .iter()
            .any(|segment| segment.offset as usize > self.contiguous)
    }

    pub(crate) fn insert(
        &mut self,
        sequence: u32,
        bytes: &[u8],
        available: usize,
    ) -> Result<bool, DomainReason> {
        if bytes.is_empty() {
            return Ok(false);
        }
        let origin = *self.origin.get_or_insert(sequence);
        let mut offset = sequence.wrapping_sub(origin) as i32;
        if offset < 0 {
            if self.fixed_origin {
                return Err(DomainReason::GenerationAmbiguous);
            }
            if offset.unsigned_abs() as usize > RAW_BUDGET {
                return Err(DomainReason::PerFlowBudget);
            }
            for segment in &mut self.segments {
                segment.offset -= offset;
            }
            self.origin = Some(sequence);
            self.contiguous = 0;
            self.parsed_contiguous = 0;
            offset = 0;
        }
        let end = offset as usize + bytes.len();
        if end > RAW_BUDGET {
            return Err(DomainReason::PerFlowBudget);
        }
        for segment in &self.segments {
            let start = (offset as usize).max(segment.offset as usize);
            let overlap_end = end.min(segment.offset as usize + segment.bytes.len());
            if start < overlap_end
                && bytes[start - offset as usize..overlap_end - offset as usize]
                    != segment.bytes
                        [start - segment.offset as usize..overlap_end - segment.offset as usize]
            {
                return Err(DomainReason::OverlapConflict);
            }
        }
        // Store only uncovered slices; retransmits consume traffic but no raw budget.
        let mut uncovered = Vec::new();
        let mut cursor = offset as usize;
        for segment in &self.segments {
            let segment_start = segment.offset as usize;
            let segment_end = segment_start + segment.bytes.len();
            if segment_end <= cursor {
                continue;
            }
            if segment_start >= end {
                break;
            }
            if segment_start > cursor {
                uncovered.push((cursor, segment_start.min(end)));
            }
            cursor = cursor.max(segment_end);
        }
        if cursor < end {
            uncovered.push((cursor, end));
        }
        let additional = uncovered
            .iter()
            .map(|(start, end)| end - start)
            .sum::<usize>();
        let count = self.segments.len() + uncovered.len();
        if count > MAX_INTERVALS {
            return Err(DomainReason::PerFlowBudget);
        }
        let reserve = additional * 3
            + count.saturating_sub(self.segments.capacity()) * std::mem::size_of::<Segment>();
        if self.allocation() + reserve > RAW_BUDGET {
            return Err(DomainReason::PerFlowBudget);
        }
        if reserve > available {
            return Err(DomainReason::GlobalBudgetEvicted);
        }
        self.segments
            .reserve_exact(count.saturating_sub(self.segments.len()));
        for (start, end) in uncovered {
            self.segments.push(Segment {
                offset: start as i32,
                bytes: bytes[start - offset as usize..end - offset as usize].into(),
            });
        }
        self.segments.sort_by_key(|segment| segment.offset);
        let mut index = 0;
        while index + 1 < self.segments.len() {
            if self.segments[index].offset as usize + self.segments[index].bytes.len()
                == self.segments[index + 1].offset as usize
            {
                let next = self.segments.remove(index + 1);
                let current = &mut self.segments[index];
                let mut joined = Vec::with_capacity(current.bytes.len() + next.bytes.len());
                joined.extend_from_slice(&current.bytes);
                joined.extend_from_slice(&next.bytes);
                current.bytes = joined.into_boxed_slice();
            } else {
                index += 1;
            }
        }
        let before = self.contiguous;
        self.contiguous = 0;
        for segment in &self.segments {
            if segment.offset as usize != self.contiguous {
                break;
            }
            self.contiguous += segment.bytes.len();
        }
        Ok(self.contiguous > before)
    }

    pub(crate) fn fresh_prefix(&mut self) -> Option<Vec<u8>> {
        if self.contiguous == self.parsed_contiguous {
            return None;
        }
        self.parsed_contiguous = self.contiguous;
        let mut prefix = Vec::with_capacity(self.contiguous);
        for segment in &self.segments {
            if segment.offset as usize >= self.contiguous {
                break;
            }
            prefix.extend_from_slice(&segment.bytes);
        }
        Some(prefix)
    }
}
