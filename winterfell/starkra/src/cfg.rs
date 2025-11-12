// cfg.rs
use std::fs;

/// Pure CFG stored as adjacency lists.
/// Node IDs are u32, used as direct indices.
/// succ[i] = successors of node i
/// pred[i] = predecessors of node i
#[derive(Debug, Clone)]
pub struct Cfg {
    succ: Vec<Vec<u32>>,
    pred: Vec<Vec<u32>>,
}

impl Cfg {
    /// Build a CFG from an adjacency list: iterator of `(node, successors)`.
    /// Vectors are sized to (max_id + 1). Missing nodes are empty.
    pub fn from_adjacency<I>(adj: I) -> Self
    where
        I: IntoIterator<Item = (u32, Vec<u32>)>,
    {
        let mut raw: Vec<(u32, Vec<u32>)> = Vec::new();
        let mut max_id: u32 = 0;

        // First pass: find max node id
        for (src, vs) in adj {
            if src > max_id { max_id = src; }
            for &v in &vs {
                if v > max_id { max_id = v; }
            }
            raw.push((src, vs));
        }

        let n = (max_id as usize) + 1;
        let mut succ: Vec<Vec<u32>> = vec![Vec::new(); n];

        // Fill successors
        for (src, vs) in raw.into_iter() {
            succ[src as usize] = vs;
        }

        // Build predecessors
        let mut pred: Vec<Vec<u32>> = vec![Vec::new(); n];
        for (u, vs) in succ.iter().enumerate() {
            let u32u = u as u32;
            for &v in vs {
                pred[v as usize].push(u32u);
            }
        }

        Cfg { succ, pred }
    }

    /// Build a CFG from a whitespace-separated adjacency list file.
    /// Each non-empty line: `src dst0 dst1 ...`
    /// Inline comments after '#' allowed.
    pub fn from_file(path: &str) -> Result<Self, String> {
        let contents = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read '{}': {}", path, e))?;

        let mut adj: Vec<(u32, Vec<u32>)> = Vec::new();

        for (lineno, raw) in contents.lines().enumerate() {
            let mut line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(i) = line.find('#') {
                line = &line[..i].trim();
                if line.is_empty() { continue; }
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.is_empty() { continue; }

            let src: u32 = parts[0].parse()
                .map_err(|_| format!("Line {}: invalid node '{}'", lineno + 1, parts[0]))?;

            let mut succs = Vec::new();
            for tok in parts.iter().skip(1) {
                let v = tok.parse::<u32>()
                    .map_err(|_| format!("Line {}: invalid successor '{}'", lineno + 1, tok))?;
                succs.push(v);
            }

            adj.push((src, succs));
        }

        Ok(Self::from_adjacency(adj))
    }

    pub fn len(&self) -> usize { self.succ.len() }
    pub fn is_empty(&self) -> bool { self.succ.is_empty() }

    pub fn nodes(&self) -> impl Iterator<Item = u32> + '_ {
        (0..self.succ.len()).map(|i| i as u32)
    }

    pub fn successors(&self, n: u32) -> &[u32] {
        self.succ.get(n as usize).map(|v| v.as_slice()).unwrap_or(&[])
    }

    pub fn predecessors(&self, n: u32) -> &[u32] {
        self.pred.get(n as usize).map(|v| v.as_slice()).unwrap_or(&[])
    }

    pub fn edges(&self) -> impl Iterator<Item = (u32, u32)> + '_ {
        self.succ.iter().enumerate().flat_map(|(u, vs)| {
            vs.iter().copied().map(move |v| (u as u32, v))
        })
    }

    /// Maximum number of successors among all nodes (out-degree)
    pub fn max_successors(&self) -> usize {
        self.succ.iter().map(|v| v.len()).max().unwrap_or(0)
    }
}
