use std::fs;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JmpType {
    Call,
    Jump,
    Ret,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    pub jmp_type: JmpType,
    /// call -> [jmp_addr, ret_addr]
    /// jump -> [addr]
    /// ret  -> [addr]
    pub addrs: Vec<u32>,
}

/// Parse the execution path text.
/// Returns (steps, initial_node, final_node)
pub fn parse_execution_path(input: &str) -> Result<(Vec<Step>, Option<u32>, Option<u32>), String> {
    let mut steps: Vec<Step> = Vec::new();
    let mut initial_node: Option<u32> = None;
    let mut final_node: Option<u32> = None;

    for (lineno, raw_line) in input.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() { continue; }

        // Detect header tokens anywhere in the line (supports same-line initial & final)
        let mut header_found = false;
        for tok in line.split_whitespace() {
            if let Some(v) = tok.strip_prefix("initial_node=") {
                initial_node = Some(parse_u32(v, lineno + 1)?);
                header_found = true;
                steps.push(Step { jmp_type: JmpType::Jump, addrs: vec![initial_node.expect("Bad initial node format")] });
            } else if let Some(v) = tok.strip_prefix("final_node=") {
                final_node = Some(parse_u32(v, lineno + 1)?);
                header_found = true;
            }
        }

        // If the line ONLY contains header values, skip opcode parsing
        if header_found && (line.contains("initial_node=") || line.contains("final_node=")) {
            // avoid treating that line as an instruction
            continue;
        }

        // Parse instructions
        let mut it = line.split_whitespace();
        let Some(op) = it.next() else { continue };
        let numbers: Vec<u32> = it
            .map(|t| parse_u32_token(t, lineno + 1))
            .collect::<Result<_, _>>()?;

        match op {
            "call" => {
                if numbers.len() != 2 {
                    return Err(format!("Line {}: 'call' expects 2 numbers", lineno + 1));
                }
                steps.push(Step { jmp_type: JmpType::Call, addrs: numbers });
            }
            "jump" => {
                if numbers.len() != 1 {
                    return Err(format!("Line {}: 'jump' expects 1 number", lineno + 1));
                }
                steps.push(Step { jmp_type: JmpType::Jump, addrs: numbers });
            }
            "ret" => {
                if numbers.len() != 1 {
                    return Err(format!("Line {}: 'ret' expects 1 number", lineno + 1));
                }
                steps.push(Step { jmp_type: JmpType::Ret, addrs: numbers });
            }
            _ => return Err(format!("Line {}: unknown opcode '{}'", lineno + 1, op)),
        }
    }

    Ok((steps, initial_node, final_node))
}

fn parse_u32(s: &str, lineno: usize) -> Result<u32, String> {
    s.trim().parse::<u32>().map_err(|e| {
        format!("Line {}: invalid number '{}': {}", lineno, s.trim(), e)
    })
}

fn parse_u32_token(tok: &str, lineno: usize) -> Result<u32, String> {
    tok.parse::<u32>().map_err(|e| {
        format!("Line {}: invalid number '{}': {}", lineno, tok, e)
    })
}

/// Load file and parse
pub fn parse_execution_path_file(path: &str)
    -> Result<(Vec<Step>, Option<u32>, Option<u32>), String>
{
    let contents = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read '{}': {}", path, e))?;

    parse_execution_path(&contents)
}

