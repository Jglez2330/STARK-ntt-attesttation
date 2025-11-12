use std::u64;

use tracing::trace_span;
use winterfell::{
    Air, AirContext, Assertion, TraceTable, TransitionConstraintDegree,
    math::{FieldElement, ToElements, fields::f64::BaseElement},
};

use crate::{
    air,
    cfg::Cfg,
    exe_path::{JmpType, Step},
};
//Public inputs
pub struct PublicInputs {
    pub start: BaseElement,
    pub end: BaseElement,
    pub nonce: BaseElement,
}

impl ToElements<BaseElement> for PublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        vec![self.start, self.end, self.nonce]
    }
}

pub struct StarkraAir {
    context: AirContext<BaseElement>,
    start: BaseElement,
    end: BaseElement,
    nonce: BaseElement,
}

impl StarkraAir {
    pub fn build_trace(path: Vec<Step>, cfg: Cfg, nonce: u32) -> TraceTable<BaseElement> {
        // columns: nonce, current, stack(top), neighbors..., valid, ret, call
        let max_succ = cfg.max_successors();
        let base_nei = 3;
        let valid_idx = base_nei + max_succ;
        let ret_idx = valid_idx + 1;
        let call_idx = ret_idx + 1;
        let width = call_idx + 1;

        let steps: Vec<Step> = path;
        let real_len = steps.len();
        let length = real_len.max(1).next_power_of_two();

        let mut trace = TraceTable::new(width, length);

        // shadow stack for CALL/RET integrity (stores return addresses)
        let mut sstack: Vec<u32> = Vec::new();

        for r in 0..length {
            let is_real = r < real_len;

            // Current node for this row
            let curr = if is_real {
                steps[r].addrs.get(0).copied().unwrap_or(0)
            } else {
                // repeat last real node for padding
                steps[real_len.saturating_sub(1)]
                    .addrs
                    .get(0)
                    .copied()
                    .unwrap_or(0)
            };

            // --- Apply CALL/RET effect to shadow stack (real rows only) ---
            if is_real {
                match steps[r].jmp_type {
                    JmpType::Call => {
                        // push return address (second addr if present)
                        let ret_addr = steps[r].addrs.get(1).copied().unwrap_or(0);
                        sstack.push(ret_addr);
                    }
                    JmpType::Ret => {
                        // pop (empty -> ignore)
                        let _ = sstack.pop();
                    }
                    _ => {}
                }
            }
            // top of stack after this step
            let top = sstack.last().copied().unwrap_or(0);

            // [0] nonce
            trace.set(0, r, BaseElement::new(nonce as u64));
            // [1] current
            trace.set(1, r, BaseElement::new(curr as u64));
            // [2] stack (shadow stack top AFTER this step)
            trace.set(2, r, BaseElement::new(top as u64));

            // neighbors: successors(curr) for real rows, else zeros
            let succ = if is_real { cfg.successors(curr) } else { &[][..] };
            for i in 0..max_succ {
                let val = if i < succ.len() {
                    BaseElement::new(succ[i] as u64)
                } else {
                    BaseElement::ZERO
                };
                trace.set(base_nei + i, r, val);
            }

            // [valid]
            trace.set(
                valid_idx,
                r,
                if is_real { BaseElement::ONE } else { BaseElement::ZERO },
            );

            // [ret], [call] flags
            let (ret_flag, call_flag) = if is_real {
                match steps[r].jmp_type {
                    JmpType::Ret => (BaseElement::ONE, BaseElement::ZERO),
                    JmpType::Call => (BaseElement::ZERO, BaseElement::ONE),
                    _ => (BaseElement::ZERO, BaseElement::ZERO),
                }
            } else {
                (BaseElement::ZERO, BaseElement::ZERO)
            };
            trace.set(ret_idx, r, ret_flag);
            trace.set(call_idx, r, call_flag);
        }

        trace
    }

    pub fn transition_check<E: FieldElement>(current: &[E], next: &[E]) -> E {
        let width = current.len();
        debug_assert!(width >= 6, "expected: nonce, current, stack, neighbors..., valid, ret, call");

        // indices per layout
        let neighbors_start = 3;
        let valid_idx = width - 3; // [valid]
        // let _ret_idx = width - 2;
        // let _call_idx = width - 1;

        let next_jmp = next[1];

        // product over neighbors: ∏ (next[1] - current[neighbor_i])
        let mut acc = E::ONE;
        for c in neighbors_start..valid_idx {
            acc *= next_jmp - current[c];
        }

        // multiply by is_valid (current row)
        acc * current[valid_idx] * next[valid_idx]
    }
}

impl Air for StarkraAir {
    type BaseField = BaseElement;
    type PublicInputs = PublicInputs;
    fn new(
        trace_info: winterfell::TraceInfo,
        pub_inputs: Self::PublicInputs,
        options: winterfell::ProofOptions,
    ) -> Self {
        let transition_degree_constraint = trace_info.width() - 4;
        let degrees = vec![
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(transition_degree_constraint),
            TransitionConstraintDegree::new(2),
        ];

        let num_assertions = 3;

        let context = AirContext::new(trace_info, degrees, num_assertions, options);

        Self {
            context,
            start: pub_inputs.start,
            end: pub_inputs.end,
            nonce: pub_inputs.nonce,
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        frame: &winterfell::EvaluationFrame<E>,
        periodic_values: &[E],
        result: &mut [E],
    ) {
        // Single-column trace example:
        let curr = frame.current();
        let next = frame.next();
        let length = curr.len();
        result[0] = curr[0] - next[0]; //Check nonce
        result[1] = Self::transition_check(curr, next);
        result[2] = (curr[2] - next[1])*next[length-2];
    }

    fn get_assertions(&self) -> Vec<winterfell::Assertion<Self::BaseField>> {
        let last = self.trace_length() - 1;
        vec![Assertion::single(0, 0, self.nonce),
             Assertion::single(1, 0, self.start),
            Assertion::single(1, last, self.end)]
    }
}
