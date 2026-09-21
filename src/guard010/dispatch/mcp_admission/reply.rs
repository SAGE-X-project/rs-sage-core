use super::*;
use crate::guard010::mcp_owned::{result_evidence, wire_id, Accepted};
use crate::guard010::mcp_setup::SetupIO;
use serde_json::json;

/// Kept inside the sole authenticated owner, never supplied by the peer/caller.
pub(crate) struct ProtectedReply {
    pub(super) operation: Arc<()>,
    pub(super) started: Stamp,
    pub(super) deadline: i64,
    pub(super) inner: String,
    pub(super) outer: String,
    pub(super) receipt: DispatchReceipt,
}
impl MCPGate {
    pub(crate) fn reply(
        &self,
        owner: &mut MCPSetup,
        endpoint: &mut CompletionEndpoint010,
        io: &mut dyn SetupIO,
        signer: &mut dyn ResultSigner,
    ) -> Result<()> {
        let mut held = None;
        let result = catch_unwind(AssertUnwindSafe(|| {
            let mut reply = owner.response.take().ok_or(Invalid)?;
            {
                let _c = self.coordinator.lock().map_err(|_| Invalid)?;
                let mut q = self.queue.lock().map_err(|_| Invalid)?;
                ensure(!q.retired && q.outputs < self.capacity)?;
                owner.admission_time(endpoint, &self.coordinator, Some(&reply.operation))?;
                owner.begin_output(&reply.operation)?;
                q.outputs += 1;
                let job = Arc::new(Mutex::new(Job {
                    cancellation: Cancellation::default(),
                    close: owner.closer(),
                    operation: reply.operation.clone(),
                    deadline: reply.deadline,
                    claim_before: None,
                    worker_before: None,
                }));
                q.output_jobs.push(job.clone());
                held = Some(job);
            }
            let raw = {
                let mut s = self.execution.state.lock().map_err(|_| Invalid)?;
                ensure(
                    !s.retired
                        && s.store.is_some()
                        && Arc::ptr_eq(&s.owner, &reply.receipt.reply.owner)
                        && !reply.receipt.reply.used,
                )?;
                reply.receipt.reply.used = true;
                let result = catch_unwind(AssertUnwindSafe(|| {
                    publication::reply(&mut s, &reply.receipt.reply.canonical, signer)
                }));
                let result = match result {
                    Ok(result) => result,
                    Err(_) => {
                        s.retired = true;
                        Err(Invalid)
                    }
                };
                if s.retired {
                    self.retire()?;
                }
                result?
            };
            let mut authority = self.result_authority.lock().map_err(|_| Invalid)?;
            let v = verify_result(
                &raw,
                &mut *authority,
                &mut Accepted(reply.receipt.reply.canonical.clone()),
            )?;
            let result: Value =
                serde_json::from_slice(&v.mcp_result(MCP_VERSION)?).map_err(|_| Invalid)?;
            let rpc =
                serde_json::to_vec(&json!({"jsonrpc":"2.0","id":reply.inner,"result":result}))
                    .map_err(|_| Invalid)?;
            let (local, peer) = owner.owner.participants().map_err(|_| Invalid)?;
            let code = super::super::super::mcp_session::response(
                MCP_VERSION,
                &reply.inner,
                &rpc,
                &reply.receipt.reply.canonical,
                &local,
                &peer,
            )?;
            let wire = owner
                .owner
                .seal_response(endpoint, &reply.outer, &rpc, code, 30)
                .map_err(|_| Invalid)?;
            ensure(
                !wire.is_empty()
                    && wire.len() <= 32768
                    && wire_id(&wire)? != reply.inner
                    && !owner.closer().closed(),
            )?;
            io.send(&wire, reply.deadline, &owner.closer())?;
            let evidence = result_evidence(
                owner,
                endpoint,
                &raw,
                &reply.receipt.reply.canonical,
                &mut authority,
            )?;
            let _c = self.coordinator.lock().map_err(|_| Invalid)?;
            let mut q = self.queue.lock().map_err(|_| Invalid)?;
            ensure(!q.retired)?;
            let now = owner.admission_time(endpoint, &self.coordinator, Some(&reply.operation))?;
            Self::watermark(&mut q, now)?;
            evidence.valid(now, reply.started, reply.deadline)?;
            owner.finish_output(&reply.operation)?;
            owner.finish_operation(&reply.operation)
        }))
        .unwrap_or(Err(Invalid));
        if result.is_err() {
            owner.fail();
        }
        if let Some(job) = held {
            if let Ok(_c) = self.coordinator.lock() {
                if let Ok(mut q) = self.queue.lock() {
                    q.output_jobs.retain(|old| !Arc::ptr_eq(old, &job));
                    q.outputs -= 1;
                }
            }
        }
        result
    }
}
