use super::{NativeRouter, invalid_state};
use rmcp::ErrorData;
use serde_json::{Value, json};
use sha2::Digest as _;
use std::time::{Duration, Instant};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

#[derive(Clone)]
pub(super) struct Route {
    pub server: String,
    generation: u32,
    hash: String,
    state: Option<String>,
    task: Option<String>,
    public_task_id: Option<String>,
    last_updated: Option<OffsetDateTime>,
    inputs: Vec<String>,
    rounds: u8,
    expires: Instant,
}

fn fingerprint(body: &Value) -> String {
    let mut body = body.clone();
    if let Some(params) = body["params"].as_object_mut() {
        for key in ["_meta", "requestState", "inputResponses"] {
            params.remove(key);
        }
    }
    // serde_json's maps use sorted keys.
    hex::encode(sha2::Sha256::digest(body.to_string().as_bytes()))
}

impl NativeRouter {
    pub(super) fn lookup(&self, token: &str, task: bool) -> Result<Route, ErrorData> {
        self.routes
            .lock()
            .get(token)
            .filter(|route| route.expires > Instant::now() && route.task.is_some() == task)
            .cloned()
            .ok_or_else(invalid_state)
    }

    pub(super) fn prepare(
        &self,
        server: &str,
        generation: u32,
        body: &mut Value,
    ) -> Result<Route, ErrorData> {
        let task = body["method"]
            .as_str()
            .is_some_and(|method| method.starts_with("tasks/"));
        let key = if task { "taskId" } else { "requestState" };
        if let Some(token) = body["params"][key].as_str() {
            let route = self.lookup(token, task)?;
            if route.server != server
                || route.generation != generation
                || (!task && route.hash != fingerprint(body))
            {
                return Err(invalid_state());
            }
            if !task
                && body["params"]["inputResponses"]
                    .as_object()
                    .is_some_and(|inputs| inputs.keys().any(|id| !route.inputs.contains(id)))
            {
                return Err(invalid_state());
            }
            if let Some(state) = if task { &route.task } else { &route.state } {
                body["params"][key] = json!(state);
            } else if let Some(params) = body["params"].as_object_mut() {
                params.remove(key);
            }
            return Ok(route);
        }
        if task || body["params"].get("inputResponses").is_some() {
            return Err(invalid_state());
        }
        Ok(Route {
            server: server.into(),
            generation,
            hash: fingerprint(body),
            state: None,
            task: None,
            public_task_id: None,
            last_updated: None,
            inputs: Vec::new(),
            rounds: 0,
            expires: Instant::now() + Duration::from_mins(15),
        })
    }

    fn store(&self, mut route: Route) -> Result<(String, Instant), ErrorData> {
        let mut routes = self.routes.lock();
        let now = Instant::now();
        // Polls and notifications must update the same public handle. An in-flight
        // update cannot re-create an evicted task or extend a reused upstream ID.
        let existing = if let Some(token) = &route.public_task_id {
            Some(routes.get_mut(token).ok_or_else(invalid_state)?)
        } else if let Some(task) = &route.task {
            routes.values_mut().find(|entry| {
                entry.server == route.server
                    && entry.generation == route.generation
                    && entry.task.as_ref() == Some(task)
                    && entry.expires > now
            })
        } else {
            None
        };
        if let Some(entry) = existing {
            if route.last_updated >= entry.last_updated {
                entry.expires = route.expires;
                entry.last_updated = route.last_updated;
            }
            if entry.expires <= now {
                return Err(invalid_state());
            }
            return Ok((
                entry.public_task_id.clone().ok_or_else(invalid_state)?,
                entry.expires,
            ));
        }
        if route.expires <= now {
            return Err(invalid_state());
        }
        routes.retain(|_, entry| entry.expires > now);
        if routes.len() >= 10_000 {
            return Err(ErrorData::internal_error(
                "routing state capacity reached",
                None,
            ));
        }
        let token = uuid::Uuid::new_v4().to_string();
        if route.task.is_some() {
            route.public_task_id = Some(token.clone());
        }
        let expires = route.expires;
        routes.insert(token.clone(), route);
        Ok((token, expires))
    }

    pub(super) fn wrap(&self, route: &Route, result: &mut Value) -> Result<(), ErrorData> {
        if result["resultType"] == "input_required" {
            let mut next = route.clone();
            next.task = None;
            next.public_task_id = None;
            next.rounds += 1;
            if next.rounds > 10 {
                return Err(ErrorData::invalid_params(
                    "continuation round limit reached",
                    None,
                ));
            }
            next.state = result["requestState"].as_str().map(str::to_owned);
            if next
                .state
                .as_ref()
                .is_some_and(|state| state.len() > 16_384)
            {
                return Err(invalid_state());
            }
            next.inputs = result["inputRequests"]
                .as_object()
                .map_or_default(|inputs| inputs.keys().cloned().collect());
            if next.inputs.iter().map(String::len).sum::<usize>() > 16_384
                || next.inputs.len() > 128
            {
                return Err(invalid_state());
            }
            result["requestState"] = json!(self.store(next)?.0);
        }
        if let Some(id) = result["taskId"].as_str() {
            if route.task.as_ref().is_some_and(|expected| expected != id) {
                return Err(invalid_state());
            }
            let mut next = route.clone();
            if id.len() > 16_384 {
                return Err(invalid_state());
            }
            next.task = Some(id.into());
            let created = result["createdAt"]
                .as_str()
                .and_then(|v| OffsetDateTime::parse(v, &Rfc3339).ok())
                .ok_or_else(invalid_state)?;
            let age = u64::try_from(
                (OffsetDateTime::now_utc() - created)
                    .whole_milliseconds()
                    .max(0),
            )
            .unwrap_or(u64::MAX);
            let ttl = result["ttlMs"]
                .as_u64()
                .unwrap_or(86_400_000)
                .min(86_400_000);
            let now = Instant::now();
            next.expires = now + Duration::from_millis(ttl.saturating_sub(age));
            next.last_updated = Some(
                result["lastUpdatedAt"]
                    .as_str()
                    .and_then(|v| OffsetDateTime::parse(v, &Rfc3339).ok())
                    .ok_or_else(invalid_state)?,
            );
            let (token, expires) = self.store(next)?;
            let remaining = u64::try_from(expires.saturating_duration_since(now).as_millis())
                .unwrap_or(u64::MAX);
            result["ttlMs"] = json!(age.saturating_add(remaining));
            result["taskId"] = json!(token);
        }
        Ok(())
    }

    pub(super) fn task_route(
        &self,
        token: &str,
        generation: u32,
    ) -> Result<(String, String), ErrorData> {
        let route = self.lookup(token, true)?;
        if route.generation != generation {
            return Err(invalid_state());
        }
        Ok((route.server, route.task.ok_or_else(invalid_state)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervisor::BackendManager;
    use std::sync::Arc;
    use time::Duration as TimeDelta;

    #[test]
    fn task_ttl_updates_preserve_the_handle_and_obey_the_cap() {
        let router = NativeRouter::new(Arc::new(BackendManager::new()), Arc::default());
        let created = OffsetDateTime::now_utc() - TimeDelta::seconds(5);
        let timestamp = |offset| {
            (created + TimeDelta::seconds(offset))
                .format(&Rfc3339)
                .unwrap()
        };
        let mut initial = json!({"taskId":"job","createdAt":timestamp(0),"lastUpdatedAt":timestamp(0),"ttlMs":60000});
        let call = router
            .prepare("worker", 1, &mut json!({"method":"tools/call","params":{}}))
            .unwrap();
        router.wrap(&call, &mut initial).unwrap();
        let token = initial["taskId"].as_str().unwrap();
        let route = router.lookup(token, true).unwrap();

        let mut latest = json!({"taskId":"job","createdAt":timestamp(0),"lastUpdatedAt":timestamp(2),"ttlMs":null});
        router.wrap(&route, &mut latest).unwrap();
        assert_eq!(latest["taskId"], token);
        assert_eq!(latest["ttlMs"], 86_400_000);
        let extended = router.lookup(token, true).unwrap().expires;
        assert!(extended > route.expires);

        let mut delayed = json!({"taskId":"job","createdAt":timestamp(0),"lastUpdatedAt":timestamp(1),"ttlMs":1000});
        router.wrap(&route, &mut delayed).unwrap();
        assert_eq!(extended, router.lookup(token, true).unwrap().expires);

        delayed["taskId"] = json!("job");
        delayed["ttlMs"] = json!(1000);
        delayed["lastUpdatedAt"] = json!(timestamp(5));
        assert!(router.wrap(&route, &mut delayed).is_err());
        assert!(router.lookup(token, true).is_err());
    }
}
