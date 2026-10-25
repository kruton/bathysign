//! Bounded process-local metrics. Never label with URLs, IDs, errors or credentials.
use std::{
    collections::BTreeMap,
    sync::{Mutex, OnceLock},
    time::Instant,
};
#[derive(Default)]
struct Sample {
    count: u64,
    seconds: f64,
    last_success: u64,
    buckets: [u64; 8],
}
static OPERATIONS: OnceLock<Mutex<BTreeMap<(&'static str, bool), Sample>>> = OnceLock::new();

pub fn observe(operation: &'static str, success: bool, start: Instant) {
    let mut samples = OPERATIONS.get_or_init(Default::default).lock().unwrap();
    let sample = samples.entry((operation, success)).or_default();
    let elapsed = start.elapsed().as_secs_f64();
    sample.count += 1;
    for (i, bound) in [1., 5., 30., 60., 300., 600., 1800., f64::INFINITY]
        .iter()
        .enumerate()
    {
        if elapsed <= *bound {
            sample.buckets[i] += 1;
        }
    }
    sample.seconds += elapsed;
    if success {
        sample.last_success = crate::config::now().unwrap_or(0);
    }
}
static ACTIVE_JOB: Mutex<Option<Instant>> = Mutex::new(None);
pub struct ActiveJob;
impl ActiveJob {
    pub fn start() -> Self {
        *ACTIVE_JOB.lock().unwrap() = Some(Instant::now());
        Self
    }
}
impl Drop for ActiveJob {
    fn drop(&mut self) {
        *ACTIVE_JOB.lock().unwrap() = None;
    }
}
pub fn render() -> String {
    let mut out = String::from(
        "# HELP bathysign_operations_total Completed operations by outcome.\n# TYPE bathysign_operations_total counter\n# HELP bathysign_operation_duration_seconds_total Cumulative operation duration.\n# TYPE bathysign_operation_duration_seconds_total counter\n# HELP bathysign_operation_last_success_timestamp_seconds Last successful operation, Unix time.\n# TYPE bathysign_operation_last_success_timestamp_seconds gauge\n",
    );
    out.push_str("# HELP bathysign_operation_duration_seconds Operation duration including network retry waits.\n# TYPE bathysign_operation_duration_seconds histogram\n");
    let active = ACTIVE_JOB.lock().unwrap();
    out.push_str(&format!("# HELP bathysign_job_active Whether the worker is executing a job.\n# TYPE bathysign_job_active gauge\nbathysign_job_active {}\n# HELP bathysign_job_elapsed_seconds Current job runtime, zero when idle.\n# TYPE bathysign_job_elapsed_seconds gauge\nbathysign_job_elapsed_seconds {}\n", u8::from(active.is_some()), active.map(|t| t.elapsed().as_secs_f64()).unwrap_or(0.)));
    let mut samples = OPERATIONS.get_or_init(Default::default).lock().unwrap();
    for operation in [
        "trust_restore",
        "trust_refresh",
        "trust_commit",
        "trust_update",
    ] {
        for success in [false, true] {
            samples.entry((operation, success)).or_default();
        }
    }
    for ((operation, success), sample) in samples.iter() {
        let outcome = if *success { "success" } else { "failure" };
        out.push_str(&format!("bathysign_operations_total{{operation=\"{operation}\",outcome=\"{outcome}\"}} {}\nbathysign_operation_duration_seconds_total{{operation=\"{operation}\",outcome=\"{outcome}\"}} {}\n", sample.count, sample.seconds));
        for (i, bound) in ["1", "5", "30", "60", "300", "600", "1800", "+Inf"]
            .iter()
            .enumerate()
        {
            out.push_str(&format!("bathysign_operation_duration_seconds_bucket{{operation=\"{operation}\",outcome=\"{outcome}\",le=\"{bound}\"}} {}\n", sample.buckets[i]));
        }
        out.push_str(&format!("bathysign_operation_duration_seconds_sum{{operation=\"{operation}\",outcome=\"{outcome}\"}} {}\nbathysign_operation_duration_seconds_count{{operation=\"{operation}\",outcome=\"{outcome}\"}} {}\n", sample.seconds, sample.count));
        if *success {
            out.push_str(&format!("bathysign_operation_last_success_timestamp_seconds{{operation=\"{operation}\"}} {}\n", sample.last_success));
        }
    }
    out
}
pub fn response(body: String) -> ([(axum::http::HeaderName, &'static str); 1], String) {
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
}

/// A stage records failure on early return, including cancellation or panic unwind.
pub struct Stage {
    operation: &'static str,
    start: Instant,
}
impl Stage {
    pub fn new(operation: &'static str) -> Self {
        Self {
            operation,
            start: Instant::now(),
        }
    }
    pub fn next(&mut self, operation: &'static str) {
        observe(self.operation, true, self.start);
        self.operation = operation;
        self.start = Instant::now();
    }
    pub fn complete(self) {
        observe(self.operation, true, self.start);
        std::mem::forget(self);
    }
}
impl Drop for Stage {
    fn drop(&mut self) {
        observe(self.operation, false, self.start);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stage_failure_and_success_export_consistent_histograms() {
        drop(Stage::new("test_failed_stage"));
        Stage::new("test_completed_stage").complete();
        let body = render();
        assert!(body.contains(
            "bathysign_operations_total{operation=\"test_failed_stage\",outcome=\"failure\"} 1"
        ));
        assert!(body.contains("bathysign_operation_duration_seconds_bucket{operation=\"test_completed_stage\",outcome=\"success\",le=\"+Inf\"} 1"));
        assert!(body.contains("bathysign_operation_duration_seconds_count{operation=\"test_completed_stage\",outcome=\"success\"} 1"));
        assert!(!body.contains("operation=\"test_failed_stage\",outcome=\"success\""));
    }
}
