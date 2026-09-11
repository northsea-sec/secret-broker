//! Performance Monitor Module
//!
//! Monitors and reports performance metrics for the crypto-engine service,
//! tracking operation latency, throughput, and resource usage

use prometheus::{
    register_counter_vec, register_gauge_vec, register_histogram_vec, CounterVec, GaugeVec,
    HistogramVec,
};
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use tokio::sync::RwLock;
use tracing::{debug, info};

/// Prometheus collectors registered once in the global default registry.
/// Cloned into each PerformanceMonitor instance (the underlying collectors are
/// Arc-based, so clones share the same counter/gauge state).
struct GlobalMetrics {
    operation_count: CounterVec,
    operation_duration: HistogramVec,
    active_operations: GaugeVec,
    error_count: CounterVec,
    memory_usage: GaugeVec,
    cpu_usage: GaugeVec,
}

static GLOBAL_METRICS: OnceLock<GlobalMetrics> = OnceLock::new();

fn global_metrics() -> &'static GlobalMetrics {
    GLOBAL_METRICS.get_or_init(|| GlobalMetrics {
        operation_count: register_counter_vec!(
            "crypto_engine_operations_total",
            "Total number of crypto operations performed",
            &["operation_type", "algorithm", "result"]
        )
        .expect("register crypto_engine_operations_total"),
        operation_duration: register_histogram_vec!(
            "crypto_engine_operation_duration_seconds",
            "Duration of crypto operations",
            &["operation_type", "algorithm"]
        )
        .expect("register crypto_engine_operation_duration_seconds"),
        active_operations: register_gauge_vec!(
            "crypto_engine_active_operations",
            "Number of currently active operations",
            &["operation_type"]
        )
        .expect("register crypto_engine_active_operations"),
        error_count: register_counter_vec!(
            "crypto_engine_errors_total",
            "Total number of crypto operation errors",
            &["operation_type", "error_type"]
        )
        .expect("register crypto_engine_errors_total"),
        memory_usage: register_gauge_vec!(
            "crypto_engine_memory_usage_bytes",
            "Memory usage of crypto engine",
            &["component"]
        )
        .expect("register crypto_engine_memory_usage_bytes"),
        cpu_usage: register_gauge_vec!(
            "crypto_engine_cpu_usage_percent",
            "CPU usage of crypto engine",
            &["component"]
        )
        .expect("register crypto_engine_cpu_usage_percent"),
    })
}

/// Performance metrics for crypto operations
#[derive(Debug, Clone)]
pub struct PerformanceMetrics {
    pub operation_count: u64,
    pub total_latency_ms: f64,
    pub average_latency_ms: f64,
    pub min_latency_ms: f64,
    pub max_latency_ms: f64,
}

/// Performance monitor for crypto operations
pub struct PerformanceMonitor {
    operation_count: CounterVec,
    operation_duration: HistogramVec,
    active_operations: GaugeVec,
    error_count: CounterVec,
    memory_usage: GaugeVec,
    cpu_usage: GaugeVec,
    metrics_cache: Arc<RwLock<HashMap<String, PerformanceMetrics>>>,
}

impl PerformanceMonitor {
    /// Create new performance monitor
    pub async fn new() -> Result<Self, anyhow::Error> {
        info!("Initializing PerformanceMonitor");

        let g = global_metrics();
        let monitor = Self {
            operation_count: g.operation_count.clone(),
            operation_duration: g.operation_duration.clone(),
            active_operations: g.active_operations.clone(),
            error_count: g.error_count.clone(),
            memory_usage: g.memory_usage.clone(),
            cpu_usage: g.cpu_usage.clone(),
            metrics_cache: Arc::new(RwLock::new(HashMap::new())),
        };

        info!("PerformanceMonitor initialized successfully");
        Ok(monitor)
    }

    /// Record operation performance
    pub async fn record_operation(
        &self,
        operation_type: &str,
        duration_ms: f64,
    ) -> Result<(), anyhow::Error> {
        // Record in Prometheus
        self.operation_duration
            .with_label_values(&[operation_type, "unknown"])
            .observe(duration_ms / 1000.0); // Convert to seconds

        // Update metrics cache
        let mut cache = self.metrics_cache.write().await;
        let metrics = cache
            .entry(operation_type.to_string())
            .or_insert(PerformanceMetrics {
                operation_count: 0,
                total_latency_ms: 0.0,
                average_latency_ms: 0.0,
                min_latency_ms: f64::MAX,
                max_latency_ms: 0.0,
            });

        metrics.operation_count += 1;
        metrics.total_latency_ms += duration_ms;
        metrics.average_latency_ms = metrics.total_latency_ms / metrics.operation_count as f64;
        metrics.min_latency_ms = metrics.min_latency_ms.min(duration_ms);
        metrics.max_latency_ms = metrics.max_latency_ms.max(duration_ms);

        debug!("Recorded {} operation: {}ms", operation_type, duration_ms);
        Ok(())
    }

    /// Record operation count
    pub async fn record_operation_count(
        &self,
        operation_type: &str,
        algorithm: &str,
        result: &str,
    ) -> Result<(), anyhow::Error> {
        self.operation_count
            .with_label_values(&[operation_type, algorithm, result])
            .inc();

        Ok(())
    }

    /// Record error
    pub async fn record_error(
        &self,
        operation_type: &str,
        error_type: &str,
    ) -> Result<(), anyhow::Error> {
        self.error_count
            .with_label_values(&[operation_type, error_type])
            .inc();

        Ok(())
    }

    /// Update active operations
    pub async fn update_active_operations(
        &self,
        operation_type: &str,
        count: i64,
    ) -> Result<(), anyhow::Error> {
        self.active_operations
            .with_label_values(&[operation_type])
            .add(count as f64);

        Ok(())
    }

    /// Update memory usage
    pub async fn update_memory_usage(
        &self,
        component: &str,
        bytes: u64,
    ) -> Result<(), anyhow::Error> {
        self.memory_usage
            .with_label_values(&[component])
            .set(bytes as f64);

        Ok(())
    }

    /// Update CPU usage
    pub async fn update_cpu_usage(
        &self,
        component: &str,
        percentage: f64,
    ) -> Result<(), anyhow::Error> {
        self.cpu_usage
            .with_label_values(&[component])
            .set(percentage);

        Ok(())
    }

    /// Report metrics
    pub async fn report_metrics(&self) -> Result<(), anyhow::Error> {
        debug!("Reporting performance metrics");

        // This would typically send metrics to monitoring systems
        // For now, we'll just log summary statistics

        let cache = self.metrics_cache.read().await;
        for (operation_type, metrics) in cache.iter() {
            if metrics.operation_count > 0 {
                info!(
                    "Performance metrics for {}: count={}, avg={}ms, min={}ms, max={}ms",
                    operation_type,
                    metrics.operation_count,
                    metrics.average_latency_ms,
                    metrics.min_latency_ms,
                    metrics.max_latency_ms
                );
            }
        }

        Ok(())
    }

    /// Get metrics for operation type
    pub async fn get_metrics(
        &self,
        operation_type: &str,
    ) -> Result<Option<PerformanceMetrics>, anyhow::Error> {
        let cache = self.metrics_cache.read().await;
        Ok(cache.get(operation_type).cloned())
    }
}
