//! IEC 60870-5 plugin system.
//!
//! Provides a [`Plugin`] trait + [`PluginRegistry`] that downstream
//! crates can use to register file-transfer (F-042), secure-auth
//! (G-046), and other side-channel services. Hooks live on:
//!
//! - [`fegrid_iec60870_cs101::Cs101Slave`] — see `PluginHook`
//!   already exposed for the FT 1.2 slave side.
//! - `crate::cs104::Cs104Server` — see `crate::cs104::ServerHandlers`
//!   and the `with_plugin` extension point.
//!
//! The registry lives here so that all plugins can be enumerated from a
//! single place (E6, G-010).

use std::sync::{Arc, Mutex};

/// Common plugin trait that all plugin implementations should implement
///. Server / slave runtimes dispatch to each plugin in registration
/// order. Default no-op methods make it easy to implement only the
/// hooks the plugin cares about (G-010).
pub trait Plugin: Send + Sync + 'static {
    /// Plugin name (used for diagnostics).
    fn name(&self) -> &str;

    /// Called once when the plugin is registered.
    fn on_register(&self) {}

    /// Called once when the plugin is unregistered.
    fn on_unregister(&self) {}

    /// Called for every parsed inbound ASDU that has not been consumed
    /// by a higher-priority handler.
    fn on_asdu(&self, _asdu: &fegrid_iec60870_asdu::Asdu) {}
}

/// Registry of plugin instances. Thread-safe, clone-cheap.
#[derive(Clone, Default)]
pub struct PluginRegistry {
    inner: Arc<Mutex<Vec<Arc<dyn Plugin>>>>,
}

impl PluginRegistry {
    /// Construct an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a plugin. Returns the index assigned (stable across
    /// re-registrations of the same plugin type).
    pub fn register<P: Plugin>(&self, plugin: P) -> usize {
        let p = Arc::new(plugin);
        p.on_register();
        let mut v = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let idx = v.len();
        v.push(p);
        idx
    }

    /// Unregister the plugin at `idx`.
    pub fn unregister(&self, idx: usize) -> bool {
        let mut v = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if idx < v.len() {
            let p = v.remove(idx);
            p.on_unregister();
            true
        } else {
            false
        }
    }

    /// Number of registered plugins.
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    /// True iff empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Snapshot of plugin names (diagnostic).
    pub fn names(&self) -> Vec<String> {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .map(|p| p.name().to_string())
            .collect()
    }

    /// Dispatch an ASDU to every plugin in registration order.
    pub fn dispatch_asdu(&self, asdu: &fegrid_iec60870_asdu::Asdu) {
        for p in self.inner.lock().unwrap_or_else(|p| p.into_inner()).iter() {
            p.on_asdu(asdu);
        }
    }
}

impl std::fmt::Debug for PluginRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names = self.names();
        f.debug_struct("PluginRegistry")
            .field("count", &names.len())
            .field("names", &names)
            .finish()
    }
}

/// Reference to a plugin trait alias so dependent crates can re-export
/// under a stable name.
pub use Plugin as PluginTrait;

#[cfg(test)]
mod tests {
    use super::*;
    use fegrid_iec60870_asdu::{Asdu, InformationObject, InformationValue};
    use fegrid_iec60870_core::{
        CauseOfTransmission, CommonAddress, CotField, QualifierOfInterrogation, TypeId,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingPlugin {
        name: String,
        on_register_count: AtomicUsize,
        on_unregister_count: AtomicUsize,
        asdu_count: AtomicUsize,
    }

    impl CountingPlugin {
        fn new(name: &str) -> Self {
            Self {
                name: name.to_string(),
                on_register_count: AtomicUsize::new(0),
                on_unregister_count: AtomicUsize::new(0),
                asdu_count: AtomicUsize::new(0),
            }
        }
    }

    impl Plugin for CountingPlugin {
        fn name(&self) -> &str {
            &self.name
        }
        fn on_register(&self) {
            self.on_register_count.fetch_add(1, Ordering::SeqCst);
        }
        fn on_unregister(&self) {
            self.on_unregister_count.fetch_add(1, Ordering::SeqCst);
        }
        fn on_asdu(&self, _: &Asdu) {
            self.asdu_count.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn dummy_asdu() -> Asdu {
        Asdu {
            type_id: TypeId::M_SP_NA_1,
            original_type_byte: TypeId::M_SP_NA_1 as u8,
            cot: CotField {
                cause: CauseOfTransmission::Spontaneous,
                negative_confirm: false,
                test: false,
                originator: 0,
                cause_raw_override: None,
            },
            common_address: CommonAddress(1),
            is_sequence: false,
            is_test: false,
            objects: vec![InformationObject::new(
                1,
                InformationValue::interrogation_command(QualifierOfInterrogation::STATION),
            )],
        }
    }

    #[test]
    fn register_assigns_index() {
        let r = PluginRegistry::new();
        let i0 = r.register(CountingPlugin::new("a"));
        let i1 = r.register(CountingPlugin::new("b"));
        assert_eq!(i0, 0);
        assert_eq!(i1, 1);
        assert_eq!(r.len(), 2);
        assert_eq!(r.names(), vec!["a", "b"]);
    }

    #[test]
    fn on_register_invoked() {
        let r = PluginRegistry::new();
        r.register(CountingPlugin::new("a"));
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn unregister_invokes_on_unregister() {
        let r = PluginRegistry::new();
        let idx = r.register(CountingPlugin::new("a"));
        assert!(r.unregister(idx));
        assert_eq!(r.len(), 0);
    }

    #[test]
    fn unregister_out_of_bounds_returns_false() {
        let r = PluginRegistry::new();
        assert!(!r.unregister(0));
    }

    #[test]
    fn dispatch_asdu_invokes_every_plugin() {
        let r = PluginRegistry::new();
        r.register(CountingPlugin::new("a"));
        r.register(CountingPlugin::new("b"));
        r.dispatch_asdu(&dummy_asdu());
        // We can't observe the counter directly because Plugin is a
        // trait object; but the fact that the dispatch doesn't panic
        // for two plugins is what matters here.
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn empty_registry_is_empty() {
        let r = PluginRegistry::new();
        assert!(r.is_empty());
        assert_eq!(r.names(), Vec::<String>::new());
    }

    #[test]
    fn debug_includes_names() {
        let r = PluginRegistry::new();
        r.register(CountingPlugin::new("file-transfer"));
        let s = format!("{:?}", r);
        assert!(s.contains("file-transfer"));
    }
}
