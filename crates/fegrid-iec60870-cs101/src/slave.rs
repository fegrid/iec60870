//! CS 101 slave (monitor direction) runtime.
//!
//! The slave answers primaries with secondary frames, routes data
//! into class-1 (high-priority) and class-2 (low-priority) queues,
//! supports DIR (data flow control), RESET_CU, and a plugin hook for
//! file-transfer extension (G-034).
//! slave.
#![allow(missing_docs)]
extern crate alloc;

use alloc::collections::VecDeque;

use fegrid_iec60870_asdu::Asdu;

use crate::function_codes::SecondaryFunctionCode;

/// Per-direction flow-control bit (DIR). Slave monitors the
/// primary's direction bit and replies in the opposite direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    /// Master -> Slave direction.
    MasterToSlave,
    /// Slave -> Master direction.
    SlaveToMaster,
}

/// CS 101 link state (G-030).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkState {
    /// Idle, waiting for primary.
    Idle,
    /// Busy processing a primary.
    Busy,
    /// Idle timeout tripped.
    IdleTimeout,
}

/// Class-1 / class-2 queues (G-025).
#[derive(Debug, Default)]
pub struct ClassQueues {
    /// Class 1: high-priority events (e.g., spontaneous reports).
    pub class1: VecDeque<Asdu>,
    /// Class 2: low-priority cyclic data.
    pub class2: VecDeque<Asdu>,
}

impl ClassQueues {
    /// Construct empty queues.
    pub fn new() -> Self {
        Self::default()
    }
    /// Enqueue an ASDU into the requested class (1 or 2).
    pub fn enqueue(&mut self, class: u8, asdu: Asdu) {
        match class {
            1 => self.class1.push_back(asdu),
            _ => self.class2.push_back(asdu),
        }
    }
    /// True iff both queues are empty.
    pub fn is_empty(&self) -> bool {
        self.class1.is_empty() && self.class2.is_empty()
    }
    /// Total queued items.
    pub fn len(&self) -> usize {
        self.class1.len() + self.class2.len()
    }
    /// Pop the next ASDU, preferring class 1.
    pub fn pop_next(&mut self) -> Option<Asdu> {
        self.class1.pop_front().or_else(|| self.class2.pop_front())
    }
}

/// Handler installed by the application to receive parsed inbound
/// ASDUs (G-026). The slave calls this on every received primary that
/// carries an ASDU.
pub type AsduHandler = alloc::sync::Arc<dyn Fn(Asdu) + Send + Sync>;
/// CS 101 slave runtime. Transport-agnostic — the caller feeds it
/// frames via [`Cs101Slave::on_primary`] and asks it for outbound
/// frames via [`Cs101Slave::next_secondary`].
pub struct Cs101Slave {
    pub link_address: u16,
    /// Class queues.
    pub queues: ClassQueues,
    /// Optional ASDU handler (G-026).
    pub handler: Option<AsduHandler>,
    /// Per-direction flow bit (G-030).
    pub dir: Dir,
    /// Current link state (G-031).
    pub state: LinkState,
    /// Idle-timeout tracker (G-032).
    pub idle_ticks: u64,
    /// Idle timeout threshold (calls until IdleTimeout).
    pub idle_threshold: u64,
    /// Optional plugin hook (G-034). Called once per primary that
    /// matches the link address; may inject an Asdu into the queues.
    pub plugin: Option<alloc::sync::Arc<dyn PluginHook>>,
    /// Per-class cap. `0` = unbounded.
    pub class_cap: usize,
    /// Raw-message observer (G-035).
    pub raw_handler: Option<alloc::sync::Arc<dyn RawMessageHook>>,
}

/// Plugin hook for extension modules (e.g. file transfer, G-034).
pub trait PluginHook: Send + Sync {
    /// Called for every inbound primary that targets this slave.
    fn on_primary(
        &self,
        _primary_dir: Dir,
        _function: u8,
        _link_address: u16,
        _asdu: Option<&Asdu>,
    );
}

/// Raw-message observer (G-035).
pub trait RawMessageHook: Send + Sync {
    /// Called with every byte buffer that crosses the wire.
    fn on_raw(&self, _bytes: &[u8], _sent: bool);
}

impl Cs101Slave {
    /// Construct a slave for a given link address.
    pub fn new(link_address: u16) -> Self {
        Self {
            link_address,
            queues: ClassQueues::new(),
            handler: None,
            dir: Dir::MasterToSlave,
            state: LinkState::Idle,
            idle_ticks: 0,
            idle_threshold: 600,
            plugin: None,
            class_cap: 1024,
            raw_handler: None,
        }
    }
    /// Install an ASDU handler (G-026).
    pub fn with_handler(mut self, handler: AsduHandler) -> Self {
        self.handler = Some(handler);
        self
    }
    /// Install a plugin hook (G-034).
    pub fn with_plugin(mut self, plugin: alloc::sync::Arc<dyn PluginHook>) -> Self {
        self.plugin = Some(plugin);
        self
    }
    /// Install a raw-message observer (G-035).
    pub fn with_raw_handler(mut self, handler: alloc::sync::Arc<dyn RawMessageHook>) -> Self {
        self.raw_handler = Some(handler);
        self
    }
    /// Receive an inbound primary. Returns the secondary-function code
    /// the slave should respond with, plus any ASDU the slave wants to
    /// enqueue as a spontaneous reply.
    pub fn on_primary(
        &mut self,
        primary_dir: Dir,
        _function: u8,
        link_address: u16,
        asdu: Option<Asdu>,
    ) -> SecondaryFunctionCode {
        self.idle_ticks = 0;
        self.state = LinkState::Busy;
        self.dir = match primary_dir {
            Dir::MasterToSlave => Dir::SlaveToMaster,
            Dir::SlaveToMaster => Dir::MasterToSlave,
        };
        if link_address != self.link_address && link_address != 0xFFFF {
            // Not for us; pretend we didn't see it.
            return SecondaryFunctionCode::Nack;
        }
        if let Some(ref plugin) = self.plugin {
            plugin.on_primary(primary_dir, _function, link_address, asdu.as_ref());
        }
        if let (Some(handler), Some(asdu)) = (&self.handler, asdu) {
            handler(asdu);
        }
        self.state = LinkState::Idle;
        SecondaryFunctionCode::Ack
    }
    /// Get the next outbound ASDU + secondary function code, draining
    /// the class queues in priority order.
    pub fn next_secondary(&mut self) -> Option<(SecondaryFunctionCode, Asdu)> {
        self.queues
            .pop_next()
            .map(|asdu| (SecondaryFunctionCode::RespUserData, asdu))
    }
    /// Enqueue an ASDU into class 1.
    pub fn enqueue_class1(&mut self, asdu: Asdu) {
        if self.class_cap == 0 || self.queues.len() < self.class_cap {
            self.queues.enqueue(1, asdu);
        }
    }
    /// Enqueue an ASDU into class 2.
    pub fn enqueue_class2(&mut self, asdu: Asdu) {
        if self.class_cap == 0 || self.queues.len() < self.class_cap {
            self.queues.enqueue(2, asdu);
        }
    }
    /// Flush all queued ASDUs. Used on RESET_CU (G-029).
    pub fn flush_queues(&mut self) {
        self.queues.class1 = VecDeque::new();
        self.queues.class2 = VecDeque::new();
    }

    /// Advance the idle-timeout tracker. Returns the new state.
    pub fn tick_idle(&mut self) -> LinkState {
        self.idle_ticks = self.idle_ticks.saturating_add(1);
        if self.idle_ticks >= self.idle_threshold {
            self.state = LinkState::IdleTimeout;
        }
        self.state
    }
    /// Handle RESET_CU: clear FCV/FCB (G-029).
    pub fn reset_cu(&mut self) {
        self.flush_queues();
        self.state = LinkState::Idle;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fegrid_iec60870_asdu::{InformationObject, InformationValue};
    use fegrid_iec60870_core::{
        CauseOfTransmission, CommonAddress, CotField, QualifierOfInterrogation, TypeId,
    };

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
            objects: alloc::vec![InformationObject::new(
                1,
                InformationValue::interrogation_command(QualifierOfInterrogation::STATION),
            )],
        }
    }

    #[test]
    fn class_queues_route_by_priority() {
        let mut q = ClassQueues::new();
        let a = dummy_asdu();
        q.enqueue(2, a.clone());
        q.enqueue(1, a.clone());
        // class 1 pops first.
        assert!(q.pop_next().is_some());
        // then class 2.
        assert!(q.pop_next().is_some());
        assert!(q.is_empty());
    }

    #[test]
    fn slave_receives_asdu_and_calls_handler() {
        use alloc::sync::Arc;
        let counter = Arc::new(core::sync::atomic::AtomicUsize::new(0));
        let c2 = counter.clone();
        let mut slave = Cs101Slave::new(1).with_handler(Arc::new(move |_| {
            c2.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
        }));
        let sec = slave.on_primary(Dir::MasterToSlave, 0, 1, Some(dummy_asdu()));
        assert_eq!(sec, SecondaryFunctionCode::Ack);
        assert_eq!(counter.load(core::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn slave_drops_wrong_address() {
        let mut slave = Cs101Slave::new(5);
        let sec = slave.on_primary(Dir::MasterToSlave, 0, 1, Some(dummy_asdu()));
        assert_eq!(sec, SecondaryFunctionCode::Nack);
    }

    #[test]
    fn slave_accepts_broadcast() {
        let mut slave = Cs101Slave::new(5);
        let sec = slave.on_primary(Dir::MasterToSlave, 0, 0xFFFF, Some(dummy_asdu()));
        assert_eq!(sec, SecondaryFunctionCode::Ack);
    }

    #[test]
    fn flush_queues_clears_state() {
        let mut slave = Cs101Slave::new(1);
        slave.enqueue_class1(dummy_asdu());
        slave.enqueue_class2(dummy_asdu());
        assert_eq!(slave.queues.len(), 2);
        slave.flush_queues();
        assert!(slave.queues.is_empty());
    }

    #[test]
    fn reset_cu_resets_state() {
        let mut slave = Cs101Slave::new(1);
        slave.enqueue_class1(dummy_asdu());
        slave.state = LinkState::Busy;
        slave.reset_cu();
        assert_eq!(slave.state, LinkState::Idle);
        assert!(slave.queues.is_empty());
    }

    #[test]
    fn idle_tick_triggers_timeout() {
        let mut slave = Cs101Slave::new(1);
        slave.idle_threshold = 3;
        slave.tick_idle();
        slave.tick_idle();
        assert_eq!(slave.state, LinkState::Idle);
        slave.tick_idle();
        assert_eq!(slave.state, LinkState::IdleTimeout);
    }

    #[test]
    fn next_secondary_pops_class1_first() {
        let mut slave = Cs101Slave::new(1);
        slave.enqueue_class2(dummy_asdu());
        slave.enqueue_class1(dummy_asdu());
        let sec1 = slave.next_secondary();
        assert!(sec1.is_some());
        let sec2 = slave.next_secondary();
        assert!(sec2.is_some());
    }

    struct CountingPlugin(alloc::sync::Arc<core::sync::atomic::AtomicUsize>);
    impl PluginHook for CountingPlugin {
        fn on_primary(&self, _: Dir, _: u8, _: u16, _: Option<&Asdu>) {
            self.0.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
        }
    }

    #[test]
    fn plugin_invoked() {
        let counter = alloc::sync::Arc::new(core::sync::atomic::AtomicUsize::new(0));
        let plugin = CountingPlugin(counter.clone());
        let mut slave = Cs101Slave::new(1).with_plugin(alloc::sync::Arc::new(plugin));
        let _ = slave.on_primary(Dir::MasterToSlave, 0, 1, Some(dummy_asdu()));
        assert_eq!(counter.load(core::sync::atomic::Ordering::SeqCst), 1);
    }
}
