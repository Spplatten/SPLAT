//! Fixed-record SPSC transport primitive. NOT mapped into Falco/Falcon and not wired to the HTTP
//! sidecar. One producer and one consumer are issued once; cloneable producer handles do not exist.
use std::{cell::{Cell, UnsafeCell}, marker::PhantomData, mem::MaybeUninit,
    sync::{Arc, atomic::{AtomicU64, Ordering}}};

const CAPACITY: usize = 1024;
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AlertRecord {
    pub binding_hi: u64, pub binding_lo: u64,
    pub boot_hi: u64, pub boot_lo: u64,
    pub cgroup: u64, pub start_ticks: u64, pub observed_boot_ns: u64,
    pub pid: u32, pub reason: u32,
}
const _: () = assert!(std::mem::size_of::<AlertRecord>() == 64);
#[repr(align(64))]
struct Counter(AtomicU64);
#[repr(align(64))]
struct Slots(UnsafeCell<[MaybeUninit<AlertRecord>; CAPACITY]>);
struct Ring { head: Counter, tail: Counter, slots: Slots }
// Safety: only Producer writes slots/head, only Consumer reads slots/writes tail. Each handle's
// API requires &mut self. Release/acquire transfers ownership; an unread slot cannot be reused.
// AlertRecord is Copy and has no heap pointers/destructor. Neither handle is Clone or Sync.
unsafe impl Sync for Ring {}
pub struct Producer { ring: Arc<Ring>, _not_sync: PhantomData<Cell<()>> }
pub struct Consumer { ring: Arc<Ring>, _not_sync: PhantomData<Cell<()>> }
pub fn channel() -> (Producer, Consumer) {
    // Exactly one startup Arc allocation; no allocation in either try operation.
    let ring = Arc::new(Ring { head:Counter(AtomicU64::new(0)), tail:Counter(AtomicU64::new(0)),
        slots:Slots(UnsafeCell::new([MaybeUninit::uninit(); CAPACITY])) });
    (Producer { ring:Arc::clone(&ring), _not_sync:PhantomData },
     Consumer { ring, _not_sync:PhantomData })
}
impl Producer {
    pub fn try_push(&mut self, event: AlertRecord) -> Result<(), AlertRecord> {
        let head = self.ring.head.0.load(Ordering::Relaxed);
        let tail = self.ring.tail.0.load(Ordering::Acquire);
        if head.wrapping_sub(tail) >= CAPACITY as u64 { return Err(event); }
        // Slot belongs exclusively to producer until release publication of head.
        unsafe { (*self.ring.slots.0.get())[(head as usize) & (CAPACITY-1)].write(event); }
        self.ring.head.0.store(head.wrapping_add(1), Ordering::Release);
        Ok(())
    }
}
impl Consumer {
    pub fn try_pop(&mut self) -> Option<AlertRecord> {
        let tail = self.ring.tail.0.load(Ordering::Relaxed);
        if tail == self.ring.head.0.load(Ordering::Acquire) { return None; }
        // Acquire observed initialized bytes. Tail is not released until the copy completes.
        let event = unsafe { (*self.ring.slots.0.get())[(tail as usize) & (CAPACITY-1)].assume_init_read() };
        self.ring.tail.0.store(tail.wrapping_add(1), Ordering::Release);
        Some(event)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::alloc::{GlobalAlloc, Layout, System};
    thread_local! { static COUNT: Cell<Option<usize>> = const { Cell::new(None) }; }
    struct Alloc;
    unsafe impl GlobalAlloc for Alloc {
        unsafe fn alloc(&self, layout:Layout)->*mut u8 {
            let _ = COUNT.try_with(|c| if let Some(n)=c.get() { c.set(Some(n+1)); });
            unsafe { System.alloc(layout) }
        }
        unsafe fn dealloc(&self,p:*mut u8,l:Layout) { unsafe { System.dealloc(p,l) } }
    }
    #[global_allocator] static ALLOC:Alloc=Alloc;
    fn event(n:u64)->AlertRecord { AlertRecord { binding_hi:n,binding_lo:0,boot_hi:1,boot_lo:2,
        cgroup:3,start_ticks:4,observed_boot_ns:5,pid:6,reason:7 } }
    #[test] fn empty_and_full_are_explicit() {
        let (mut p,mut c)=channel(); assert!(c.try_pop().is_none());
        for n in 0..CAPACITY { assert!(p.try_push(event(n as u64)).is_ok()); }
        assert_eq!(p.try_push(event(9999)),Err(event(9999)));
        for n in 0..CAPACITY { assert_eq!(c.try_pop(),Some(event(n as u64))); }
        assert!(c.try_pop().is_none());
    }
    #[test] fn hot_operations_allocate_nothing() {
        let (mut p,mut c)=channel(); COUNT.with(|n|n.set(Some(0)));
        for n in 0..100000 { p.try_push(event(n)).unwrap(); assert_eq!(c.try_pop(),Some(event(n))); }
        let count=COUNT.with(|n|n.replace(None)); assert_eq!(count,Some(0));
    }
    #[test] fn counter_wrap_preserves_fifo() {
        let (mut p,mut c)=channel();
        p.ring.head.0.store(u64::MAX-10,Ordering::Relaxed);
        p.ring.tail.0.store(u64::MAX-10,Ordering::Relaxed);
        for n in 0..100 { p.try_push(event(n)).unwrap(); assert_eq!(c.try_pop(),Some(event(n))); }
    }
    #[test] fn concurrent_transfer_preserves_every_record() {
        let (mut p,mut c)=channel();
        let producer=std::thread::spawn(move || for n in 0..100000 {
            while p.try_push(event(n)).is_err() { std::hint::spin_loop(); }
        });
        for n in 0..100000 { loop {
            if let Some(value)=c.try_pop() { assert_eq!(value,event(n)); break; }
            std::hint::spin_loop();
        }}
        producer.join().unwrap();
    }
}
