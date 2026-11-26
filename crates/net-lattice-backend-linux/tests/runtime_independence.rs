#![cfg(target_os = "linux")]

use net_lattice_backend_linux::LinuxBackend;
use net_lattice_model::event::EventFilter;
#[cfg(feature = "async")]
use net_lattice_platform::AsyncEventProvider;
use net_lattice_platform::{EventProvider, InterfaceProvider};

fn exercise_backend() {
    let backend = LinuxBackend::new().expect("open backend inside executor");
    assert!(
        backend
            .interfaces()
            .expect("read interfaces")
            .iter()
            .any(|interface| interface.name == "lo")
    );
    drop(
        backend
            .watch_filtered(EventFilter::none())
            .expect("open watcher"),
    );
    #[cfg(feature = "async")]
    drop(
        backend
            .watch_async(EventFilter::none())
            .expect("open async watcher"),
    );
}

#[test]
fn production_backend_works_inside_tokio() {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(async {
            exercise_backend();
        });
}

#[test]
fn production_backend_works_inside_async_io() {
    async_io::block_on(async {
        exercise_backend();
    });
}
