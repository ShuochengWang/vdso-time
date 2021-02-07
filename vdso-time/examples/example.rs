#[cfg(feature = "std")]

include!("common.in");

fn main() {
    example();
}

#[cfg(not(feature = "std"))]
fn main() {}
