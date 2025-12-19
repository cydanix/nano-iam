fn main() {
    // Ensure Cargo recompiles when migration files change
    // This is important because sqlx::migrate!() embeds migrations at compile time
    println!("cargo:rerun-if-changed=src/migrations");
}

