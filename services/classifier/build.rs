fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_dir = std::env::var("PROTO_DIR")
        .unwrap_or_else(|_| "../../proto".to_string());
    tonic_build::configure()
        .build_server(true)
        .build_client(false)
        .compile(&[format!("{proto_dir}/classifier.proto")], &[proto_dir])?;
    Ok(())
}
