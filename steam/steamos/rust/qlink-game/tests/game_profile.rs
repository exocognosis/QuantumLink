use qlink_game::GameProfile;

#[test]
fn parses_game_profile_and_matches_executable_basename() {
    let profile = GameProfile::from_toml_str(
        r#"
        id = "factorio"
        display_name = "Factorio"
        executables = ["factorio"]
        udp_ports = [34197]
        lan_discovery = true
        voice_chat_safe = true
        low_latency = true
        "#,
    )
    .expect("profile parses");

    assert_eq!(profile.id, "factorio");
    assert_eq!(profile.display_name, "Factorio");
    assert_eq!(profile.udp_ports, vec![34197]);
    assert!(profile.lan_discovery);
    assert!(profile.voice_chat_safe);
    assert!(profile.low_latency);
    assert!(profile.validate().is_ok());
    assert!(profile.matches_executable("/usr/bin/factorio"));
    assert!(!profile.matches_executable("/usr/bin/steam"));
}

#[test]
fn rejects_unsafe_profile_identifiers_and_executable_paths() {
    let mut profile = GameProfile::from_toml_str(
        r#"
        id = "factorio"
        display_name = "Factorio"
        executables = ["factorio"]
        udp_ports = [34197]
        lan_discovery = true
        voice_chat_safe = true
        low_latency = true
        "#,
    )
    .unwrap();

    profile.id = "../factorio".to_string();
    assert!(profile.validate().is_err());
    profile.id = "factorio".to_string();
    profile.executables = vec!["/usr/bin/factorio".to_string()];
    assert!(profile.validate().is_err());
}
