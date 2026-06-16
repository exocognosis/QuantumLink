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
    assert!(profile.matches_executable("/usr/bin/factorio"));
    assert!(!profile.matches_executable("/usr/bin/steam"));
}
