use qlink_game::{profile::SteamBypassPolicy, GameProfile};

#[test]
fn steam_bypass_categories_are_not_protected_by_default_profiles() {
    let profile = GameProfile::from_toml_str(
        r#"
        id = "default-game"
        display_name = "Default Game"
        executables = ["default-game"]
        udp_ports = [27015]
        lan_discovery = true
        voice_chat_safe = true
        low_latency = true
        "#,
    )
    .expect("profile parses");

    let policy = SteamBypassPolicy::default();

    for category in [
        "steam_account",
        "steam_store",
        "steam_wallet",
        "steam_checkout",
        "steam_inventory",
        "steam_marketplace",
        "steam_launcher",
        "steam_embedded_browser",
        "steam_updates",
        "steam_login",
    ] {
        assert!(
            !policy.protects_category(&profile, category),
            "{category} must remain bypassed for default profiles"
        );
    }
}

#[test]
fn steam_bypass_config_matches_production_safe_defaults() {
    let policy =
        SteamBypassPolicy::from_toml_str(include_str!("../../../config/steam-bypass.toml"))
            .expect("steam bypass config parses");

    assert_eq!(policy.default_action(), "bypass");
    assert_eq!(policy.protect_overlay_cidr(), "100.64.0.0/10");
    assert!(policy.protect_game_profile_routes());
    assert!(policy.full_tunnel_requires_explicit_underlay_exemptions());
    assert_eq!(
        policy.bypass_categories(),
        &[
            "account",
            "store",
            "wallet",
            "checkout",
            "inventory",
            "marketplace",
            "launcher",
            "embedded_browser",
            "updates",
            "login",
        ]
    );
}
