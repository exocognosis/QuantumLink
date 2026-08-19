use eframe::egui::{
    self, Align, Button, Color32, FontId, Frame, Layout, RichText, ScrollArea, Sense, Stroke,
    TextEdit, Ui, Vec2,
};
use qlink_desktop::{
    execute_request, ControlRequest, ControlResult, ControlSnapshot, IdentityAction, IdentityInput,
    QlinkCtlRunner,
};
use qlink_proto::{
    ConnectionPhase, DataPlanePathChangeReason, DataPlaneState, DytallixTrustDecision,
    DytallixTrustHealth, GameProcessClassificationState, GameProfileInfo,
    GameProfilePortEnforcementState, LocalRegistryBindingState, MeshTrustMode, NetworkPlanState,
    PathKind, PathMtuProbeState, RuntimeCapabilityState, SteamOsRuntimeCapabilities, StoredPeer,
};
use serde_json::Value;
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::Duration;

const BG: Color32 = Color32::from_rgb(18, 20, 23);
const PANEL: Color32 = Color32::from_rgb(26, 29, 33);
const PANEL_ALT: Color32 = Color32::from_rgb(32, 36, 41);
const BORDER: Color32 = Color32::from_rgb(58, 64, 72);
const TEXT: Color32 = Color32::from_rgb(236, 239, 242);
const MUTED: Color32 = Color32::from_rgb(159, 168, 178);
const GREEN: Color32 = Color32::from_rgb(72, 190, 128);
const CYAN: Color32 = Color32::from_rgb(76, 176, 204);
const AMBER: Color32 = Color32::from_rgb(226, 169, 74);
const RED: Color32 = Color32::from_rgb(224, 91, 91);

fn main() -> eframe::Result {
    let game_mode = std::env::args().any(|argument| argument == "--game-mode");
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("QuantumLink SteamOS")
            .with_inner_size([1180.0, 760.0])
            .with_min_inner_size([920.0, 620.0])
            .with_fullscreen(game_mode),
        ..Default::default()
    };
    eframe::run_native(
        "QuantumLink SteamOS",
        options,
        Box::new(move |context| Ok(Box::new(QuantumLinkDesktop::new(context, game_mode)))),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Page {
    Overview,
    Peers,
    Profiles,
    Identity,
    Diagnostics,
}

impl Page {
    const ALL: [Self; 5] = [
        Self::Overview,
        Self::Peers,
        Self::Profiles,
        Self::Identity,
        Self::Diagnostics,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Peers => "Peers",
            Self::Profiles => "Game Profiles",
            Self::Identity => "Dytallix Identity",
            Self::Diagnostics => "Diagnostics",
        }
    }

    fn shifted(self, delta: isize) -> Self {
        let current = Self::ALL
            .iter()
            .position(|page| *page == self)
            .unwrap_or_default() as isize;
        let count = Self::ALL.len() as isize;
        Self::ALL[(current + delta).rem_euclid(count) as usize]
    }
}

struct WorkerResponse {
    result: Result<ControlResult, String>,
}

struct QuantumLinkDesktop {
    page: Page,
    game_mode: bool,
    request_tx: Sender<ControlRequest>,
    response_rx: Receiver<WorkerResponse>,
    busy: bool,
    snapshot: Option<ControlSnapshot>,
    selected_peer_id: Option<String>,
    profile_cursor: usize,
    invite_code: String,
    identity_input: IdentityInput,
    identity_document: Option<Value>,
    diagnostic_output: Option<String>,
    support_bundle_path: String,
    notice: Option<(String, Color32)>,
    confirm_peer_action: Option<(String, bool)>,
}

impl QuantumLinkDesktop {
    fn new(context: &eframe::CreationContext<'_>, game_mode: bool) -> Self {
        configure_style(&context.egui_ctx);
        let (request_tx, request_rx) = mpsc::channel::<ControlRequest>();
        let (response_tx, response_rx) = mpsc::channel::<WorkerResponse>();
        std::thread::Builder::new()
            .name("qlink-desktop-control".to_string())
            .spawn(move || {
                let runner = QlinkCtlRunner::discover();
                while let Ok(request) = request_rx.recv() {
                    let result = execute_request(&runner, request);
                    if response_tx.send(WorkerResponse { result }).is_err() {
                        break;
                    }
                }
            })
            .expect("control worker starts");

        let mut app = Self {
            page: Page::Overview,
            game_mode,
            request_tx,
            response_rx,
            busy: false,
            snapshot: None,
            selected_peer_id: None,
            profile_cursor: 0,
            invite_code: String::new(),
            identity_input: IdentityInput {
                config_file: "/etc/quantumlink/config.json".to_string(),
                state_dir: "/var/lib/quantumlink".to_string(),
                max_peer_ttl_seconds: "120".to_string(),
                ..IdentityInput::default()
            },
            identity_document: None,
            diagnostic_output: None,
            support_bundle_path: default_support_bundle_path(),
            notice: None,
            confirm_peer_action: None,
        };
        app.submit(ControlRequest::Refresh);
        app
    }

    fn submit(&mut self, request: ControlRequest) {
        if self.busy {
            return;
        }
        match self.request_tx.send(request) {
            Ok(()) => {
                self.busy = true;
                self.notice = None;
            }
            Err(_) => {
                self.notice = Some(("Control worker is unavailable".to_string(), RED));
            }
        }
    }

    fn receive_results(&mut self) {
        while let Ok(response) = self.response_rx.try_recv() {
            self.busy = false;
            match response.result {
                Ok(ControlResult::Snapshot(snapshot)) => self.apply_snapshot(snapshot),
                Ok(ControlResult::Action { message, snapshot }) => {
                    self.apply_snapshot(snapshot);
                    self.notice = Some((message, GREEN));
                }
                Ok(ControlResult::Identity { action, document }) => {
                    self.identity_document = Some(document);
                    self.notice = Some((
                        format!("Dytallix {} completed", action.command_name()),
                        GREEN,
                    ));
                }
                Ok(ControlResult::SupportBundle { output, snapshot }) => {
                    self.apply_snapshot(snapshot);
                    self.notice = Some((format!("Support bundle saved to {output}"), GREEN));
                }
                Ok(ControlResult::Diagnostic { output, snapshot }) => {
                    self.apply_snapshot(snapshot);
                    self.diagnostic_output = Some(output);
                    self.notice = Some(("Diagnostic checks completed".to_string(), GREEN));
                }
                Err(error) => self.notice = Some((error, RED)),
            }
        }
    }

    fn apply_snapshot(&mut self, snapshot: ControlSnapshot) {
        let selected = snapshot.peer_store.selected_peer_id.clone();
        if let Some(index) = snapshot
            .daemon
            .as_ref()
            .and_then(|daemon| daemon.game_profile.selected_profile.as_ref())
            .and_then(|selected| {
                snapshot.daemon.as_ref().and_then(|daemon| {
                    daemon
                        .game_profile
                        .available_profiles
                        .iter()
                        .position(|profile| profile.id == selected.id)
                })
            })
        {
            self.profile_cursor = index;
        }
        self.snapshot = Some(snapshot);
        self.selected_peer_id = selected;
    }

    fn sidebar(&mut self, ui: &mut Ui) {
        ui.add_space(10.0);
        ui.label(RichText::new("QUANTUMLINK").size(18.0).strong().color(TEXT));
        ui.label(RichText::new("STEAMOS").size(11.0).strong().color(GREEN));
        ui.add_space(26.0);

        for page in Page::ALL {
            let selected = self.page == page;
            let button = Button::new(RichText::new(page.label()).size(14.0).color(if selected {
                TEXT
            } else {
                MUTED
            }))
            .fill(if selected {
                PANEL_ALT
            } else {
                Color32::TRANSPARENT
            })
            .stroke(if selected {
                Stroke::new(1.0, BORDER)
            } else {
                Stroke::NONE
            })
            .corner_radius(6.0);
            if ui.add_sized([168.0, 44.0], button).clicked() {
                self.page = page;
                self.confirm_peer_action = None;
            }
            ui.add_space(4.0);
        }

        ui.with_layout(Layout::bottom_up(Align::LEFT), |ui| {
            ui.label(RichText::new("PQC gaming mesh").size(11.0).color(MUTED));
            if self.game_mode {
                ui.label(RichText::new("GAME MODE").size(11.0).strong().color(CYAN));
            }
            ui.label(RichText::new("v0.1.0").size(11.0).color(MUTED));
        });
    }

    fn header(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.label(
                    RichText::new(self.page.label())
                        .size(22.0)
                        .strong()
                        .color(TEXT),
                );
                ui.label(
                    RichText::new(self.header_status())
                        .size(12.0)
                        .color(self.header_status_color()),
                );
            });
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let refresh = ui.add_enabled(
                    !self.busy,
                    Button::new("Refresh")
                        .fill(PANEL_ALT)
                        .stroke(Stroke::new(1.0, BORDER))
                        .corner_radius(6.0),
                );
                if refresh.clicked() {
                    self.submit(ControlRequest::Refresh);
                }
                if self.busy {
                    ui.spinner();
                }
            });
        });
    }

    fn header_status(&self) -> String {
        match self
            .snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.daemon.as_ref())
        {
            Some(status) => format!(
                "{} / {}",
                phase_label(status.phase),
                path_label(status.data_plane.transport_path)
            ),
            None => "Service stopped".to_string(),
        }
    }

    fn header_status_color(&self) -> Color32 {
        match self
            .snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.daemon.as_ref())
        {
            Some(status) if status.phase == ConnectionPhase::Connected => GREEN,
            Some(status) if status.phase == ConnectionPhase::Failed => RED,
            Some(_) => AMBER,
            None => MUTED,
        }
    }

    fn overview(&mut self, ui: &mut Ui) {
        let snapshot = self.snapshot.clone();
        ScrollArea::vertical().show(ui, |ui| {
            ui.columns(2, |columns| {
                card(&mut columns[0], "Connection", |ui| {
                    let daemon = snapshot.as_ref().and_then(|value| value.daemon.as_ref());
                    let connected = daemon.is_some_and(|status| {
                        status.phase == ConnectionPhase::Connected
                            && status.data_plane.state == DataPlaneState::Ready
                    });
                    status_row(
                        ui,
                        if connected {
                            "Protected"
                        } else {
                            "Disconnected"
                        },
                        if connected { GREEN } else { MUTED },
                    );
                    ui.add_space(12.0);
                    value_row(ui, "Peer", self.selected_peer_label());
                    value_row(
                        ui,
                        "Path",
                        daemon
                            .map(|status| path_label(status.data_plane.transport_path))
                            .unwrap_or("Unavailable"),
                    );
                    value_row(
                        ui,
                        "Route",
                        daemon
                            .and_then(|status| status.network.route_mode)
                            .map(route_mode_label)
                            .unwrap_or("Game only"),
                    );
                    value_row(
                        ui,
                        "Profile",
                        daemon
                            .and_then(|status| status.game_profile.selected_profile.as_ref())
                            .map(|profile| profile.display_name.as_str())
                            .unwrap_or("No profile selected"),
                    );
                    ui.add_space(14.0);
                    ui.horizontal(|ui| {
                        if connected {
                            if ui
                                .add_enabled(!self.busy, primary_button("Disconnect", RED, 132.0))
                                .clicked()
                            {
                                self.submit(ControlRequest::Disconnect);
                            }
                        } else {
                            let can_connect = self.selected_peer_id.is_some() && !self.busy;
                            if ui
                                .add_enabled(can_connect, primary_button("Connect", GREEN, 132.0))
                                .clicked()
                            {
                                if let Some(peer_id) = self.selected_peer_id.clone() {
                                    self.submit(ControlRequest::Connect { peer_id });
                                }
                            }
                        }
                    });
                });

                card(&mut columns[1], "Live Path", |ui| {
                    let daemon = snapshot.as_ref().and_then(|value| value.daemon.as_ref());
                    let peer = daemon.and_then(|status| status.peers.first());
                    metric_row(
                        ui,
                        "RTT",
                        peer.and_then(|peer| peer.median_rtt_ms)
                            .map(|value| format!("{value} ms"))
                            .unwrap_or_else(|| "--".to_string()),
                    );
                    metric_row(
                        ui,
                        "Jitter",
                        peer.and_then(|peer| peer.jitter_ms)
                            .map(|value| format!("{value} ms"))
                            .unwrap_or_else(|| "--".to_string()),
                    );
                    metric_row(
                        ui,
                        "Packet loss",
                        peer.and_then(|peer| peer.packet_loss_percent)
                            .map(|value| format!("{value:.1}%"))
                            .unwrap_or_else(|| "--".to_string()),
                    );
                    metric_row(
                        ui,
                        "Relay privacy",
                        peer.map(|peer| yes_no(peer.relay_privacy))
                            .unwrap_or("--")
                            .to_string(),
                    );
                    let stability = daemon.map(|status| &status.data_plane.flow_stability);
                    metric_row(
                        ui,
                        "Active flows",
                        stability
                            .map(|status| status.active_flow_count.to_string())
                            .unwrap_or_else(|| "--".to_string()),
                    );
                    metric_row(
                        ui,
                        "Path MTU",
                        stability
                            .and_then(|status| status.path_mtu)
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "--".to_string()),
                    );
                    metric_row(
                        ui,
                        "Last change",
                        stability
                            .and_then(|status| status.last_path_change_reason)
                            .map(path_change_reason_label)
                            .unwrap_or("--")
                            .to_string(),
                    );
                    metric_row(
                        ui,
                        "MTU probe",
                        stability
                            .map(|status| path_mtu_probe_state_label(status.mtu_probe_state))
                            .unwrap_or("--")
                            .to_string(),
                    );
                });
            });
            ui.add_space(14.0);
            ui.columns(2, |columns| {
                card(&mut columns[0], "Protection", |ui| {
                    let daemon = snapshot.as_ref().and_then(|value| value.daemon.as_ref());
                    value_row(
                        ui,
                        "Kill switch",
                        daemon
                            .map(|status| yes_no(status.kill_switch))
                            .unwrap_or("On"),
                    );
                    value_row(ui, "Steam account traffic", "Bypassed");
                    value_row(ui, "Steam commerce traffic", "Bypassed");
                    value_row(ui, "Packet routing", "Per flow");
                    value_row(ui, "Process injection", "Disabled");
                });
                card(&mut columns[1], "Dytallix Trust", |ui| {
                    let binding = snapshot
                        .as_ref()
                        .and_then(|value| value.daemon.as_ref())
                        .map(|daemon| &daemon.publication.local_registry_binding);
                    let remote = snapshot
                        .as_ref()
                        .and_then(|value| value.daemon.as_ref())
                        .map(|daemon| &daemon.publication.remote_peer_trust);
                    value_row(
                        ui,
                        "Local identity",
                        binding
                            .map(|value| registry_state_label(value.state))
                            .unwrap_or("Not checked"),
                    );
                    value_row(
                        ui,
                        "Remote decision",
                        remote
                            .map(|value| trust_decision_label(value.decision))
                            .unwrap_or("Not checked"),
                    );
                    value_row(
                        ui,
                        "Registry health",
                        remote
                            .map(|value| trust_health_label(value.health))
                            .unwrap_or("Unknown"),
                    );
                    value_row(
                        ui,
                        "Identity revision",
                        binding
                            .and_then(|value| value.identity_revision)
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "--".to_string()),
                    );
                });
            });
        });
    }

    fn peers(&mut self, ui: &mut Ui) {
        let peers = self
            .snapshot
            .as_ref()
            .map(|snapshot| snapshot.peer_store.peers.clone())
            .unwrap_or_default();
        ScrollArea::vertical().show(ui, |ui| {
            card(ui, "Import Invite", |ui| {
                ui.horizontal(|ui| {
                    ui.add_sized(
                        [ui.available_width() - 130.0, 36.0],
                        TextEdit::singleline(&mut self.invite_code).hint_text("Invite code"),
                    );
                    if ui
                        .add_enabled(
                            !self.busy && !self.invite_code.trim().is_empty(),
                            primary_button("Import", CYAN, 110.0),
                        )
                        .clicked()
                    {
                        let encoded = std::mem::take(&mut self.invite_code);
                        self.submit(ControlRequest::ImportInvite { encoded });
                    }
                });
            });
            ui.add_space(14.0);

            if peers.is_empty() {
                card(ui, "Trusted Peers", |ui| {
                    ui.label(RichText::new("No peers").color(MUTED));
                });
            }
            for peer in peers {
                self.peer_card(ui, &peer);
                ui.add_space(10.0);
            }
        });
    }

    fn profiles(&mut self, ui: &mut Ui) {
        let profile_status = self
            .snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.daemon.as_ref())
            .map(|daemon| daemon.game_profile.clone());
        ScrollArea::vertical().show(ui, |ui| {
            let Some(profile_status) = profile_status else {
                card(ui, "Game Profiles", |ui| {
                    ui.label(
                        RichText::new("Service unavailable. Profiles cannot be loaded.")
                            .color(MUTED),
                    );
                });
                return;
            };

            if let Some(warning) = profile_status.selection_warning.as_deref() {
                Frame::new()
                    .fill(Color32::from_rgb(49, 40, 26))
                    .stroke(Stroke::new(1.0, AMBER))
                    .corner_radius(6.0)
                    .inner_margin(12.0)
                    .show(ui, |ui| {
                        ui.label(RichText::new(warning).color(AMBER));
                    });
                ui.add_space(12.0);
            }

            let enforcement = &profile_status.port_enforcement;
            let classification = &profile_status.process_classification;
            Frame::new()
                .fill(PANEL)
                .stroke(Stroke::new(
                    1.0,
                    if enforcement.restart_required {
                        AMBER
                    } else {
                        BORDER
                    },
                ))
                .corner_radius(6.0)
                .inner_margin(12.0)
                .show(ui, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        status_pill(
                            ui,
                            port_enforcement_label(enforcement.state),
                            if enforcement.restart_required {
                                AMBER
                            } else {
                                GREEN
                            },
                        );
                        value_chip(
                            ui,
                            "Applied profile",
                            enforcement.profile_id.as_deref().unwrap_or("None"),
                        );
                        value_chip(ui, "UDP", &port_list(&enforcement.udp_ports));
                        status_pill(
                            ui,
                            process_classification_label(classification.state),
                            if classification.state == GameProcessClassificationState::ApplyFailed {
                                RED
                            } else if classification.state == GameProcessClassificationState::Active
                            {
                                GREEN
                            } else {
                                AMBER
                            },
                        );
                        if let Some(executable) = classification.executable.as_deref() {
                            value_chip(ui, "Process", executable);
                        }
                        if enforcement.restart_required {
                            ui.label(RichText::new("Restart required").color(AMBER).strong());
                        }
                    });
                });
            ui.add_space(12.0);

            if profile_status.available_profiles.is_empty() {
                card(ui, "Game Profiles", |ui| {
                    ui.label(RichText::new("No installed profiles").color(MUTED));
                });
                return;
            }

            self.profile_cursor = self
                .profile_cursor
                .min(profile_status.available_profiles.len().saturating_sub(1));
            for (index, profile) in profile_status.available_profiles.into_iter().enumerate() {
                let selected = profile_status
                    .selected_profile
                    .as_ref()
                    .is_some_and(|current| current.id == profile.id);
                self.profile_card(
                    ui,
                    &profile,
                    selected,
                    self.game_mode && index == self.profile_cursor,
                );
                ui.add_space(10.0);
            }
        });
    }

    fn profile_card(
        &mut self,
        ui: &mut Ui,
        profile: &GameProfileInfo,
        selected: bool,
        focused: bool,
    ) {
        Frame::new()
            .fill(if selected { PANEL_ALT } else { PANEL })
            .stroke(Stroke::new(
                if focused { 2.0 } else { 1.0 },
                if selected {
                    GREEN
                } else if focused {
                    CYAN
                } else {
                    BORDER
                },
            ))
            .corner_radius(6.0)
            .inner_margin(16.0)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(
                            RichText::new(&profile.display_name)
                                .size(17.0)
                                .strong()
                                .color(TEXT),
                        );
                        ui.label(RichText::new(&profile.id).size(11.0).color(MUTED));
                    });
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        status_pill(
                            ui,
                            if selected {
                                "Selected"
                            } else if focused {
                                "Focused"
                            } else {
                                "Available"
                            },
                            if selected { GREEN } else { CYAN },
                        );
                    });
                });
                ui.add_space(12.0);
                ui.horizontal_wrapped(|ui| {
                    value_chip(ui, "UDP", &port_list(&profile.udp_ports));
                    value_chip(ui, "LAN", yes_no(profile.lan_discovery));
                    value_chip(ui, "Voice", yes_no(profile.voice_chat_safe));
                    value_chip(ui, "Low latency", yes_no(profile.low_latency));
                });
                ui.add_space(12.0);
                if selected {
                    if ui
                        .add_enabled(!self.busy, secondary_button("Clear selection", 140.0))
                        .clicked()
                    {
                        self.submit(ControlRequest::ClearProfile);
                    }
                } else if ui
                    .add_enabled(!self.busy, primary_button("Select profile", CYAN, 140.0))
                    .clicked()
                {
                    self.submit(ControlRequest::SelectProfile {
                        profile_id: profile.id.clone(),
                    });
                }
            });
    }

    fn peer_card(&mut self, ui: &mut Ui, peer: &StoredPeer) {
        let selected = self.selected_peer_id.as_deref() == Some(&peer.peer_id);
        Frame::new()
            .fill(if selected { PANEL_ALT } else { PANEL })
            .stroke(Stroke::new(1.0, if selected { GREEN } else { BORDER }))
            .corner_radius(6.0)
            .inner_margin(16.0)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(RichText::new(&peer.alias).size(16.0).strong().color(TEXT));
                        ui.label(
                            RichText::new(short_id(&peer.peer_id))
                                .size(11.0)
                                .color(MUTED),
                        );
                    });
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if selected {
                            status_pill(ui, "Selected", GREEN);
                        } else if peer.revoked {
                            status_pill(ui, "Revoked", RED);
                        } else {
                            status_pill(ui, "Available", CYAN);
                        }
                    });
                });
                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    value_chip(ui, "Mesh", &peer.mesh_id);
                    value_chip(ui, "Trust", trust_mode_label(peer.trust_mode));
                    value_chip(ui, "Source", &peer.trust_source);
                });
                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    if selected {
                        if ui
                            .add_enabled(!self.busy, secondary_button("Clear selection", 126.0))
                            .clicked()
                        {
                            self.submit(ControlRequest::ClearPeerSelection);
                        }
                    } else if !peer.revoked
                        && ui
                            .add_enabled(!self.busy, primary_button("Select", CYAN, 96.0))
                            .clicked()
                    {
                        self.submit(ControlRequest::SelectPeer {
                            peer_id: peer.peer_id.clone(),
                        });
                    }
                    if !peer.revoked
                        && ui
                            .add_enabled(!self.busy, secondary_button("Revoke", 96.0))
                            .clicked()
                    {
                        self.confirm_peer_action = Some((peer.peer_id.clone(), true));
                    }
                    if ui
                        .add_enabled(!self.busy, secondary_button("Remove", 96.0))
                        .clicked()
                    {
                        self.confirm_peer_action = Some((peer.peer_id.clone(), false));
                    }
                });
                if let Some((peer_id, revoke)) = self.confirm_peer_action.clone() {
                    if peer_id == peer.peer_id {
                        ui.add_space(10.0);
                        Frame::new()
                            .fill(Color32::from_rgb(49, 31, 31))
                            .corner_radius(4.0)
                            .inner_margin(10.0)
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.label(
                                        RichText::new(if revoke {
                                            "Confirm peer revocation"
                                        } else {
                                            "Confirm peer removal"
                                        })
                                        .color(TEXT),
                                    );
                                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                        if ui.button("Cancel").clicked() {
                                            self.confirm_peer_action = None;
                                        }
                                        if ui
                                            .add(primary_button(
                                                if revoke { "Revoke" } else { "Remove" },
                                                RED,
                                                92.0,
                                            ))
                                            .clicked()
                                        {
                                            self.confirm_peer_action = None;
                                            self.submit(if revoke {
                                                ControlRequest::RevokePeer { peer_id }
                                            } else {
                                                ControlRequest::RemovePeer { peer_id }
                                            });
                                        }
                                    });
                                });
                            });
                    }
                }
            });
    }

    fn identity(&mut self, ui: &mut Ui) {
        ScrollArea::vertical().show(ui, |ui| {
            ui.columns(2, |columns| {
                card(&mut columns[0], "Registry Status", |ui| {
                    let document = self.identity_document.as_ref();
                    value_row(ui, "Peer", json_text(document, &["peerId"]).unwrap_or("--"));
                    value_row(
                        ui,
                        "Network",
                        json_text(document, &["networkId"]).unwrap_or("--"),
                    );
                    value_row(
                        ui,
                        "Contract",
                        json_text(document, &["contractAddress"]).unwrap_or("--"),
                    );
                    value_row(
                        ui,
                        "Status",
                        json_text(document, &["identity", "status"]).unwrap_or("Not checked"),
                    );
                    value_row(
                        ui,
                        "Finality",
                        json_bool(document, &["transactionFinalityVerified"])
                            .map(yes_no)
                            .unwrap_or("Not verified"),
                    );
                    ui.add_space(12.0);
                    if ui
                        .add_enabled(!self.busy, primary_button("Refresh identity", CYAN, 150.0))
                        .clicked()
                    {
                        self.submit(ControlRequest::Identity {
                            action: IdentityAction::Status,
                            input: self.identity_input.clone(),
                        });
                    }
                });
                card(&mut columns[1], "Identity Policy", |ui| {
                    form_row(ui, "Config", &mut self.identity_input.config_file, false);
                    form_row(ui, "State", &mut self.identity_input.state_dir, false);
                    form_row(
                        ui,
                        "Peer TTL",
                        &mut self.identity_input.max_peer_ttl_seconds,
                        false,
                    );
                    form_row(ui, "Mesh scope", &mut self.identity_input.mesh_scope, false);
                });
            });
            ui.add_space(14.0);
            card(ui, "Wallet-authorized Operations", |ui| {
                ui.columns(2, |columns| {
                    form_row(
                        &mut columns[0],
                        "Keystore",
                        &mut self.identity_input.keystore_path,
                        false,
                    );
                    form_row(
                        &mut columns[1],
                        "Wallet",
                        &mut self.identity_input.wallet_name,
                        false,
                    );
                });
                form_row(ui, "Peer ID", &mut self.identity_input.peer_id, false);
                ui.add_space(10.0);
                ui.horizontal_wrapped(|ui| {
                    for (action, color) in [
                        (IdentityAction::Register, GREEN),
                        (IdentityAction::Update, CYAN),
                        (IdentityAction::Suspend, AMBER),
                        (IdentityAction::Reactivate, GREEN),
                        (IdentityAction::Revoke, RED),
                    ] {
                        let peer_ready =
                            !matches!(action, IdentityAction::Suspend | IdentityAction::Revoke)
                                || !self.identity_input.peer_id.trim().is_empty();
                        let enabled = !self.busy
                            && !self.identity_input.keystore_path.trim().is_empty()
                            && peer_ready;
                        if ui
                            .add_enabled(
                                enabled,
                                primary_button(title_case(action.command_name()), color, 112.0),
                            )
                            .clicked()
                        {
                            self.submit(ControlRequest::Identity {
                                action,
                                input: self.identity_input.clone(),
                            });
                        }
                    }
                });
            });
        });
    }

    fn diagnostics(&mut self, ui: &mut Ui) {
        let snapshot = self.snapshot.clone();
        let daemon_running = snapshot
            .as_ref()
            .and_then(|value| value.daemon.as_ref())
            .is_some();
        ScrollArea::vertical().show(ui, |ui| {
            ui.columns(2, |columns| {
                card(&mut columns[0], "Runtime", |ui| {
                    let daemon = snapshot.as_ref().and_then(|value| value.daemon.as_ref());
                    value_row(
                        ui,
                        "Network",
                        daemon
                            .map(|status| network_state_label(status.network.state))
                            .unwrap_or("Stopped"),
                    );
                    value_row(
                        ui,
                        "Data plane",
                        daemon
                            .map(|status| data_plane_label(status.data_plane.state))
                            .unwrap_or("Not started"),
                    );
                    value_row(
                        ui,
                        "Interface",
                        daemon
                            .and_then(|status| status.data_plane.interface_name.as_deref())
                            .unwrap_or("--"),
                    );
                    value_row(
                        ui,
                        "Session keys",
                        daemon
                            .map(|status| yes_no(status.data_plane.peer_session_ready))
                            .unwrap_or("No"),
                    );
                });
                card(&mut columns[1], "Packet Counters", |ui| {
                    let metrics = snapshot
                        .as_ref()
                        .and_then(|value| value.daemon.as_ref())
                        .map(|daemon| daemon.data_plane.metrics);
                    metric_row(
                        ui,
                        "Observed",
                        metrics
                            .map(|value| value.observed_packets)
                            .unwrap_or(0)
                            .to_string(),
                    );
                    metric_row(
                        ui,
                        "Emitted",
                        metrics
                            .map(|value| value.emitted_packets)
                            .unwrap_or(0)
                            .to_string(),
                    );
                    metric_row(
                        ui,
                        "Dropped",
                        metrics
                            .map(|value| value.dropped_packets)
                            .unwrap_or(0)
                            .to_string(),
                    );
                    metric_row(
                        ui,
                        "Transport errors",
                        metrics
                            .map(|value| value.transport_errors)
                            .unwrap_or(0)
                            .to_string(),
                    );
                });
            });
            ui.add_space(14.0);
            card(ui, "Host Capabilities", |ui| {
                let capabilities = snapshot
                    .as_ref()
                    .and_then(|value| value.daemon.as_ref())
                    .map(|status| &status.runtime_capabilities);
                ui.columns(2, |columns| {
                    value_row(
                        &mut columns[0],
                        "cgroup v2",
                        capability_state(capabilities.map(|value| value.cgroup_v2.state)),
                    );
                    value_row(
                        &mut columns[0],
                        "nftables cgroup",
                        capability_state(capabilities.map(|value| value.nftables_cgroup_v2.state)),
                    );
                    value_row(
                        &mut columns[0],
                        "TUN",
                        capability_state(capabilities.map(|value| value.tun.state)),
                    );
                    value_row(
                        &mut columns[1],
                        "systemd scopes",
                        capability_state(capabilities.map(|value| value.systemd_user_scopes.state)),
                    );
                    value_row(
                        &mut columns[1],
                        "PolicyKit",
                        capability_state(capabilities.map(|value| value.policykit.state)),
                    );
                    value_row(
                        &mut columns[1],
                        "logind session",
                        capability_state(capabilities.map(|value| value.logind_session.state)),
                    );
                });
                if let Some(detail) = capabilities.and_then(first_capability_issue) {
                    ui.separator();
                    ui.label(RichText::new(detail).color(AMBER));
                }
            });
            ui.add_space(14.0);
            card(ui, "Service Controls", |ui| {
                ui.horizontal_wrapped(|ui| {
                    if ui
                        .add_enabled(
                            !self.busy && !daemon_running,
                            primary_button("Start", GREEN, 110.0),
                        )
                        .clicked()
                    {
                        self.submit(ControlRequest::StartService);
                    }
                    if ui
                        .add_enabled(
                            !self.busy && daemon_running,
                            secondary_button("Restart", 110.0),
                        )
                        .clicked()
                    {
                        self.submit(ControlRequest::RestartService);
                    }
                    if ui
                        .add_enabled(
                            !self.busy && daemon_running,
                            primary_button("Stop", RED, 110.0),
                        )
                        .clicked()
                    {
                        self.submit(ControlRequest::Disconnect);
                    }
                    if ui
                        .add_enabled(!self.busy, secondary_button("Run checks", 120.0))
                        .clicked()
                    {
                        self.submit(ControlRequest::Doctor);
                    }
                });
            });
            if let Some(output) = self.diagnostic_output.as_deref() {
                ui.add_space(14.0);
                card(ui, "Diagnostic Report", |ui| {
                    ScrollArea::horizontal().show(ui, |ui| {
                        ui.add(
                            egui::Label::new(RichText::new(output).monospace().color(TEXT))
                                .selectable(true),
                        );
                    });
                });
            }
            ui.add_space(14.0);
            card(ui, "Support Bundle", |ui| {
                ui.horizontal(|ui| {
                    ui.add_sized(
                        [ui.available_width() - 170.0, 36.0],
                        TextEdit::singleline(&mut self.support_bundle_path),
                    );
                    if ui
                        .add_enabled(
                            !self.busy && !self.support_bundle_path.trim().is_empty(),
                            primary_button("Export", CYAN, 150.0),
                        )
                        .clicked()
                    {
                        self.submit(ControlRequest::SupportBundle {
                            output: self.support_bundle_path.clone(),
                        });
                    }
                });
            });
            if let Some(error) = snapshot
                .as_ref()
                .and_then(|value| value.daemon_error.as_deref())
            {
                ui.add_space(14.0);
                card(ui, "Service Error", |ui| {
                    ui.label(RichText::new(error).color(RED));
                });
            }
        });
    }

    fn selected_peer_label(&self) -> &str {
        let Some(peer_id) = self.selected_peer_id.as_deref() else {
            return "No peer selected";
        };
        self.snapshot
            .as_ref()
            .and_then(|snapshot| {
                snapshot
                    .peer_store
                    .peers
                    .iter()
                    .find(|peer| peer.peer_id == peer_id)
            })
            .map(|peer| peer.alias.as_str())
            .unwrap_or(peer_id)
    }

    fn handle_game_mode_input(&mut self, context: &egui::Context) {
        if !self.game_mode {
            return;
        }
        if context.input(|input| input.key_pressed(egui::Key::Escape)) {
            self.page = Page::Overview;
            return;
        }
        if context.wants_keyboard_input() {
            return;
        }

        let previous_page = context.input(|input| {
            input.key_pressed(egui::Key::ArrowLeft) || input.key_pressed(egui::Key::PageUp)
        });
        let next_page = context.input(|input| {
            input.key_pressed(egui::Key::ArrowRight) || input.key_pressed(egui::Key::PageDown)
        });
        if previous_page {
            self.page = self.page.shifted(-1);
            return;
        }
        if next_page {
            self.page = self.page.shifted(1);
            return;
        }
        if self.page != Page::Profiles {
            return;
        }

        let profiles = self
            .snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.daemon.as_ref())
            .map(|daemon| daemon.game_profile.available_profiles.clone())
            .unwrap_or_default();
        if profiles.is_empty() {
            self.profile_cursor = 0;
            return;
        }
        if context.input(|input| input.key_pressed(egui::Key::ArrowUp)) {
            self.profile_cursor = self
                .profile_cursor
                .checked_sub(1)
                .unwrap_or(profiles.len() - 1);
        } else if context.input(|input| input.key_pressed(egui::Key::ArrowDown)) {
            self.profile_cursor = (self.profile_cursor + 1) % profiles.len();
        }

        if !self.busy && context.input(|input| input.key_pressed(egui::Key::Enter)) {
            let profile = &profiles[self.profile_cursor.min(profiles.len() - 1)];
            let selected = self
                .snapshot
                .as_ref()
                .and_then(|snapshot| snapshot.daemon.as_ref())
                .and_then(|daemon| daemon.game_profile.selected_profile.as_ref())
                .is_some_and(|current| current.id == profile.id);
            self.submit(if selected {
                ControlRequest::ClearProfile
            } else {
                ControlRequest::SelectProfile {
                    profile_id: profile.id.clone(),
                }
            });
        }
    }
}

impl eframe::App for QuantumLinkDesktop {
    fn update(&mut self, context: &egui::Context, _frame: &mut eframe::Frame) {
        self.receive_results();
        self.handle_game_mode_input(context);
        if self.busy {
            context.request_repaint_after(Duration::from_millis(100));
        }

        egui::SidePanel::left("navigation")
            .exact_width(196.0)
            .frame(
                Frame::new()
                    .fill(Color32::from_rgb(21, 23, 27))
                    .inner_margin(14.0),
            )
            .show(context, |ui| self.sidebar(ui));

        egui::TopBottomPanel::top("header")
            .exact_height(76.0)
            .frame(
                Frame::new()
                    .fill(BG)
                    .inner_margin(egui::Margin::symmetric(22, 14)),
            )
            .show(context, |ui| self.header(ui));

        egui::TopBottomPanel::bottom("notice")
            .resizable(false)
            .show_animated(context, self.notice.is_some(), |ui| {
                if let Some((message, color)) = self.notice.clone() {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(message).color(color));
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if ui.small_button("Close").clicked() {
                                self.notice = None;
                            }
                        });
                    });
                }
            });

        egui::CentralPanel::default()
            .frame(Frame::new().fill(BG).inner_margin(22.0))
            .show(context, |ui| match self.page {
                Page::Overview => self.overview(ui),
                Page::Peers => self.peers(ui),
                Page::Profiles => self.profiles(ui),
                Page::Identity => self.identity(ui),
                Page::Diagnostics => self.diagnostics(ui),
            });
    }
}

fn configure_style(context: &egui::Context) {
    let mut style = (*context.style()).clone();
    style.visuals = egui::Visuals::dark();
    style.visuals.panel_fill = BG;
    style.visuals.window_fill = PANEL;
    style.visuals.extreme_bg_color = Color32::from_rgb(14, 16, 18);
    style.visuals.widgets.inactive.bg_fill = PANEL_ALT;
    style.visuals.widgets.inactive.weak_bg_fill = PANEL_ALT;
    style.visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, BORDER);
    style.visuals.widgets.hovered.bg_fill = Color32::from_rgb(41, 46, 52);
    style.visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, CYAN);
    style.visuals.widgets.active.bg_fill = Color32::from_rgb(48, 55, 61);
    style.visuals.selection.bg_fill = Color32::from_rgb(40, 91, 79);
    style.spacing.item_spacing = Vec2::new(10.0, 8.0);
    style.text_styles.insert(
        egui::TextStyle::Body,
        FontId::new(14.0, egui::FontFamily::Proportional),
    );
    context.set_style(style);
}

fn card(ui: &mut Ui, title: &str, content: impl FnOnce(&mut Ui)) {
    Frame::new()
        .fill(PANEL)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(6.0)
        .inner_margin(16.0)
        .show(ui, |ui| {
            ui.set_min_height(150.0);
            ui.label(RichText::new(title).size(15.0).strong().color(TEXT));
            ui.add_space(12.0);
            content(ui);
        });
}

fn primary_button(text: impl Into<String>, color: Color32, width: f32) -> Button<'static> {
    Button::new(
        RichText::new(text.into())
            .strong()
            .color(Color32::from_rgb(14, 18, 17)),
    )
    .fill(color)
    .stroke(Stroke::NONE)
    .corner_radius(6.0)
    .min_size(Vec2::new(width, 44.0))
}

fn secondary_button(text: &'static str, width: f32) -> Button<'static> {
    Button::new(RichText::new(text).color(TEXT))
        .fill(PANEL_ALT)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(6.0)
        .min_size(Vec2::new(width, 44.0))
}

fn port_list(ports: &[u16]) -> String {
    ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn status_row(ui: &mut Ui, label: &str, color: Color32) {
    ui.horizontal(|ui| {
        let (rect, _) = ui.allocate_exact_size(Vec2::splat(10.0), Sense::hover());
        ui.painter().circle_filled(rect.center(), 5.0, color);
        ui.label(RichText::new(label).size(20.0).strong().color(TEXT));
    });
}

fn value_row(ui: &mut Ui, label: &str, value: impl AsRef<str>) {
    ui.horizontal(|ui| {
        ui.label(RichText::new(label).color(MUTED));
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.label(RichText::new(value.as_ref()).color(TEXT));
        });
    });
}

fn metric_row(ui: &mut Ui, label: &str, value: String) {
    value_row(ui, label, value);
    ui.separator();
}

fn value_chip(ui: &mut Ui, label: &str, value: &str) {
    Frame::new()
        .fill(Color32::from_rgb(23, 26, 30))
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(4.0)
        .inner_margin(egui::Margin::symmetric(9, 5))
        .show(ui, |ui| {
            ui.label(
                RichText::new(format!("{label}: {value}"))
                    .size(11.0)
                    .color(MUTED),
            );
        });
}

fn status_pill(ui: &mut Ui, label: &str, color: Color32) {
    Frame::new()
        .fill(color.gamma_multiply(0.18))
        .stroke(Stroke::new(1.0, color.gamma_multiply(0.6)))
        .corner_radius(4.0)
        .inner_margin(egui::Margin::symmetric(9, 4))
        .show(ui, |ui| {
            ui.label(RichText::new(label).size(11.0).strong().color(color));
        });
}

fn form_row(ui: &mut Ui, label: &str, value: &mut String, password: bool) {
    ui.label(RichText::new(label).size(11.0).color(MUTED));
    let editor = TextEdit::singleline(value).desired_width(f32::INFINITY);
    ui.add_sized(
        [ui.available_width(), 34.0],
        if password {
            editor.password(true)
        } else {
            editor
        },
    );
    ui.add_space(4.0);
}

fn phase_label(phase: ConnectionPhase) -> &'static str {
    match phase {
        ConnectionPhase::Idle => "Idle",
        ConnectionPhase::Preparing => "Preparing",
        ConnectionPhase::Connecting => "Connecting",
        ConnectionPhase::Connected => "Connected",
        ConnectionPhase::Degraded => "Degraded",
        ConnectionPhase::Failed => "Failed",
    }
}

fn path_label(path: Option<PathKind>) -> &'static str {
    match path {
        Some(PathKind::Direct) => "Direct path",
        Some(PathKind::Relay) => "Relay path",
        Some(PathKind::Probing) => "Probing",
        Some(PathKind::Unavailable) | None => "Unavailable",
    }
}

fn path_change_reason_label(reason: DataPlanePathChangeReason) -> &'static str {
    match reason {
        DataPlanePathChangeReason::Initial => "Initial path",
        DataPlanePathChangeReason::PathFailure => "Path failure",
        DataPlanePathChangeReason::SustainedImprovement => "Sustained improvement",
        DataPlanePathChangeReason::NetworkChange => "Network change",
        DataPlanePathChangeReason::Unknown => "Unknown",
    }
}

fn path_mtu_probe_state_label(state: PathMtuProbeState) -> &'static str {
    match state {
        PathMtuProbeState::BaseOnly => "Safe base",
        PathMtuProbeState::Searching => "Searching",
        PathMtuProbeState::Confirmed => "Confirmed",
        PathMtuProbeState::Unknown => "Unknown",
    }
}

fn route_mode_label(mode: qlink_proto::RouteMode) -> &'static str {
    match mode {
        qlink_proto::RouteMode::GameOnly => "Game only",
        qlink_proto::RouteMode::ProtectedPrefixesOnly => "Protected routes",
        qlink_proto::RouteMode::FullTunnel => "Full tunnel",
    }
}

fn trust_mode_label(mode: MeshTrustMode) -> &'static str {
    match mode {
        MeshTrustMode::PrivateFriends => "Private friends",
        MeshTrustMode::PublicDytallixRequired => "Dytallix required",
        MeshTrustMode::DevelopmentOptional => "Development",
    }
}

fn registry_state_label(state: LocalRegistryBindingState) -> &'static str {
    match state {
        LocalRegistryBindingState::NotConfigured => "Not configured",
        LocalRegistryBindingState::Pending => "Pending",
        LocalRegistryBindingState::Active => "Active",
        LocalRegistryBindingState::Missing => "Missing",
        LocalRegistryBindingState::Revoked => "Revoked",
        LocalRegistryBindingState::Suspended => "Suspended",
        LocalRegistryBindingState::Mismatched => "Mismatched",
        LocalRegistryBindingState::Expired => "Expired",
        LocalRegistryBindingState::Unavailable => "Unavailable",
        LocalRegistryBindingState::Unknown => "Unknown",
    }
}

fn trust_decision_label(decision: DytallixTrustDecision) -> &'static str {
    match decision {
        DytallixTrustDecision::NotChecked => "Not checked",
        DytallixTrustDecision::Accepted => "Accepted",
        DytallixTrustDecision::Denied => "Denied",
        DytallixTrustDecision::Revoked => "Revoked",
        DytallixTrustDecision::Suspended => "Suspended",
        DytallixTrustDecision::Mismatched => "Mismatched",
        DytallixTrustDecision::Unknown => "Unknown",
    }
}

fn trust_health_label(health: DytallixTrustHealth) -> &'static str {
    match health {
        DytallixTrustHealth::Healthy => "Healthy",
        DytallixTrustHealth::Degraded => "Degraded",
        DytallixTrustHealth::Unavailable => "Unavailable",
        DytallixTrustHealth::Unknown => "Unknown",
    }
}

fn network_state_label(state: NetworkPlanState) -> &'static str {
    match state {
        NetworkPlanState::NotStarted => "Not started",
        NetworkPlanState::Planned => "Planned",
        NetworkPlanState::ApplyFailed => "Apply failed",
        NetworkPlanState::Applied => "Applied",
    }
}

fn data_plane_label(state: DataPlaneState) -> &'static str {
    match state {
        DataPlaneState::NotStarted => "Not started",
        DataPlaneState::Starting => "Starting",
        DataPlaneState::Ready => "Ready",
        DataPlaneState::Degraded => "Degraded",
        DataPlaneState::Failed => "Failed",
    }
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "Yes"
    } else {
        "No"
    }
}

fn capability_state(state: Option<RuntimeCapabilityState>) -> &'static str {
    match state {
        Some(RuntimeCapabilityState::NotChecked) => "Not checked",
        Some(RuntimeCapabilityState::Supported) => "Supported",
        Some(RuntimeCapabilityState::Unsupported) => "Unsupported",
        Some(RuntimeCapabilityState::Unavailable) => "Unavailable",
        None => "--",
    }
}

fn first_capability_issue(capabilities: &SteamOsRuntimeCapabilities) -> Option<&str> {
    [
        &capabilities.cgroup_v2,
        &capabilities.nftables_cgroup_v2,
        &capabilities.tun,
        &capabilities.systemd_user_scopes,
        &capabilities.policykit,
        &capabilities.logind_session,
    ]
    .into_iter()
    .find(|capability| {
        matches!(
            capability.state,
            RuntimeCapabilityState::Unsupported | RuntimeCapabilityState::Unavailable
        )
    })
    .and_then(|capability| capability.detail.as_deref())
}

fn port_enforcement_label(state: GameProfilePortEnforcementState) -> &'static str {
    match state {
        GameProfilePortEnforcementState::NotApplicable => "Ports inactive",
        GameProfilePortEnforcementState::Planned => "Ports planned",
        GameProfilePortEnforcementState::FailClosed => "No profile",
        GameProfilePortEnforcementState::Applied => "Ports active",
        GameProfilePortEnforcementState::ApplyFailed => "Apply failed",
    }
}

fn process_classification_label(state: GameProcessClassificationState) -> &'static str {
    match state {
        GameProcessClassificationState::NotApplicable => "Process inactive",
        GameProcessClassificationState::FailClosed => "Process blocked",
        GameProcessClassificationState::Armed => "Process armed",
        GameProcessClassificationState::Active => "Process active",
        GameProcessClassificationState::ApplyFailed => "Process failed",
    }
}

fn short_id(value: &str) -> String {
    if value.chars().count() <= 28 {
        return value.to_string();
    }
    let start: String = value.chars().take(14).collect();
    let end: String = value
        .chars()
        .rev()
        .take(8)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    format!("{start}...{end}")
}

fn title_case(value: &str) -> &'static str {
    match value {
        "register" => "Register",
        "update" => "Update",
        "suspend" => "Suspend",
        "reactivate" => "Reactivate",
        "revoke" => "Revoke",
        _ => "Run",
    }
}

fn json_text<'a>(document: Option<&'a Value>, path: &[&str]) -> Option<&'a str> {
    let mut value = document?;
    for segment in path {
        value = value.get(*segment)?;
    }
    value.as_str()
}

fn json_bool(document: Option<&Value>, path: &[&str]) -> Option<bool> {
    let mut value = document?;
    for segment in path {
        value = value.get(*segment)?;
    }
    value.as_bool()
}

fn default_support_bundle_path() -> String {
    std::env::var("HOME")
        .map(|home| format!("{home}/Desktop/quantumlink-support.zip"))
        .unwrap_or_else(|_| "/tmp/quantumlink-support.zip".to_string())
}
