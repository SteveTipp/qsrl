use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

use eframe::egui::{self, Color32, RichText, ScrollArea, TextEdit};
use qsrl::commands::SettingsOverrides;
use qsrl::config::RepoConfig;
use qsrl::protocol::{
    CompressionLayout, CompressionMode, ManifestEncoding, SignatureAlgorithm, SignaturePlacement,
};
use qsrl::ui_bridge::{
    ExtractRequest, InspectReport, InspectRequest, KeygenAlgorithm, KeygenReport, KeygenRequest,
    PackRequest, SignRequest, VerifyReport, VerifyRequest, inspect_report, pack_input_file_count,
    run_extract, run_keygen, run_pack, run_sign, validate_extract_request,
    validate_inspect_request, validate_keygen_request, validate_pack_request,
    validate_sign_request, validate_verify_request, verify_report,
};

fn main() -> eframe::Result<()> {
    let root = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("QSRL Desktop")
            .with_inner_size([1180.0, 820.0])
            .with_min_inner_size([980.0, 680.0])
            .with_icon(qsrl_desktop_icon()),
        ..Default::default()
    };

    eframe::run_native(
        "QSRL Desktop",
        native_options,
        Box::new(move |cc| {
            apply_qwork_theme(&cc.egui_ctx);
            Ok(Box::new(QsrlDesktopApp::new(root.clone())))
        }),
    )
}

fn qsrl_desktop_icon() -> egui::IconData {
    eframe::icon_data::from_png_bytes(include_bytes!("../../QSRL_Icon.png"))
        .expect("bundled QSRL_Icon.png must be a valid PNG")
}

const QWORK_BLACK: Color32 = Color32::from_rgb(0, 0, 0);
const QWORK_PANEL: Color32 = Color32::from_rgb(6, 8, 6);
const QWORK_GREEN: Color32 = Color32::from_rgb(0, 255, 0);
const QWORK_GREEN_DIM: Color32 = Color32::from_rgb(0, 96, 0);
const QWORK_GREEN_DARK: Color32 = Color32::from_rgb(0, 24, 0);
const QWORK_WHITE: Color32 = Color32::from_rgb(245, 245, 245);
const QWORK_BLUE: Color32 = Color32::from_rgb(48, 128, 255);
const QWORK_ERROR: Color32 = Color32::from_rgb(255, 88, 88);
const FORM_LABEL_WIDTH: f32 = 300.0;
const FORM_FIELD_WIDTH: f32 = 360.0;
const FORM_FIELD_MIN_WIDTH: f32 = 180.0;
const FORM_ROW_HEIGHT: f32 = 24.0;
const FORM_BROWSE_BUTTON_WIDTH: f32 = 72.0;
const FORM_COPY_BUTTON_WIDTH: f32 = 52.0;

fn apply_qwork_theme(ctx: &egui::Context) {
    let mut style = (*ctx.global_style()).clone();
    style.visuals = egui::Visuals::dark();
    let visuals = &mut style.visuals;

    visuals.override_text_color = Some(QWORK_WHITE);
    visuals.weak_text_color = Some(Color32::from_rgb(176, 176, 176));
    visuals.panel_fill = QWORK_BLACK;
    visuals.window_fill = QWORK_PANEL;
    visuals.window_stroke = egui::Stroke::new(1.0, QWORK_GREEN_DIM);
    visuals.faint_bg_color = QWORK_GREEN_DARK;
    visuals.extreme_bg_color = QWORK_BLACK;
    visuals.text_edit_bg_color = Some(QWORK_BLACK);
    visuals.code_bg_color = Color32::from_rgb(0, 14, 0);
    visuals.hyperlink_color = QWORK_BLUE;
    visuals.warn_fg_color = QWORK_GREEN;
    visuals.error_fg_color = QWORK_ERROR;
    visuals.selection.bg_fill = QWORK_GREEN_DARK;
    visuals.selection.stroke = egui::Stroke::new(1.0, QWORK_GREEN);

    visuals.widgets.noninteractive.bg_fill = QWORK_PANEL;
    visuals.widgets.noninteractive.weak_bg_fill = QWORK_BLACK;
    visuals.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0, QWORK_GREEN_DIM);
    visuals.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0, QWORK_WHITE);

    visuals.widgets.inactive.bg_fill = Color32::from_rgb(0, 12, 0);
    visuals.widgets.inactive.weak_bg_fill = QWORK_GREEN_DARK;
    visuals.widgets.inactive.bg_stroke = egui::Stroke::new(1.0, QWORK_GREEN_DIM);
    visuals.widgets.inactive.fg_stroke = egui::Stroke::new(1.0, QWORK_WHITE);

    visuals.widgets.hovered.bg_fill = Color32::from_rgb(0, 36, 0);
    visuals.widgets.hovered.weak_bg_fill = Color32::from_rgb(0, 48, 0);
    visuals.widgets.hovered.bg_stroke = egui::Stroke::new(1.0, QWORK_GREEN);
    visuals.widgets.hovered.fg_stroke = egui::Stroke::new(1.0, QWORK_GREEN);

    visuals.widgets.active.bg_fill = Color32::from_rgb(0, 56, 0);
    visuals.widgets.active.weak_bg_fill = Color32::from_rgb(0, 72, 0);
    visuals.widgets.active.bg_stroke = egui::Stroke::new(1.0, QWORK_GREEN);
    visuals.widgets.active.fg_stroke = egui::Stroke::new(1.0, QWORK_GREEN);
    visuals.widgets.open = visuals.widgets.hovered;

    ctx.set_global_style(style);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Workflow {
    Pack,
    Keygen,
    Sign,
    Verify,
    Extract,
    Inspect,
    Info,
}

impl Workflow {
    fn label(self) -> &'static str {
        match self {
            Self::Pack => "Pack",
            Self::Keygen => "Keygen",
            Self::Sign => "Sign",
            Self::Verify => "Verify",
            Self::Extract => "Extract",
            Self::Inspect => "Inspect",
            Self::Info => "Info",
        }
    }

    fn main_workflows() -> [Self; 6] {
        [
            Self::Pack,
            Self::Keygen,
            Self::Sign,
            Self::Verify,
            Self::Extract,
            Self::Inspect,
        ]
    }
}

#[derive(Clone, Copy, Debug)]
enum StatusKind {
    Success,
    Error,
    Info,
    Warning,
}

#[derive(Clone, Debug)]
struct StatusBanner {
    kind: StatusKind,
    title: String,
    detail_lines: Vec<String>,
    action: Option<StatusAction>,
}

impl StatusBanner {
    fn empty() -> Self {
        Self {
            kind: StatusKind::Info,
            title: String::new(),
            detail_lines: Vec::new(),
            action: None,
        }
    }

    fn is_empty(&self) -> bool {
        self.title.is_empty() && self.detail_lines.is_empty() && self.action.is_none()
    }
}

#[derive(Clone, Debug)]
struct StatusAction {
    label: &'static str,
    path: PathBuf,
}

#[derive(Clone, Debug)]
struct PackForm {
    input_path: String,
    output_path: String,
    signature_algorithm: SignatureAlgorithm,
    manifest_encoding: ManifestEncoding,
    compression_mode: CompressionMode,
    compression_layout: CompressionLayout,
    recipient_keys: Vec<String>,
}

impl PackForm {
    fn from_config(config: &RepoConfig) -> Self {
        Self {
            input_path: String::new(),
            output_path: String::new(),
            signature_algorithm: config.signature_algorithm,
            manifest_encoding: config.manifest_encoding,
            compression_mode: config.compression_mode,
            compression_layout: config.compression_layout,
            recipient_keys: vec![String::new()],
        }
    }
}

#[derive(Clone, Debug)]
struct KeygenForm {
    output_root: String,
    algorithm: KeygenAlgorithm,
}

impl KeygenForm {
    fn new(root: &Path) -> Self {
        Self {
            output_root: root.display().to_string(),
            algorithm: KeygenAlgorithm::MlDsa,
        }
    }
}

#[derive(Clone, Debug)]
struct SignForm {
    archive_path: String,
    key_path: String,
    placement: SignaturePlacement,
    detached_signature_path: String,
}

impl SignForm {
    fn from_config(config: &RepoConfig) -> Self {
        Self {
            archive_path: String::new(),
            key_path: String::new(),
            placement: config.signature_placement,
            detached_signature_path: String::new(),
        }
    }
}

#[derive(Clone, Debug, Default)]
struct VerifyForm {
    archive_path: String,
    public_key_path: String,
    detached_signature_path: String,
}

#[derive(Clone, Debug, Default)]
struct ExtractForm {
    archive_path: String,
    output_dir: String,
    public_key_path: String,
    detached_signature_path: String,
    recipient_key_path: String,
}

#[derive(Clone, Debug, Default)]
struct InspectForm {
    archive_path: String,
}

enum TaskMessage {
    Pack(Result<String, String>),
    Keygen(Result<KeygenReport, String>),
    Sign(Result<String, String>),
    Verify(Result<VerifyReport, String>),
    Extract(Result<String, String>),
    Inspect(Result<InspectReport, String>),
}

struct QsrlDesktopApp {
    root: PathBuf,
    active_workflow: Workflow,
    status: StatusBanner,
    log: String,
    pack_form: PackForm,
    keygen_form: KeygenForm,
    sign_form: SignForm,
    verify_form: VerifyForm,
    extract_form: ExtractForm,
    inspect_form: InspectForm,
    last_keygen: Option<KeygenReport>,
    last_verify: Option<VerifyReport>,
    last_inspect: Option<InspectReport>,
    pending_empty_pack_request: Option<PackRequest>,
    worker: Option<Receiver<TaskMessage>>,
    pending_label: Option<&'static str>,
}

impl QsrlDesktopApp {
    fn new(root: PathBuf) -> Self {
        let (config, status) = match RepoConfig::load_or_default(&root) {
            Ok(config) => (config, StatusBanner::empty()),
            Err(error) => (
                RepoConfig::default(),
                StatusBanner {
                    kind: StatusKind::Error,
                    title: "Could not load repo config".into(),
                    detail_lines: vec![format!("{}\n{error}", RepoConfig::path(&root).display())],
                    action: None,
                },
            ),
        };

        let backend = if cfg!(feature = "liboqs-backend") {
            "Crypto backend: liboqs-backend enabled"
        } else {
            "Crypto backend: stub signing mode; build with desktop-ui,liboqs-backend for real ML-DSA, SLH-DSA, and ML-KEM"
        };

        Self {
            root: root.clone(),
            active_workflow: Workflow::Pack,
            status,
            log: format!(
                "QSRL Desktop ready\n{}\nworkspace: {}",
                backend,
                root.display()
            ),
            pack_form: PackForm::from_config(&config),
            keygen_form: KeygenForm::new(&root),
            sign_form: SignForm::from_config(&config),
            verify_form: VerifyForm::default(),
            extract_form: ExtractForm::default(),
            inspect_form: InspectForm::default(),
            last_keygen: None,
            last_verify: None,
            last_inspect: None,
            pending_empty_pack_request: None,
            worker: None,
            pending_label: None,
        }
    }

    fn is_busy(&self) -> bool {
        self.worker.is_some()
    }

    fn start_pack(&mut self) {
        let request = PackRequest {
            root: self.root.clone(),
            input_path: PathBuf::from(self.pack_form.input_path.trim()),
            output_path: PathBuf::from(self.pack_form.output_path.trim()),
            settings: SettingsOverrides {
                signature_algorithm: Some(self.pack_form.signature_algorithm),
                manifest_encoding: Some(self.pack_form.manifest_encoding),
                compression_mode: Some(self.pack_form.compression_mode),
                compression_layout: Some(self.pack_form.compression_layout),
                ..SettingsOverrides::default()
            },
            recipient_key_paths: self
                .pack_form
                .recipient_keys
                .iter()
                .map(|value| value.trim())
                .filter(|value| !value.is_empty())
                .map(PathBuf::from)
                .collect(),
        };
        if let Err(error) = validate_pack_request(&request) {
            self.finish_error("Pack", error.to_string());
            return;
        }
        match pack_input_file_count(&request.input_path) {
            Ok(0) => {
                self.pending_empty_pack_request = Some(request.clone());
                self.status = StatusBanner {
                    kind: StatusKind::Warning,
                    title: "Selected folder is empty".into(),
                    detail_lines: vec![
                        "Packing now will create an empty .qsrl archive.".into(),
                        request.input_path.display().to_string(),
                    ],
                    action: None,
                };
                return;
            }
            Ok(_) => {}
            Err(error) => {
                self.finish_error("Pack", error.to_string());
                return;
            }
        }
        self.pending_empty_pack_request = None;
        self.launch_pack_task(request);
    }

    fn launch_pack_task(&mut self, request: PackRequest) {
        self.last_keygen = None;
        self.last_inspect = None;
        self.last_verify = None;
        let (sender, receiver) = mpsc::channel();
        self.worker = Some(receiver);
        self.pending_label = Some("Pack");
        self.status = info_banner("Pack in progress...", &[]);
        thread::spawn(move || {
            let result = run_pack(&request).map_err(|error| error.to_string());
            let _ = sender.send(TaskMessage::Pack(result));
        });
    }

    fn start_keygen(&mut self) {
        let request = KeygenRequest {
            output_root: PathBuf::from(self.keygen_form.output_root.trim()),
            algorithm: self.keygen_form.algorithm,
        };
        if let Err(error) = validate_keygen_request(&request) {
            self.finish_error("Key generation", error.to_string());
            return;
        }
        self.last_keygen = None;
        self.last_inspect = None;
        self.last_verify = None;
        let (sender, receiver) = mpsc::channel();
        self.worker = Some(receiver);
        self.pending_label = Some("Keygen");
        self.status = info_banner("Key generation in progress...", &[]);
        thread::spawn(move || {
            let result = run_keygen(&request).map_err(|error| error.to_string());
            let _ = sender.send(TaskMessage::Keygen(result));
        });
    }

    fn start_sign(&mut self) {
        let request = SignRequest {
            archive_path: PathBuf::from(self.sign_form.archive_path.trim()),
            key_path: PathBuf::from(self.sign_form.key_path.trim()),
            placement_override: Some(self.sign_form.placement),
            signature_path: trimmed_optional_path(&self.sign_form.detached_signature_path),
        };
        if let Err(error) = validate_sign_request(&request) {
            self.finish_error("Sign", error.to_string());
            return;
        }
        self.last_verify = None;
        let (sender, receiver) = mpsc::channel();
        self.worker = Some(receiver);
        self.pending_label = Some("Sign");
        self.status = info_banner("Sign in progress...", &[]);
        thread::spawn(move || {
            let result = run_sign(&request).map_err(|error| error.to_string());
            let _ = sender.send(TaskMessage::Sign(result));
        });
    }

    fn start_verify(&mut self) {
        let request = VerifyRequest {
            archive_path: PathBuf::from(self.verify_form.archive_path.trim()),
            public_key_path: PathBuf::from(self.verify_form.public_key_path.trim()),
            signature_path: trimmed_optional_path(&self.verify_form.detached_signature_path),
        };
        if let Err(error) = validate_verify_request(&request) {
            self.finish_error("Verify", error.to_string());
            return;
        }
        let (sender, receiver) = mpsc::channel();
        self.worker = Some(receiver);
        self.pending_label = Some("Verify");
        self.status = info_banner("Verify in progress...", &[]);
        thread::spawn(move || {
            let result = verify_report(&request).map_err(|error| error.to_string());
            let _ = sender.send(TaskMessage::Verify(result));
        });
    }

    fn start_extract(&mut self) {
        let request = ExtractRequest {
            archive_path: PathBuf::from(self.extract_form.archive_path.trim()),
            output_dir: PathBuf::from(self.extract_form.output_dir.trim()),
            public_key_path: trimmed_optional_path(&self.extract_form.public_key_path),
            signature_path: trimmed_optional_path(&self.extract_form.detached_signature_path),
            recipient_key_path: trimmed_optional_path(&self.extract_form.recipient_key_path),
        };
        if let Err(error) = validate_extract_request(&request) {
            self.finish_error("Extract", error.to_string());
            return;
        }
        self.last_inspect = None;
        self.last_verify = None;
        let (sender, receiver) = mpsc::channel();
        self.worker = Some(receiver);
        self.pending_label = Some("Extract");
        self.status = info_banner("Extract in progress...", &[]);
        thread::spawn(move || {
            let result = run_extract(&request).map_err(|error| error.to_string());
            let _ = sender.send(TaskMessage::Extract(result));
        });
    }

    fn start_inspect(&mut self) {
        let request = InspectRequest {
            archive_path: PathBuf::from(self.inspect_form.archive_path.trim()),
        };
        if let Err(error) = validate_inspect_request(&request) {
            self.finish_error("Inspect", error.to_string());
            return;
        }
        let (sender, receiver) = mpsc::channel();
        self.worker = Some(receiver);
        self.pending_label = Some("Inspect");
        self.status = info_banner("Inspect in progress...", &[]);
        thread::spawn(move || {
            let result = inspect_report(&request).map_err(|error| error.to_string());
            let _ = sender.send(TaskMessage::Inspect(result));
        });
    }

    fn poll_worker(&mut self, ctx: &egui::Context) {
        if let Some(receiver) = &self.worker {
            match receiver.try_recv() {
                Ok(message) => {
                    self.worker = None;
                    self.pending_label = None;
                    match message {
                        TaskMessage::Pack(result) => match result {
                            Ok(log) => self.finish_success("Pack", log),
                            Err(error) => self.finish_error("Pack", error),
                        },
                        TaskMessage::Keygen(result) => match result {
                            Ok(report) => {
                                self.log = report.log.clone();
                                self.status = StatusBanner {
                                    kind: StatusKind::Success,
                                    title: "Key generation completed successfully".into(),
                                    detail_lines: vec![
                                        format!("Algorithm: {}", report.algorithm.as_str()),
                                        format!("Keys folder: {}", report.keys_dir.display()),
                                        format!(
                                            "Private key: {}",
                                            report.private_key_path.display()
                                        ),
                                        format!("Public key: {}", report.public_key_path.display()),
                                    ],
                                    action: None,
                                };
                                self.last_keygen = Some(report);
                            }
                            Err(error) => self.finish_error("Key generation", error),
                        },
                        TaskMessage::Sign(result) => match result {
                            Ok(log) => self.finish_success("Sign", log),
                            Err(error) => self.finish_error("Sign", error),
                        },
                        TaskMessage::Verify(result) => match result {
                            Ok(report) => {
                                self.log = report.log.clone();
                                self.status = StatusBanner {
                                    kind: StatusKind::Success,
                                    title: "Verify completed successfully".into(),
                                    detail_lines: vec![
                                        format!("Archive: {}", report.archive_path.display()),
                                        format!("Signature: {}", report.signature_status),
                                        format!("File hashes: {}", report.file_hash_status),
                                        format!("Files checked: {}", report.files_checked),
                                    ],
                                    action: None,
                                };
                                self.last_verify = Some(report);
                            }
                            Err(error) => self.finish_error("Verify", error),
                        },
                        TaskMessage::Extract(result) => match result {
                            Ok(log) => self.finish_success("Extract", log),
                            Err(error) => self.finish_error("Extract", error),
                        },
                        TaskMessage::Inspect(result) => match result {
                            Ok(report) => {
                                self.log = report.log.clone();
                                self.status = StatusBanner {
                                    kind: StatusKind::Success,
                                    title: "Inspect completed successfully".into(),
                                    detail_lines: vec![
                                        format!("Archive: {}", report.archive_path.display()),
                                        format!("Files: {}", report.files.len()),
                                        format!(
                                            "Signature: {} / {}",
                                            report.signature_algorithm.as_str(),
                                            report.signature_placement.as_str()
                                        ),
                                        format!(
                                            "Encryption: {}",
                                            if report.encrypted { "enabled" } else { "none" }
                                        ),
                                    ],
                                    action: None,
                                };
                                self.last_inspect = Some(report);
                            }
                            Err(error) => self.finish_error("Inspect", error),
                        },
                    }
                }
                Err(mpsc::TryRecvError::Empty) => {
                    ctx.request_repaint_after(Duration::from_millis(100));
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.worker = None;
                    self.pending_label = None;
                    self.finish_error("Desktop task", "background worker disconnected".into());
                }
            }
        }
    }

    fn finish_success(&mut self, label: &str, log: String) {
        self.log = log;
        let action = if label == "Extract" {
            trimmed_optional_path(&self.extract_form.output_dir).map(|path| StatusAction {
                label: "Open output folder",
                path,
            })
        } else {
            None
        };
        self.status = StatusBanner {
            kind: StatusKind::Success,
            title: format!("{label} completed successfully"),
            detail_lines: summary_lines(&self.log, 4),
            action,
        };
    }

    fn finish_error(&mut self, label: &str, error: String) {
        self.log = format!("{label} failed\n{error}");
        self.status = StatusBanner {
            kind: StatusKind::Error,
            title: format!("{label} failed"),
            detail_lines: summary_lines(&self.log, 5),
            action: None,
        };
    }

    fn render_sidebar(&mut self, ctx: &egui::Context) {
        #[allow(deprecated)]
        egui::Panel::left("workflow-sidebar")
            .resizable(false)
            .min_size(170.0)
            .show(ctx, |ui| {
                let previous_workflow = self.active_workflow;
                ui.heading("QSRL Desktop")
                    .on_hover_text("Made by Steve Tippeconnic");
                ui.separator();
                for workflow in Workflow::main_workflows() {
                    ui.selectable_value(&mut self.active_workflow, workflow, workflow.label());
                }
                ui.separator();
                ui.label(RichText::new("Workspace").strong());
                hover_copy_value(ui, &self.root.display().to_string(), true);
                ui.add_space(8.0);
                ui.label(RichText::new("Build mode").strong());
                if cfg!(feature = "liboqs-backend") {
                    ui.label("liboqs backend enabled");
                } else {
                    ui.label("stub signing backend");
                }
                if let Some(label) = self.pending_label {
                    ui.add_space(12.0);
                    ui.label(RichText::new(format!("{label} running...")).strong());
                }
                ui.separator();
                ui.selectable_value(
                    &mut self.active_workflow,
                    Workflow::Info,
                    Workflow::Info.label(),
                );
                if previous_workflow != self.active_workflow && !self.is_busy() {
                    self.status = StatusBanner::empty();
                }
            });
    }

    fn render_status(&self, ui: &mut egui::Ui) {
        if self.status.is_empty() {
            return;
        }
        let color = match self.status.kind {
            StatusKind::Success => QWORK_GREEN,
            StatusKind::Error => QWORK_ERROR,
            StatusKind::Info => QWORK_BLUE,
            StatusKind::Warning => QWORK_GREEN,
        };
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.colored_label(color, RichText::new(&self.status.title).strong());
            for line in &self.status.detail_lines {
                ui.label(line);
            }
            if let Some(action) = &self.status.action {
                ui.add_space(6.0);
                if ui.button(action.label).clicked()
                    && let Err(error) = open_in_file_manager(&action.path)
                {
                    ui.ctx().copy_text(action.path.display().to_string());
                    ui.label(format!("Could not open folder: {error}"));
                }
                ui.label(RichText::new(action.path.display().to_string()).small());
            }
        });
    }

    fn render_pack(&mut self, ui: &mut egui::Ui) {
        ui.heading("Pack");
        ui.label("Package a folder into a .qsrl archive.");
        ui.add_space(8.0);

        ui.add_enabled_ui(!self.is_busy(), |ui| {
            path_row_directory(
                ui,
                &self.root,
                "Input folder",
                &mut self.pack_form.input_path,
            );
            path_row_save_archive(
                ui,
                &self.root,
                "Output archive",
                &mut self.pack_form.output_path,
            );

            enum_combo(
                ui,
                "Signature algorithm",
                &mut self.pack_form.signature_algorithm,
                &[
                    (SignatureAlgorithm::MlDsa, "ml-dsa"),
                    (SignatureAlgorithm::SlhDsa, "slh-dsa"),
                ],
            );
            enum_combo(
                ui,
                "Manifest encoding",
                &mut self.pack_form.manifest_encoding,
                &[
                    (ManifestEncoding::TextV1, "text-v1"),
                    (ManifestEncoding::BinaryV1, "binary-v1"),
                ],
            );
            enum_combo(
                ui,
                "Compression mode",
                &mut self.pack_form.compression_mode,
                &[
                    (CompressionMode::None, "none"),
                    (CompressionMode::Rle, "rle"),
                ],
            );
            enum_combo(
                ui,
                "Compression layout",
                &mut self.pack_form.compression_layout,
                &[
                    (CompressionLayout::PerFile, "per-file"),
                    (CompressionLayout::WholeArchive, "whole-archive"),
                ],
            );

            ui.add_space(8.0);
            ui.label(RichText::new("Recipient public keys").strong());
            ui.label("Leave blank for a signed-only archive.");
            let mut remove_index = None;
            let recipient_count = self.pack_form.recipient_keys.len();
            for (index, path) in self.pack_form.recipient_keys.iter_mut().enumerate() {
                ui.horizontal(|ui| {
                    form_label(ui, &format!("Recipient {}", index + 1));
                    let response = form_text_field(
                        ui,
                        path,
                        FORM_BROWSE_BUTTON_WIDTH + ui.spacing().item_spacing.x,
                    );
                    if !path.trim().is_empty() {
                        response.on_hover_text(path.clone());
                    }
                    if browse_button(ui).clicked()
                        && let Some(selected) =
                            pick_file(&self.root, path, Some(("Public keys", &["public"])))
                    {
                        *path = selected.display().to_string();
                    }
                    if recipient_count > 1 && ui.button("Remove").clicked() {
                        remove_index = Some(index);
                    }
                });
            }
            if let Some(index) = remove_index {
                self.pack_form.recipient_keys.remove(index);
            }
            if ui.button("Add recipient").clicked() {
                self.pack_form.recipient_keys.push(String::new());
            }

            ui.add_space(12.0);
            if ui.button("Run pack").clicked() {
                self.start_pack();
            }
            if let Some(request) = self.pending_empty_pack_request.clone() {
                ui.add_space(10.0);
                egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui.colored_label(QWORK_GREEN, RichText::new("Empty archive warning").strong());
                    ui.label(format!(
                        "No files were found under {}.",
                        request.input_path.display()
                    ));
                    ui.horizontal(|ui| {
                        if ui.button("Pack empty archive anyway").clicked() {
                            self.pending_empty_pack_request = None;
                            self.launch_pack_task(request.clone());
                        }
                        if ui.button("Cancel").clicked() {
                            self.pending_empty_pack_request = None;
                            self.status = StatusBanner::empty();
                        }
                    });
                });
            }
        });
    }

    fn render_keygen(&mut self, ui: &mut egui::Ui) {
        ui.heading("Key Generation");
        ui.label("Generate local signing or recipient keys into a keys/ folder.");
        ui.add_space(8.0);

        ui.add_enabled_ui(!self.is_busy(), |ui| {
            path_row_directory(
                ui,
                &self.root,
                "Output root",
                &mut self.keygen_form.output_root,
            );
            metadata_path_row(
                ui,
                "Keys folder",
                &PathBuf::from(self.keygen_form.output_root.trim()).join("keys"),
            );
            enum_combo(
                ui,
                "Algorithm",
                &mut self.keygen_form.algorithm,
                &[
                    (KeygenAlgorithm::MlDsa, "ml-dsa"),
                    (KeygenAlgorithm::SlhDsa, "slh-dsa"),
                    (KeygenAlgorithm::MlKemRecipient, "ml-kem"),
                ],
            );
            ui.add_space(12.0);
            if ui.button("Generate keypair").clicked() {
                self.start_keygen();
            }
        });

        if let Some(report) = &self.last_keygen {
            ui.add_space(12.0);
            ui.separator();
            ui.label(RichText::new("Generated key files").strong());
            metadata_row(ui, "Algorithm", report.algorithm.as_str());
            metadata_path_row(ui, "Output root", &report.output_root);
            metadata_path_row(ui, "Keys folder", &report.keys_dir);
            metadata_path_row(ui, "Private key", &report.private_key_path);
            metadata_path_row(ui, "Public key", &report.public_key_path);
        }
    }

    fn render_sign(&mut self, ui: &mut egui::Ui) {
        ui.heading("Sign");
        ui.label("Attach an embedded signature or write a detached signature file.");
        ui.add_space(8.0);

        ui.add_enabled_ui(!self.is_busy(), |ui| {
            path_row_file(
                ui,
                &self.root,
                "Archive",
                &mut self.sign_form.archive_path,
                Some(("QSRL archives", &["qsrl"])),
            );
            path_row_file(
                ui,
                &self.root,
                "Private key",
                &mut self.sign_form.key_path,
                Some(("Private keys", &["private"])),
            );
            enum_combo(
                ui,
                "Signature placement",
                &mut self.sign_form.placement,
                &[
                    (SignaturePlacement::Embedded, "embedded"),
                    (SignaturePlacement::Detached, "detached"),
                ],
            );
            if self.sign_form.placement == SignaturePlacement::Detached {
                path_row_save_signature(
                    ui,
                    &self.root,
                    "Detached signature",
                    &mut self.sign_form.detached_signature_path,
                );
            }
            ui.add_space(12.0);
            if ui.button("Run sign").clicked() {
                self.start_sign();
            }
        });
    }

    fn render_verify(&mut self, ui: &mut egui::Ui) {
        ui.heading("Verify");
        ui.label(
            "Verify the archive signature and check file hashes when the payload is plaintext.",
        );
        ui.add_space(8.0);

        ui.add_enabled_ui(!self.is_busy(), |ui| {
            path_row_file(
                ui,
                &self.root,
                "Archive",
                &mut self.verify_form.archive_path,
                Some(("QSRL archives", &["qsrl"])),
            );
            path_row_file(
                ui,
                &self.root,
                "Public key",
                &mut self.verify_form.public_key_path,
                Some(("Public keys", &["public"])),
            );
            path_row_file(
                ui,
                &self.root,
                "Detached signature (optional)",
                &mut self.verify_form.detached_signature_path,
                Some(("Signature files", &["sig"])),
            );
            ui.add_space(12.0);
            if ui.button("Run verify").clicked() {
                self.start_verify();
            }
        });

        if let Some(report) = &self.last_verify {
            ui.add_space(12.0);
            ui.separator();
            ui.label(RichText::new("Verification summary").strong());
            metadata_path_row(ui, "Archive", &report.archive_path);
            metadata_row(ui, "Signature", &report.signature_status);
            metadata_row(ui, "File hashes", &report.file_hash_status);
            metadata_row(ui, "Files checked", &report.files_checked.to_string());
            metadata_row(ui, "Placement", report.placement.as_str());
            metadata_row(ui, "Algorithm", report.algorithm.as_str());
        }
    }

    fn render_extract(&mut self, ui: &mut egui::Ui) {
        ui.heading("Extract");
        ui.label(
            "Extract files safely into an output directory and verify integrity before writing.",
        );
        ui.add_space(8.0);

        ui.add_enabled_ui(!self.is_busy(), |ui| {
            path_row_file(
                ui,
                &self.root,
                "Archive",
                &mut self.extract_form.archive_path,
                Some(("QSRL archives", &["qsrl"])),
            );
            path_row_directory(
                ui,
                &self.root,
                "Output directory",
                &mut self.extract_form.output_dir,
            );
            path_row_file(
                ui,
                &self.root,
                "Public key for signature check (optional)",
                &mut self.extract_form.public_key_path,
                Some(("Public keys", &["public"])),
            );
            path_row_file(
                ui,
                &self.root,
                "Detached signature (optional)",
                &mut self.extract_form.detached_signature_path,
                Some(("Signature files", &["sig"])),
            );
            path_row_file(
                ui,
                &self.root,
                "Recipient private key (required if encrypted)",
                &mut self.extract_form.recipient_key_path,
                Some(("Private keys", &["private"])),
            );
            ui.add_space(12.0);
            if ui.button("Run extract").clicked() {
                self.start_extract();
            }
        });

        if matches!(self.status.kind, StatusKind::Success)
            && self
                .status
                .action
                .as_ref()
                .map(|action| action.label == "Open output folder")
                .unwrap_or(false)
        {
            ui.add_space(12.0);
            ui.separator();
            ui.label(RichText::new("Extraction summary").strong());
            if let Some(action) = &self.status.action {
                metadata_path_row(ui, "Output folder", &action.path);
            }
        }
    }

    fn render_inspect(&mut self, ui: &mut egui::Ui) {
        ui.heading("Inspect");
        ui.label("Read archive metadata directly from the existing QSRL parser.");
        ui.add_space(8.0);

        ui.add_enabled_ui(!self.is_busy(), |ui| {
            path_row_file(
                ui,
                &self.root,
                "Archive",
                &mut self.inspect_form.archive_path,
                Some(("QSRL archives", &["qsrl"])),
            );
            ui.add_space(12.0);
            if ui.button("Run inspect").clicked() {
                self.start_inspect();
            }
        });

        if let Some(report) = &self.last_inspect {
            ui.add_space(12.0);
            ui.separator();
            ui.label(RichText::new("Archive metadata").strong());
            metadata_row(ui, "Format version", &report.format_version.to_string());
            metadata_row(
                ui,
                "Signature algorithm",
                report.signature_algorithm.as_str(),
            );
            metadata_row(
                ui,
                "Signature placement",
                report.signature_placement.as_str(),
            );
            metadata_row(ui, "Signature scope", &report.signature_scope);
            metadata_row(ui, "Manifest encoding", report.manifest_encoding.as_str());
            metadata_row(
                ui,
                "Compression",
                &format!(
                    "{} / {}",
                    report.compression_mode.as_str(),
                    report.compression_layout.as_str()
                ),
            );
            metadata_row(ui, "Encrypted", if report.encrypted { "yes" } else { "no" });
            metadata_row(ui, "Recipient count", &report.recipient_count.to_string());
            metadata_row(
                ui,
                "KEM method",
                report.kem_method.as_deref().unwrap_or("n/a"),
            );
            metadata_row(
                ui,
                "AEAD method",
                report.aead_method.as_deref().unwrap_or("n/a"),
            );
            metadata_row(ui, "Signature status", &report.signature_status);

            ui.add_space(8.0);
            ui.label(RichText::new("Files").strong());
            for file in &report.files {
                egui::Frame::group(ui.style()).show(ui, |ui| {
                    metadata_row(ui, "Path", &file.path);
                    metadata_row(ui, "Size", &format!("{} bytes", file.size));
                    metadata_row(ui, "SHA-256", &file.sha256_hex);
                    metadata_row(ui, "Compression", file.compression.as_str());
                });
                ui.add_space(6.0);
            }
        }
    }

    fn render_info(&self, ui: &mut egui::Ui) {
        ui.heading("Info");
        ui.label("Local reference for the QSRL desktop sections.");
        ui.add_space(8.0);

        ScrollArea::vertical().show(ui, |ui| {
            info_section(
                ui,
                "Keygen",
                "Creates local ML-DSA, SLH-DSA, and ML-KEM keypairs. ML-DSA and SLH-DSA are used for signatures. ML-KEM is used for recipient key encapsulation. Private key files stay local.",
            );
            info_section(
                ui,
                "Pack",
                "Packages a folder into a .qsrl archive. The archive records an inspectable manifest, file metadata, hashes, compression settings, and optional recipient encryption metadata.",
            );
            info_section(
                ui,
                "Sign",
                "Signs an archive using a private signature key. QSRL supports embedded signatures and detached .sig files.",
            );
            info_section(
                ui,
                "Verify",
                "Checks an archive signature using the matching public key. For encrypted archives, verification can check the signature, while encrypted payload authentication happens during decrypt/extract.",
            );
            info_section(
                ui,
                "Extract",
                "Restores files from a .qsrl archive into an output folder. For signed archives, providing the public key checks the signature. For encrypted archives, the matching ML-KEM recipient private key is required to recover the archive key and decrypt the AES-256-GCM protected payload.",
            );
            info_section(
                ui,
                "Inspect",
                "Reads archive metadata without extracting files. It shows the format version, signature information, manifest settings, compression settings, encryption status, recipient count, and file hashes.",
            );
        });
    }
}

impl eframe::App for QsrlDesktopApp {
    #[allow(deprecated)]
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.poll_worker(&ctx);
        self.render_sidebar(&ctx);

        egui::Panel::bottom("output-log")
            .resizable(true)
            .min_size(180.0)
            .default_size(240.0)
            .show(&ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Output log").strong());
                    if ui.button("Clear").clicked() && !self.is_busy() {
                        self.log.clear();
                    }
                });
                let mut selectable_log = self.log.clone();
                ui.add(
                    TextEdit::multiline(&mut selectable_log)
                        .desired_rows(12)
                        .code_editor()
                        .desired_width(f32::INFINITY),
                );
            });

        egui::CentralPanel::default().show(&ctx, |ui| {
            self.render_status(ui);
            ui.add_space(10.0);
            match self.active_workflow {
                Workflow::Info => self.render_info(ui),
                _ => {
                    ScrollArea::vertical()
                        .auto_shrink([false, false])
                        .show(ui, |ui| match self.active_workflow {
                            Workflow::Pack => self.render_pack(ui),
                            Workflow::Keygen => self.render_keygen(ui),
                            Workflow::Sign => self.render_sign(ui),
                            Workflow::Verify => self.render_verify(ui),
                            Workflow::Extract => self.render_extract(ui),
                            Workflow::Inspect => self.render_inspect(ui),
                            Workflow::Info => {
                                unreachable!("Info is rendered outside this scroll area")
                            }
                        });
                }
            }
        });
    }
}

fn info_section(ui: &mut egui::Ui, title: &str, body: &str) {
    ui.label(RichText::new(title).strong().color(QWORK_GREEN));
    ui.add_space(3.0);
    ui.label(RichText::new(body).color(QWORK_WHITE));
    ui.add_space(12.0);
}

fn form_label(ui: &mut egui::Ui, label: &str) {
    ui.allocate_ui_with_layout(
        egui::vec2(FORM_LABEL_WIDTH, FORM_ROW_HEIGHT),
        egui::Layout::right_to_left(egui::Align::Center),
        |ui| {
            ui.label(RichText::new(label).strong().color(QWORK_GREEN));
        },
    );
}

fn responsive_field_width(ui: &egui::Ui, trailing_width: f32) -> f32 {
    (ui.available_width() - trailing_width).clamp(FORM_FIELD_MIN_WIDTH, FORM_FIELD_WIDTH)
}

fn path_row_trailing_width(ui: &egui::Ui) -> f32 {
    FORM_BROWSE_BUTTON_WIDTH + FORM_COPY_BUTTON_WIDTH + (ui.spacing().item_spacing.x * 2.0)
}

fn form_text_field(ui: &mut egui::Ui, value: &mut String, trailing_width: f32) -> egui::Response {
    ui.add_sized(
        [responsive_field_width(ui, trailing_width), FORM_ROW_HEIGHT],
        TextEdit::singleline(value),
    )
}

fn browse_button(ui: &mut egui::Ui) -> egui::Response {
    ui.add_sized(
        [FORM_BROWSE_BUTTON_WIDTH, FORM_ROW_HEIGHT],
        egui::Button::new("Browse"),
    )
}

fn metadata_row(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.horizontal(|ui| {
        form_label(ui, label);
        hover_copy_value(ui, value, false);
    });
}

fn metadata_path_row(ui: &mut egui::Ui, label: &str, path: &Path) {
    ui.horizontal(|ui| {
        form_label(ui, label);
        hover_copy_value(ui, &path.display().to_string(), true);
    });
}

fn enum_combo<T>(ui: &mut egui::Ui, label: &str, value: &mut T, options: &[(T, &str)])
where
    T: Copy + PartialEq,
{
    ui.horizontal(|ui| {
        form_label(ui, label);
        egui::ComboBox::from_id_salt(label)
            .width(responsive_field_width(ui, 0.0))
            .selected_text(
                options
                    .iter()
                    .find_map(|(option, text)| (*option == *value).then_some(*text))
                    .unwrap_or("select"),
            )
            .show_ui(ui, |ui| {
                for (option, text) in options {
                    ui.selectable_value(value, *option, *text);
                }
            });
    });
}

fn path_row_directory(ui: &mut egui::Ui, root: &Path, label: &str, value: &mut String) {
    ui.horizontal(|ui| {
        form_label(ui, label);
        let response = form_text_field(ui, value, path_row_trailing_width(ui));
        if !value.trim().is_empty() {
            response.on_hover_text(value.clone());
        }
        if browse_button(ui).clicked()
            && let Some(selected) = pick_folder(root, value)
        {
            *value = selected.display().to_string();
        }
        copy_path_button(ui, value);
    });
}

fn path_row_file(
    ui: &mut egui::Ui,
    root: &Path,
    label: &str,
    value: &mut String,
    filter: Option<(&str, &[&str])>,
) {
    ui.horizontal(|ui| {
        form_label(ui, label);
        let response = form_text_field(ui, value, path_row_trailing_width(ui));
        if !value.trim().is_empty() {
            response.on_hover_text(value.clone());
        }
        if browse_button(ui).clicked()
            && let Some(selected) = pick_file(root, value, filter)
        {
            *value = selected.display().to_string();
        }
        copy_path_button(ui, value);
    });
}

fn path_row_save_archive(ui: &mut egui::Ui, root: &Path, label: &str, value: &mut String) {
    ui.horizontal(|ui| {
        form_label(ui, label);
        let response = form_text_field(ui, value, path_row_trailing_width(ui));
        if !value.trim().is_empty() {
            response.on_hover_text(value.clone());
        }
        if browse_button(ui).clicked()
            && let Some(selected) = save_file(
                root,
                value,
                "archive.qsrl",
                Some(("QSRL archives", &["qsrl"])),
            )
        {
            *value = ensure_extension(selected, "qsrl").display().to_string();
        }
        copy_path_button(ui, value);
    });
}

fn path_row_save_signature(ui: &mut egui::Ui, root: &Path, label: &str, value: &mut String) {
    ui.horizontal(|ui| {
        form_label(ui, label);
        let response = form_text_field(ui, value, path_row_trailing_width(ui));
        if !value.trim().is_empty() {
            response.on_hover_text(value.clone());
        }
        if browse_button(ui).clicked()
            && let Some(selected) = save_file(
                root,
                value,
                "archive.qsrl.sig",
                Some(("Signature files", &["sig"])),
            )
        {
            *value = ensure_extension(selected, "sig").display().to_string();
        }
        copy_path_button(ui, value);
    });
}

fn pick_folder(root: &Path, current: &str) -> Option<PathBuf> {
    let mut dialog = rfd::FileDialog::new();
    if let Some(start_dir) = dialog_start_dir(root, current) {
        dialog = dialog.set_directory(start_dir);
    }
    dialog.pick_folder()
}

fn pick_file(root: &Path, current: &str, filter: Option<(&str, &[&str])>) -> Option<PathBuf> {
    let mut dialog = rfd::FileDialog::new();
    if let Some(start_dir) = dialog_start_dir(root, current) {
        dialog = dialog.set_directory(start_dir);
    }
    if let Some((label, extensions)) = filter {
        dialog = dialog.add_filter(label, extensions);
    }
    dialog.pick_file()
}

fn save_file(
    root: &Path,
    current: &str,
    default_name: &str,
    filter: Option<(&str, &[&str])>,
) -> Option<PathBuf> {
    let mut dialog = rfd::FileDialog::new();
    if let Some(start_dir) = dialog_start_dir(root, current) {
        dialog = dialog.set_directory(start_dir);
    }
    dialog = dialog.set_file_name(default_name);
    if let Some((label, extensions)) = filter {
        dialog = dialog.add_filter(label, extensions);
    }
    dialog.save_file()
}

fn dialog_start_dir(root: &Path, current: &str) -> Option<PathBuf> {
    let trimmed = current.trim();
    if trimmed.is_empty() {
        return Some(root.to_path_buf());
    }
    let path = PathBuf::from(trimmed);
    if path.is_dir() {
        Some(path)
    } else {
        path.parent()
            .map(Path::to_path_buf)
            .or_else(|| Some(root.to_path_buf()))
    }
}

fn trimmed_optional_path(value: &str) -> Option<PathBuf> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(PathBuf::from(trimmed))
    }
}

fn ensure_extension(mut path: PathBuf, extension: &str) -> PathBuf {
    if path.extension().and_then(|value| value.to_str()) != Some(extension) {
        path.set_extension(extension);
    }
    path
}

fn info_banner(title: &str, details: &[&str]) -> StatusBanner {
    StatusBanner {
        kind: StatusKind::Info,
        title: title.into(),
        detail_lines: details.iter().map(|value| value.to_string()).collect(),
        action: None,
    }
}

fn summary_lines(log: &str, max_lines: usize) -> Vec<String> {
    log.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .take(max_lines)
        .map(ToOwned::to_owned)
        .collect()
}

fn copy_path_button(ui: &mut egui::Ui, value: &str) {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        ui.allocate_space(egui::vec2(FORM_COPY_BUTTON_WIDTH, FORM_ROW_HEIGHT));
        return;
    }
    if ui
        .add_sized(
            [FORM_COPY_BUTTON_WIDTH, FORM_ROW_HEIGHT],
            egui::Button::new("Copy"),
        )
        .on_hover_text("Copy path")
        .clicked()
    {
        ui.ctx().copy_text(trimmed.to_string());
    }
}

fn hover_copy_value(ui: &mut egui::Ui, value: &str, monospace: bool) {
    let copy_width = FORM_COPY_BUTTON_WIDTH + ui.spacing().item_spacing.x;
    let value_width = (ui.available_width() - copy_width).max(80.0);
    let available_chars = (value_width / 8.0).floor() as usize;
    let shortened = shorten_middle(value, available_chars.clamp(8, 72));
    let text = if monospace {
        RichText::new(shortened.clone()).monospace()
    } else {
        RichText::new(shortened.clone())
    };
    let response = ui
        .add_sized([value_width, FORM_ROW_HEIGHT], egui::Label::new(text))
        .on_hover_text(value.to_string());
    if response.double_clicked() {
        ui.ctx().copy_text(value.to_string());
    }
    if ui
        .add_sized(
            [FORM_COPY_BUTTON_WIDTH, FORM_ROW_HEIGHT],
            egui::Button::new("Copy"),
        )
        .on_hover_text("Copy full value")
        .clicked()
    {
        ui.ctx().copy_text(value.to_string());
    }
}

fn shorten_middle(value: &str, max_chars: usize) -> String {
    let total = value.chars().count();
    if total <= max_chars {
        return value.to_string();
    }
    let keep_each_side = max_chars.saturating_sub(3) / 2;
    let start: String = value.chars().take(keep_each_side).collect();
    let end: String = value
        .chars()
        .rev()
        .take(keep_each_side)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    format!("{start}...{end}")
}

fn open_in_file_manager(path: &Path) -> Result<(), String> {
    let mut command = if cfg!(target_os = "macos") {
        let mut command = Command::new("open");
        command.arg(path);
        command
    } else if cfg!(target_os = "windows") {
        let mut command = Command::new("explorer");
        command.arg(path);
        command
    } else {
        let mut command = Command::new("xdg-open");
        command.arg(path);
        command
    };
    let status = command
        .status()
        .map_err(|error| format!("launching system file manager: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("system file manager exited with status {status}"))
    }
}
