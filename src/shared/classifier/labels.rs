//! Classifier label order — must match `manifest.json` and the subtype output tensor.

pub const INSTRUCTION_HIJACKING_LABELS: &[&str] = &[
    "instruction_override",
    "instruction_forgetting",
    "reset_system",
    "bypass_security",
    "information_extraction",
];

pub const ROLE_CONFUSION_LABELS: &[&str] = &[
    "role_assumption",
    "mode_switching",
    "permission_assertion",
    "role_indicator",
];

pub const TOOL_USE_HIJACKING_LABELS: &[&str] = &["tool_use_hijacking"];

/// Full label order matching `manifest.json` and the subtype output tensor.
pub const CLASSIFIER_LABELS: &[&str] = &[
    "instruction_override",
    "instruction_forgetting",
    "reset_system",
    "bypass_security",
    "information_extraction",
    "role_assumption",
    "mode_switching",
    "permission_assertion",
    "role_indicator",
    "tool_use_hijacking",
];

pub type ClassifierLabel = String;

/// Attack family filter for [`super::combined::CombinedClassifier::classify_family`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClassifierFamily {
    InstructionHijacking,
    RoleConfusion,
    ToolUseHijacking,
}

impl ClassifierFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            ClassifierFamily::InstructionHijacking => "instruction_hijacking",
            ClassifierFamily::RoleConfusion => "role_confusion",
            ClassifierFamily::ToolUseHijacking => "tool_use_hijacking",
        }
    }
}

pub fn labels_for_family(family: ClassifierFamily) -> &'static [&'static str] {
    match family {
        ClassifierFamily::InstructionHijacking => INSTRUCTION_HIJACKING_LABELS,
        ClassifierFamily::RoleConfusion => ROLE_CONFUSION_LABELS,
        ClassifierFamily::ToolUseHijacking => TOOL_USE_HIJACKING_LABELS,
    }
}
