use std::path::{Path, PathBuf};

use crate::RunnerError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StageDirectory {
    Input,
    Output,
    Home,
    Config,
    Data,
    Cache,
    Temp,
    Runtime,
    Reports,
}

impl StageDirectory {
    const fn name(self) -> &'static str {
        match self {
            Self::Input => "input",
            Self::Output => "output",
            Self::Home => "home",
            Self::Config => "config",
            Self::Data => "data",
            Self::Cache => "cache",
            Self::Temp => "temp",
            Self::Runtime => "runtime",
            Self::Reports => "reports",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StageLayout {
    root: PathBuf,
}

impl StageLayout {
    pub fn new(root: PathBuf) -> Result<Self, RunnerError> {
        root.is_absolute()
            .then_some(Self { root })
            .ok_or(RunnerError::InvalidStage)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn path(&self, directory: StageDirectory) -> PathBuf {
        self.root.join(directory.name())
    }
}
