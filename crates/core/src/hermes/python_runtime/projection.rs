use super::super::python_installation::{PythonInstallation, real_path};
use super::{
    RuntimeFile, SourceRoot, invalid, literals, preparation::Control, read_file, stage_path,
};
use context_relay_protocol::ClientError;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

pub(super) struct Projection {
    pub roots: Vec<SourceRoot>,
    pub generated: Vec<(String, Vec<u8>)>,
    pub controls: Vec<RuntimeFile>,
}

#[cfg(test)]
pub(super) fn build(installation: &PythonInstallation) -> Result<Projection, ClientError> {
    build_controlled(
        installation,
        &Control::new(&std::sync::atomic::AtomicBool::new(false), &mut |_| {}),
    )
}

pub(super) fn build_controlled(
    installation: &PythonInstallation,
    preparation: &Control<'_>,
) -> Result<Projection, ClientError> {
    preparation.check()?;
    let mut plan = Projection {
        roots: vec![
            SourceRoot {
                source: installation.python_home.clone(),
                destination: "python".into(),
            },
            SourceRoot {
                source: installation.site_packages.clone(),
                destination: "packages".into(),
            },
        ],
        generated: Vec::new(),
        controls: Vec::new(),
    };
    let mut modules = BTreeMap::new();
    if let Some(source) = &installation.editable_source {
        let project = control(
            &source.join("pyproject.toml"),
            "source/pyproject.toml",
            &mut plan,
            preparation,
        )?;
        plan.roots.push(SourceRoot {
            source: source.join("pyproject.toml"),
            destination: "source/pyproject.toml".into(),
        });
        let doc: toml_edit::DocumentMut = project.parse().map_err(|_| invalid())?;
        let setuptools = doc
            .get("tool")
            .and_then(|tool| tool.get("setuptools"))
            .ok_or_else(invalid)?;
        for name in strings(setuptools.get("py-modules").ok_or_else(invalid)?)? {
            preparation.check()?;
            identifier(&name)?;
            safe_pattern(&name)?;
            let path = real_path(&source.join(format!("{name}.py")), false)?;
            modules.insert(name.clone(), (path.clone(), false));
            plan.roots.push(SourceRoot {
                source: path,
                destination: format!("source/{name}.py"),
            });
        }
        let include = setuptools
            .get("packages")
            .and_then(|value| value.get("find"))
            .and_then(|value| value.get("include"))
            .ok_or_else(invalid)?;
        for pattern in strings(include)? {
            preparation.check()?;
            let name = pattern.strip_suffix(".*").unwrap_or(&pattern);
            identifier(name)?;
            safe_pattern(name)?;
            let path = real_path(&source.join(name), true)?;
            if let Some((existing, directory)) = modules.get(name) {
                if existing != &path || !directory {
                    return Err(invalid());
                }
            } else {
                modules.insert(name.into(), (path.clone(), true));
                plan.roots.push(SourceRoot {
                    source: path,
                    destination: format!("source/{name}"),
                });
            }
        }
        if !modules.contains_key("hermes_cli") {
            return Err(invalid());
        }
        if let Some(data) = setuptools.get("package-data") {
            for (package, patterns) in data.as_table_like().ok_or_else(invalid)?.iter() {
                preparation.check()?;
                if package != "*"
                    && !modules.contains_key(package.split('.').next().ok_or_else(invalid)?)
                {
                    return Err(invalid());
                }
                for pattern in strings(patterns)? {
                    preparation.check()?;
                    safe_pattern(&pattern)?;
                }
            }
        }
        if let Some(data) = setuptools.get("data-files") {
            for (target, patterns) in data.as_table_like().ok_or_else(invalid)?.iter() {
                preparation.check()?;
                stage_path(target)?;
                for pattern in strings(patterns)? {
                    preparation.check()?;
                    safe_pattern(&pattern)?;
                    if !pattern.starts_with(&(target.to_owned() + "/")) {
                        return Err(invalid());
                    }
                }
                add_source_directory(source, target, &mut plan)?;
            }
        }
        let manifest = control(
            &source.join("MANIFEST.in"),
            "source/MANIFEST.in",
            &mut plan,
            preparation,
        )?;
        plan.roots.push(SourceRoot {
            source: source.join("MANIFEST.in"),
            destination: "source/MANIFEST.in".into(),
        });
        for line in manifest
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
        {
            preparation.check()?;
            let parts: Vec<_> = line.split_ascii_whitespace().collect();
            match parts.as_slice() {
                [
                    "graft",
                    name @ ("skills" | "optional-skills" | "optional-mcps" | "locales"),
                ] => add_source_directory(source, name, &mut plan)?,
                ["recursive-include", package, patterns @ ..]
                    if modules
                        .get(*package)
                        .is_some_and(|(_, directory)| *directory)
                        && !patterns.is_empty() =>
                {
                    for pattern in patterns {
                        preparation.check()?;
                        safe_pattern(pattern)?;
                    }
                }
                ["global-exclude", "__pycache__" | "*.py[cod]"] => {}
                _ => return Err(invalid()),
            }
        }
    } else {
        // Wheel data-files are installed under the environment prefix rather
        // than site-packages. These are Hermes's declared sibling-data roots.
        for name in ["skills", "optional-skills", "optional-mcps", "locales"] {
            preparation.check()?;
            let path = installation.venv.join(name);
            match fs::symlink_metadata(&path) {
                Ok(_) => plan.roots.push(SourceRoot {
                    source: real_path(&path, true)?,
                    destination: format!("environment/{name}"),
                }),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(invalid()),
            }
        }
    }
    let (extra_paths, pywin32) = startup_paths(installation, &modules, &mut plan, preparation)?;
    let mut paths = vec![
        "Lib".to_owned(),
        "DLLs".to_owned(),
        "../packages".to_owned(),
    ];
    if installation.editable_source.is_some() {
        paths.push("../source".into());
    }
    paths.extend(
        extra_paths
            .into_iter()
            .map(|path| format!("../packages/{path}")),
    );
    let dlls: Vec<_> = [11, 12, 13]
        .into_iter()
        .filter(|minor| {
            installation
                .python_home
                .join(format!("python3{minor}.dll"))
                .is_file()
        })
        .collect();
    let [minor] = dlls.as_slice() else {
        return Err(invalid());
    };
    plan.generated.push((
        format!("python/python3{minor}._pth"),
        (paths.join("\n") + "\n").into_bytes(),
    ));
    plan.generated
        .push(("bootstrap.py".into(), bootstrap(pywin32).into_bytes()));
    plan.generated.push((
        "environment/.context-relay-prefix".into(),
        b"hermes-python-source-first-v1\n".to_vec(),
    ));
    plan.roots
        .sort_by(|left, right| left.destination.cmp(&right.destination));
    let mut roots: Vec<SourceRoot> = Vec::new();
    for root in plan.roots {
        preparation.check()?;
        let mut matching = None;
        for parent in &roots {
            preparation.check()?;
            if root.destination == parent.destination
                || root
                    .destination
                    .starts_with(&(parent.destination.clone() + "/"))
            {
                matching = Some(parent);
                break;
            }
        }
        if let Some(parent) = matching {
            let suffix = root
                .destination
                .strip_prefix(&parent.destination)
                .ok_or_else(invalid)?
                .trim_start_matches('/');
            if root.source != parent.source.join(suffix) {
                return Err(invalid());
            }
        } else {
            roots.push(root);
        }
    }
    plan.roots = roots;
    Ok(plan)
}

fn strings(item: &toml_edit::Item) -> Result<Vec<String>, ClientError> {
    let array = item.as_array().ok_or_else(invalid)?;
    if array.len() > 256 {
        return Err(invalid());
    }
    array
        .iter()
        .map(|value| value.as_str().map(str::to_owned).ok_or_else(invalid))
        .collect()
}

fn identifier(name: &str) -> Result<(), ClientError> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        || name.as_bytes()[0].is_ascii_digit()
    {
        return Err(invalid());
    }
    Ok(())
}

pub(super) fn safe_pattern(pattern: &str) -> Result<(), ClientError> {
    stage_path(pattern)?;
    if pattern.split('/').any(|part| {
        matches!(
            part.to_ascii_lowercase().as_str(),
            ".env" | ".envrc" | ".git" | "venv" | ".venv" | "node_modules"
        )
    }) {
        return Err(invalid());
    }
    Ok(())
}

fn add_source_directory(
    source: &Path,
    relative: &str,
    plan: &mut Projection,
) -> Result<(), ClientError> {
    safe_pattern(relative)?;
    if relative.contains(['*', '?', '[', ']']) {
        return Err(invalid());
    }
    plan.roots.push(SourceRoot {
        source: real_path(&source.join(relative), true)?,
        destination: format!("source/{relative}"),
    });
    Ok(())
}

fn control(
    path: &Path,
    relative: &str,
    plan: &mut Projection,
    preparation: &Control<'_>,
) -> Result<String, ClientError> {
    preparation.check()?;
    let mut bytes = Vec::new();
    let file = read_file(path, relative, |chunk| {
        preparation.check()?;
        if bytes.len() + chunk.len() > 256 * 1024 {
            return Err(invalid());
        }
        bytes.extend_from_slice(chunk);
        Ok(())
    })?;
    plan.controls.push(file);
    String::from_utf8(bytes).map_err(|_| invalid())
}

fn startup_paths(
    installation: &PythonInstallation,
    modules: &BTreeMap<String, (PathBuf, bool)>,
    plan: &mut Projection,
    preparation: &Control<'_>,
) -> Result<(Vec<String>, bool), ClientError> {
    let mut paths = BTreeSet::new();
    let mut pywin32 = false;
    let mut editable = false;
    let finder_module = format!(
        "__editable___hermes_agent_{}_finder",
        installation.version.replace('.', "_")
    );
    let editable_line = format!("import {finder_module}; {finder_module}.install()");
    for (name, path) in super::children_controlled(&installation.site_packages, preparation)? {
        preparation.check()?;
        if !name.ends_with(".pth") {
            continue;
        }
        let text = control(&path, &format!("packages/{name}"), plan, preparation)?;
        for line in text
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
        {
            preparation.check()?;
            if line == "import _virtualenv" {
                continue;
            }
            if line == "import pywin32_bootstrap" {
                pywin32 = true;
                continue;
            }
            if line == editable_line && installation.editable_source.is_some() {
                if editable
                    || name != format!("__editable__.hermes_agent-{}.pth", installation.version)
                {
                    return Err(invalid());
                }
                editable = true;
                let finder = control(
                    &installation
                        .site_packages
                        .join(format!("{finder_module}.py")),
                    &format!("packages/{finder_module}.py"),
                    plan,
                    preparation,
                )?;
                validate_finder(&finder, installation, modules)?;
                continue;
            }
            if line.starts_with("import ") || line.starts_with("import\t") {
                return Err(invalid());
            }
            let relative = line.replace('\\', "/");
            stage_path(&relative)?;
            real_path(&installation.site_packages.join(&relative), true)?;
            paths.insert(relative);
        }
    }
    if installation.editable_source.is_some() != editable {
        return Err(invalid());
    }
    if pywin32 {
        real_path(&installation.site_packages.join("pywin32_system32"), true)?;
    }
    Ok((paths.into_iter().collect(), pywin32))
}

fn validate_finder(
    text: &str,
    installation: &PythonInstallation,
    modules: &BTreeMap<String, (PathBuf, bool)>,
) -> Result<(), ClientError> {
    let mut normalized = Vec::new();
    let mut mapping = None;
    let mut namespaces = None;
    let placeholder = format!(
        "PATH_PLACEHOLDER = '__editable__.hermes_agent-{}.finder' + \".__path_hook__\"",
        installation.version
    );
    let mut seen_placeholder = false;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("MAPPING: dict[str, str] = ") {
            if mapping.replace(literals::parse(value)?).is_some() {
                return Err(invalid());
            }
            normalized.push("MAPPING: dict[str, str] = {}".to_owned());
        } else if let Some(value) = line.strip_prefix("NAMESPACES: dict[str, list[str]] = ") {
            if namespaces.replace(literals::parse(value)?).is_some() {
                return Err(invalid());
            }
            normalized.push("NAMESPACES: dict[str, list[str]] = {}".to_owned());
        } else if line == placeholder {
            if seen_placeholder {
                return Err(invalid());
            }
            seen_placeholder = true;
            normalized.push("PATH_PLACEHOLDER = \"CONTEXT_RELAY_EDITABLE_NAMESPACE\"".into());
        } else {
            normalized.push(line.to_owned());
        }
    }
    if !seen_placeholder || normalized.join("\n") + "\n" != include_str!("editable_finder.template")
    {
        return Err(invalid());
    }
    let mapping = mapping.ok_or_else(invalid)?;
    let mapping = mapping.as_object().ok_or_else(invalid)?;
    if mapping.len() != modules.len() {
        return Err(invalid());
    }
    for (name, (expected, directory)) in modules {
        let mapped = PathBuf::from(
            mapping
                .get(name)
                .and_then(|value| value.as_str())
                .ok_or_else(invalid)?,
        );
        let mapped = if *directory {
            mapped
        } else {
            mapped.with_extension("py")
        };
        if real_path(&mapped, *directory)? != *expected {
            return Err(invalid());
        }
    }
    let namespaces = namespaces.ok_or_else(invalid)?;
    for (name, paths) in namespaces.as_object().ok_or_else(invalid)? {
        let top = name.split('.').next().ok_or_else(invalid)?;
        if !modules.get(top).is_some_and(|(_, directory)| *directory) {
            return Err(invalid());
        }
        let relative = name.replace('.', "/");
        stage_path(&relative)?;
        let expected = real_path(
            &installation
                .editable_source
                .as_ref()
                .ok_or_else(invalid)?
                .join(relative),
            true,
        )?;
        let paths = paths.as_array().ok_or_else(invalid)?;
        let [path] = paths.as_slice() else {
            return Err(invalid());
        };
        if real_path(Path::new(path.as_str().ok_or_else(invalid)?), true)? != expected {
            return Err(invalid());
        }
    }
    Ok(())
}

fn bootstrap(pywin32: bool) -> String {
    let dll = if pywin32 {
        "_dll_handles = [os.add_dll_directory(str(root / 'packages' / 'pywin32_system32'))]\n"
    } else {
        "_dll_handles = []\n"
    };
    format!(
        "# Context Relay Hermes runtime projection v1\nimport sys\nimport os\nfrom pathlib import Path\nroot = Path(__file__).resolve().parent\nsys.prefix = str(root / 'environment')\nsys.exec_prefix = sys.prefix\nsys.dont_write_bytecode = True\n{dll}args = sys.argv[1:]\nif args == ['path-probe']:\n    import json\n    print(json.dumps({{'paths': sys.path, 'prefix': sys.prefix, 'isolated': sys.flags.isolated, 'noSite': sys.flags.no_site, 'siteLoaded': 'site' in sys.modules}}))\n    raise SystemExit(0)\nif args not in (['--version'], ['config', 'check']) or not os.environ.get('HERMES_HOME'):\n    raise SystemExit(64)\nsys.argv = ['hermes'] + args\nfrom hermes_cli.main import main\nraise SystemExit(main())\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn fixture() -> (tempfile::TempDir, PythonInstallation) {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        let source = root.join("source");
        let packages = source.join("venv/Lib/site-packages");
        for path in [
            &packages,
            &root.join("python/Lib"),
            &root.join("python/DLLs"),
            &source.join("hermes_cli"),
            &source.join("skills"),
            &source.join("optional-skills"),
            &source.join("locales"),
            &source.join("optional-mcps/linear"),
        ] {
            fs::create_dir_all(path).unwrap();
        }
        fs::write(root.join("python/python.exe"), b"MZ base interpreter").unwrap();
        fs::write(root.join("python/python311.dll"), b"MZ runtime").unwrap();
        fs::write(
            source.join("hermes_cli/main.py"),
            b"raise RuntimeError('do not execute')",
        )
        .unwrap();
        fs::write(source.join("helper.py"), b"VALUE = 1").unwrap();
        fs::write(source.join(".env"), b"PRIVATE-MUST-STAY-OUTSIDE").unwrap();
        fs::write(source.join("locales/en.yaml"), b"hello: Hello").unwrap();
        fs::write(
            source.join("optional-mcps/linear/manifest.yaml"),
            b"name: linear",
        )
        .unwrap();
        fs::write(source.join("MANIFEST.in"), b"graft skills\ngraft optional-skills\ngraft locales\ngraft optional-mcps\nglobal-exclude __pycache__\nglobal-exclude *.py[cod]\n").unwrap();
        fs::write(source.join("pyproject.toml"), "[tool.setuptools]\npy-modules = ['helper']\n[tool.setuptools.packages.find]\ninclude = ['hermes_cli', 'hermes_cli.*']\n[tool.setuptools.data-files]\nlocales = ['locales/*.yaml']\n'optional-mcps/linear' = ['optional-mcps/linear/manifest.yaml']\n").unwrap();
        let mapping = serde_json::json!({"hermes_cli":source.join("hermes_cli"),"helper":source.join("helper")});
        let finder = include_str!("editable_finder.template")
            .replace(
                "MAPPING: dict[str, str] = {}",
                &format!("MAPPING: dict[str, str] = {mapping}"),
            )
            .replace(
                "PATH_PLACEHOLDER = \"CONTEXT_RELAY_EDITABLE_NAMESPACE\"",
                "PATH_PLACEHOLDER = '__editable__.hermes_agent-0.17.0.finder' + \".__path_hook__\"",
            );
        fs::write(
            packages.join("__editable___hermes_agent_0_17_0_finder.py"),
            finder,
        )
        .unwrap();
        fs::write(packages.join("__editable__.hermes_agent-0.17.0.pth"), b"import __editable___hermes_agent_0_17_0_finder; __editable___hermes_agent_0_17_0_finder.install()\n").unwrap();
        let installation = PythonInstallation {
            version: "0.17.0".into(),
            venv: source.join("venv"),
            interpreter: source.join("venv/Scripts/python.exe"),
            python_home: root.join("python"),
            site_packages: packages,
            editable_source: Some(source),
            metadata: Vec::new(),
        };
        (temp, installation)
    }

    #[test]
    fn projects_declared_modules_packages_and_sibling_data_without_checkout_secrets() {
        let (_temp, installation) = fixture();
        let plan = build(&installation).unwrap();
        let destinations: Vec<_> = plan
            .roots
            .iter()
            .map(|root| root.destination.as_str())
            .collect();
        for expected in [
            "source/helper.py",
            "source/hermes_cli",
            "source/skills",
            "source/optional-skills",
            "source/locales",
            "source/optional-mcps",
        ] {
            assert!(destinations.contains(&expected), "missing {expected}");
        }
        assert!(!destinations.contains(&"source"));
        assert!(
            !destinations
                .iter()
                .any(|path| path.ends_with(".env") || path.contains("/venv"))
        );
        assert!(
            plan.generated
                .iter()
                .any(|(path, _)| path == "python/python311._pth")
        );
    }

    #[test]
    fn rejects_excluded_package_declarations_even_with_a_matching_finder() {
        for name in ["venv", "node_modules", "VENV"] {
            let (_temp, installation) = fixture();
            let source = installation.editable_source.as_ref().unwrap();
            fs::create_dir_all(source.join(name)).unwrap();
            let project = source.join("pyproject.toml");
            let text = fs::read_to_string(&project)
                .unwrap()
                .replace("'hermes_cli.*'", &format!("'hermes_cli.*', '{name}'"));
            fs::write(&project, text).unwrap();
            let finder = installation
                .site_packages
                .join("__editable___hermes_agent_0_17_0_finder.py");
            let mapping = serde_json::json!({"hermes_cli": source.join("hermes_cli"), "helper": source.join("helper"), name: source.join(name)});
            let body = fs::read_to_string(&finder)
                .unwrap()
                .lines()
                .map(|line| {
                    if line.starts_with("MAPPING: ") {
                        format!("MAPPING: dict[str, str] = {mapping}")
                    } else {
                        line.to_owned()
                    }
                })
                .collect::<Vec<_>>()
                .join("\n")
                + "\n";
            fs::write(finder, body).unwrap();
            assert!(
                build(&installation).is_err(),
                "accepted excluded package {name}"
            );
        }
    }

    #[test]
    fn rejects_modified_finder_and_unknown_executable_startup_lines() {
        let (_temp, installation) = fixture();
        let finder = installation
            .site_packages
            .join("__editable___hermes_agent_0_17_0_finder.py");
        let original = fs::read_to_string(&finder).unwrap();
        fs::write(
            &finder,
            original.clone() + "\nraise RuntimeError('extra startup code')\n",
        )
        .unwrap();
        assert!(build(&installation).is_err());
        fs::write(&finder, original).unwrap();
        fs::write(
            installation.site_packages.join("unknown.pth"),
            b"import os; os.system('anything')\n",
        )
        .unwrap();
        assert!(build(&installation).is_err());
    }
}
