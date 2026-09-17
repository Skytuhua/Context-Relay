# Windows Hermes runtime projection

The editable finder template is a normalized copy of setuptools' generated finder
observed in the selected Hermes editable installation. Only its MAPPING, NAMESPACES
and versioned PATH_PLACEHOLDER assignments are variable. The parser verifies its
remaining body but never executes it. The accompanying editable_finder.LICENSE is
the setuptools license from https://github.com/pypa/setuptools/blob/main/LICENSE.

This is a local-installation recognition template, not publisher authentication.
Runtime source-first policy v1 omits bytecode caches and never processes .pth code.
The generated bootstrap replaces recognized editable and pywin32 startup behavior
with stage-relative import and DLL paths. Unknown startup forms are rejected.

Capture is not launch authorization or a filesystem/network sandbox. Production
management commands require the separate sealed-runtime and containment contracts.
