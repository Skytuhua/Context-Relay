# Windows clean qualification preparation — September 14, 2026

**SUPERSEDED — do not execute the media/guest steps below.** The user canceled VM and ISO work and requested testing only on this physical PC. This file preserves historical preparation evidence. VirtualBox and the two empty definitions are unused; no OS media or guest installation exists. Current execution uses dedicated Windows test-user profiles under the amended plan.

Status: tooling and two empty VM definitions prepared. No guest OS, Context Relay installation, clean acceptance, or physical observation has passed.

## Verified host and tooling

Host: Windows 11 Home x64, build 10.0.26200.9445; Intel i7-14700F; 28 logical processors; 65,292 MiB RAM. VirtualBox reports hardware virtualization and nested paging available. Data lives on E:, with approximately 1.29 TB free at preflight.

Oracle VirtualBox 7.2.16 r174877 base application installed using the signed MSI, `ADDLOCAL=VBoxApplication`, silent/no restart, with automatic launch, shortcuts and file associations disabled. Installation exit 0. No network filter/host-only, USB, Python or Extension Pack was selected; `VBoxManage list extpacks` reports zero. Basic NAT is used. Existing inaccessible VM registration `ccbae5e6-4f55-46f4-ace6-5fa12a681774` was preserved.

| Artifact | SHA-256 | Evidence |
| --- | --- | --- |
| VirtualBox-7.2.16-174877-Win.exe (177,741,408 bytes) | `9383a42bffa5c0ac4bc5f1c7d820478d84380d3a17b65aa9b43e6778cbdb615a` | Matches [Oracle published checksum](https://download.virtualbox.org/virtualbox/7.2.16/SHA256SUMS); Authenticode Valid, Oracle America, Inc. |
| Extracted amd64 MSI | `c22d9250cb60e9ea6d0fff079bbd04de38900d2c59d38de3ea32cc091b4eedf3` | Authenticode Valid, Oracle America, Inc.; extraction exit 0. |

Installer, extracted files and `install.log`: `E:\Context Relay Releases\qualification-tools\virtualbox-7.2.16`.
Executable: `C:\Program Files\Oracle\VirtualBox\VBoxManage.exe`.
Installation follows [Oracle Windows installation documentation](https://docs.oracle.com/en/virtualization/virtualbox/7.2/user/installation.html).

## Guest definitions

| Guest | VM UUID | Disk UUID |
| --- | --- | --- |
| ContextRelay-PR16-Win-A | `4ca80a47-b554-4377-bbac-641c8a90945c` | `3b6efde4-0dfc-463f-8a1b-12af05c143ae` |
| ContextRelay-PR16-Win-B | `d71d2f83-bc0b-47c1-b711-10ef2ceade0f` | `9434e26c-32a4-4589-8638-66d39e82bcc5` |

Each guest: independent empty 120 GiB dynamic VDI; 8 GiB RAM; four CPUs; EFI; TPM 2.0; VBoxSVGA/128 MiB; NAT with host-loopback reachability disabled; no shared folders, clipboard transfer or drag/drop; audio output enabled for screen-reader checks, input disabled. Separate Windows installations will create distinct OS identities. Both remain powered off. Machine-readable preinstall settings are preserved in `E:\Context Relay Releases\qualification-vms`.

## Required media and native user steps

1. Obtain an appropriately licensed Windows 11 x64 ISO. If eligible for Microsoft's professional/organization evaluation, complete the [official Windows 11 Enterprise registration](https://info.microsoft.com/ww-landing-windows-11-enterprise.html). Microsoft describes a 90-day evaluation and requires registration; no product key is needed. Eligibility must not be invented. An existing appropriately licensed image is also usable. See [Microsoft's prerequisites and verification instructions](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-11-enterprise).
2. Save the ISO under `E:\Context Relay Releases\qualification-tools\windows-media` and provide only its local path. Do not share account credentials or license keys. Before attachment, record its exact edition/version/language, size, SHA-256 and matching official checksum. Media lacking authoritative integrity/licensing evidence remains unqualified.
3. Attach the verified ISO to each guest's SATA optical drive. Start a visible guest only for the user's installation interaction. Install only to that guest's empty virtual disk. Complete Microsoft sign-in and license/activation directly in the guest; do not capture credentials in evidence.
4. Install required Windows updates and verified Guest Additions from the base package. Keep clipboard and shared-folder features disabled. Install regular Chrome in each guest for the actual browser login tests. Record guest build, VM settings, locale, activation/evaluation expiration and browser version.
5. Before any Context Relay account/device enrollment, shut down each guest cleanly and create a separately named `clean-pre-enrollment` snapshot. Record snapshot UUIDs and absence of Context Relay vault/device state. Do not clone an enrolled machine to create the second identity.
6. Qualification runs use the exact final candidate and hosted deployment manifest. Preserve a read-only transfer ISO or another explicitly scoped artifact path; never expose the host user's vault, home, credentials or working checkout to guests.
7. Execute the complete Windows/shared acceptance twice, resetting both guests to the recorded clean snapshot before each pass. Record test account/device identifiers without tokens, every scenario's result, artifact hashes and raw latency data. Snapshot preparation is not acceptance evidence.

Physical-PC requirements remain separate. Prepare a dedicated OS test user and exact installer/procedure before requesting physical sign-in, accessibility or native GUI actions. The user's normal installed service and vault remain intact.
