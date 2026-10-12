# Public disclosure tracker — reproof pipeline campaigns

Reporter of record: Sergey Gordeychik ([@scadastrangelove](https://github.com/scadastrangelove)).

Policy (same as the [rust-in-peace tracker](https://github.com/scadastrangelove/rust-in-peace/blob/main/DISCLOSURES-PUBLIC.md)):

- **Private channel first** — GitHub private vulnerability reporting or a
  vendor security email. Where no private channel exists (archived
  upstream), the finding goes to a public issue, plus a PR when a fix is
  ready.
- **No exploit details before a fix ships.** Reports still under vendor
  triage are listed by channel / advisory ID and status only — no
  vulnerability class, mechanism, or PoC.
- **Cadence:** follow-up at ~14 days if silent; public disclosure at ~90
  days if unresponsive. Disputed closures get a standing re-check rather
  than an immediate contest.

This file tracks the **October 2026 wave** run by the reproof pipeline
(including the rust-in-peace ai-agent profile): AI coding agents and
gateways, the TR-069/CWMP CPE-agent stack and its embedded SOAP runtime,
TR-069 ACS servers, and broadband-CPE firmware. Rust-crate and Linux-kernel
campaign counts live in the rust-in-peace tracker, not here.

## AI coding-agent campaign — October 2026 wave

AI coding agents / gateways reviewed by the reproof + rust-in-peace
ai-agent profile pipeline. Each was reported through a private channel
(GitHub private vulnerability reporting or a vendor security email), is
unfixed and unpublished, and is listed here by channel/advisory-ID and
status only — no vulnerability class, mechanism, or PoC.

| Target | Reported | Channel / Advisory ID | Status |
|---|---|---|---|
| ZCode CLI (zai-org/ZCode) | 2026-10-08 | GHSA-85m2-c246-958r (private advisory) | Filed — under vendor triage |
| Pi (earendil-works/pi) | 2026-10-08 | direct email — security@earendil.com | Sent — awaiting acknowledgement; technical detail withheld per policy |
| goose (Block / AAIF, aaif-goose/goose) | 2026-10-05 | GitHub private advisory + open-source-governance@block.xyz | Sent — awaiting acknowledgement; technical detail withheld per policy |
| OmniRoute (diegosouzapw/OmniRoute) | 2026-10-05 | private GitHub advisory + vendor email | Sent — awaiting acknowledgement; technical detail withheld per policy |
| kimi-code (MoonshotAI / Moonshot) | 2026-10-05 | direct email — security@moonshot.ai | Acknowledged 2026-10-05 (auto-reply; forwarded to a specialist team); technical detail withheld per policy |

## TR-069 / CWMP & embedded-SOAP campaign — October 2026 wave

TR-069/CWMP CPE agents and the embedded C SOAP/XML runtime (gSOAP) they
build on, same pipeline and same policy (channel/advisory-ID and status
only; no mechanism).

| Target | Reported | Channel / Advisory ID | Status |
|---|---|---|---|
| EasyCwmp (pivasoftware/easycwmp) | 2026-10-07 | direct email — maintainers + CERT | Sent — awaiting acknowledgement; technical detail withheld per policy |
| icwmp (iopsys/BBF, dev.iopsys.eu/bbf/icwmp) | 2026-10 | direct email — IOPSYS (suvendhu.hansa / vivek.dutta / info@iopsys.se) | Acknowledged 2026-10-09 — vendor reviewing and working on fixes (vendor ETA ~2 weeks), embargo in effect; technical detail withheld per policy |
| CcspTr069Pa (RDK-B, code.rdkcentral.com) | 2026-10-10 | direct email — security@rdkcentral.com + support | Sent — 90-day embargo proposed; awaiting acknowledgement; technical detail withheld per policy |
| gSOAP (Genivia) | 2026-10-09 | direct email — engelen@genivia.com + contact@genivia.com | Sent — 90-day embargo proposed; awaiting acknowledgement; technical detail withheld per policy |

## TR-069 ACS servers — October 2026 wave

Open-source TR-069 ACS servers (the ACS side, opposite the CPE-client
agents above), same pipeline and policy — channel and status only; no
mechanism — except FreeACS, whose upstream is archived read-only, so there
is no private channel or coordinated-fix path and its technical detail is
therefore already public (see its row).

| Target | Reported | Channel | Status |
|---|---|---|---|
| GenieACS (genieacs/genieacs) | 2026-10-11 | direct email — support@genieacs.com + security + CERT/CC (GitHub private reporting disabled) | Sent — 45-day embargo suggested; awaiting acknowledgement; technical detail withheld per policy |
| FreeACS (freeacs/freeacs) | 2026-10-12 | upstream archived read-only since 2024-09-04 — its SECURITY.md "open an issue" channel is dead — so disclosed as public issues on the fork scadastrangelove/freeacs | Published — 8 findings + index (#1–#9; 1 Critical, 5 High, 2 Medium). Technical detail is public (archived upstream = no coordinated-fix path) |

## Broadband CPE device firmware — October 2026 wave

Broadband-CPE (ONT / home-gateway) device firmware reviewed from publicly
obtainable images by the reproof + rust-in-peace pipeline and reported to
the vendors' PSIRTs under the same policy — channel and status only; no
vulnerability class, mechanism, or PoC.

| Target | Reported | Channel | Status |
|---|---|---|---|
| ZTE ZXHN F670L (TR-069 / web stack) | 2026-10-12 | ZTE PSIRT | Sent — coordinated disclosure; awaiting acknowledgement; technical detail withheld per policy |
| Huawei EchoLife HG8145V5 / EG8145V5 (TR-069 CWMP) | 2026-10-12 | Huawei PSIRT | Sent — 90-day embargo proposed; awaiting acknowledgement; technical detail withheld per policy |

---

Last updated: 2026-10-12.
