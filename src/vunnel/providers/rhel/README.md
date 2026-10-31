# RHEL provider

## EAP 7.4 RPM records

The provider also processes Red Hat JBoss EAP 7.4 RPM affected-release
records for RHEL 7, 8, and 9. Acceptance requires agreement between the
product name, EAP platform CPE, `eap7-` package prefix, and RPM dist tag.

These records are emitted under the corresponding `rhel:7`, `rhel:8`,
or `rhel:9` namespace. The output does not retain the EAP product stream
as a separate qualifier.

Unresolved EAP package states are included to preserve affected-state
precedence over fixed releases. EAP `Not affected` states are excluded.

This coverage applies to RPM records. It does not establish the fix
status of standalone Maven artifacts.

### Disclosed product conflicts

Before importing EAP records, the provider checks both `affected_release` and
`package_state` for the same `eap7-` RPM name and RHEL major associated with
different EAP product CPEs. It defers the new EAP import for that package and
platform rather than collapsing those products into one RHEL threshold.
Different EUS/ELS product CPEs are also treated as conflicts, even when the
reported fixed versions agree. Ordinary RHEL records are unchanged.

This guard addresses conflicts disclosed in the current CVE document only.
It does not identify the installed package's EAP stream, prove that all
streams have been disclosed, or provide general stream isolation. Deferred
records remain a coverage gap; they do not mean that a package is unaffected.
For example, CVE-2021-44906 discloses an EAP 7.3 EUS `eap7-hal-console` fix
at `0:3.2.17-1.Final_redhat_00001.1.el7eap` and an EAP 7.4 fix at
`0:3.3.13-1.Final_redhat_00001.1.el7eap`. Importing only the latter would
incorrectly flag the former fixed build, so this pair is deferred.
