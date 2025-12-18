---
name: Vulnerability Match Issue
about: Report an issue with vulnerability matching
title: ''
labels: [ bug, false-positive ]
assignees: ''
---

**Vulnerability ID**:
<!-- CVE, GHSA, etc. -->

**Package URL or steps to reproduce**:
<!--
Running `grype <PackageURL>` should show the matching issue. If it does, please provide
the full Package URL, e.g.: pkg:apk/alpine/alpine-baselayout@3.7.0-r0?arch=x86_64&distro=alpine-3.22.2
make sure to include all parameters, including the distro, where applicable.

If the issue can't be reproduced with a Package URL, please link to a public artifact
grype can scan or provide other instructions to reproduce.
Some suggestions:
1. Link to Dockerhub, GitHub, GitLab, maven central, quay.io, etc to a public
   artifact we can try scanning
2. A Dockerfile that we can build and scan
3. A simple script that creates a directory exhibiting the issue, for example a
   list of `npm install` commands

Please also include the grype command and any configuration used.
-->

**Anything else we need to know?**:
<!-- Add additional information here:
Some suggestions:
1. Links to the GHSA or CVE page(s)
2. Explanation why a vulnerability is or isn't applicable
-->

**Environment**:
- Output of `grype version`:
- OS (e.g: `cat /etc/os-release` or similar):
