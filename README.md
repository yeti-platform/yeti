# Yeti Platform

Yeti aims to bridge the gap between CTI and DFIR practitioners by providing a
Forensics Intelligence platform and pipeline for DFIR teams. It was born out of frustration
of having to answer the question "where have I seen this artifact before?" or
"how do I search for IOCs related to this threat (or all threats?) in my timeline?"

Documentation links:

* Main website: https://yeti-platform.io/
* [Documentation](https://yeti-platform.io/docs)
* [Guides](https://yeti-platform.io/guides)

## What is Yeti?

In a nutshell, Yeti allows you to:

- Bulk search observables and get a pretty good guess on the nature of the
  threat, and how to find it on a system.
- Inversely, focus on a threat and quickly list all TTPs, malware, and related
  DFIR artifacts.
- Let CTI analysts focus on adding intelligence rather than worrying about
  machine-readable export formats.
- Incorporate your own data sources, analytics, and logic very easily.

This is done by:

- Storing technical and tactical CTI (observables, TTPs, campagins, etc.) from
  internal or external systems.
- Being a backend for DFIR-related queries: Yara signatures, Sigma rules, DFIQ.
- Providing a web API to automate queries (think incident management platform)
  and enrichment (think malware sandbox).
- Export the data in user-defined formats so that they can be ingested by
  third-party applications (SIEM, DFIR platforms).
