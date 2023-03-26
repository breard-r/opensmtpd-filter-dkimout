# Filter DKIMout

[![Build Status](https://github.com/breard-r/opensmtpd-filter-dkimout/actions/workflows/ci.yml/badge.svg)](https://github.com/breard-r/opensmtpd-filter-dkimout/actions/workflows/ci.yml)
![Minimum rustc version](https://img.shields.io/badge/rustc-1.64.0+-lightgray.svg)
![License MIT OR Apache 2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)

DKIM filter for [OpenSMTPD](https://www.opensmtpd.org/).


## Project status

This is a work in progress, it is not supposed to work yet.


## Frequently Asked Questions

### Does this filter signs outgoing emails using DKIM or check the DKIM signature of incoming emails?

It only signs outgoing emails.

### Why create another filter for that?

Currently, the options to sign outgoing emails with DKIM are the following:
- [DKIMproxy](https://dkimproxy.sourceforge.net/usage.html)
- [filter-dkimsign](https://imperialat.at/dev/filter-dkimsign/)
- [filter-rspamd](https://github.com/poolpOrg/filter-rspamd)

DKIMproxy is not an OpenSMTPD filter and is therefore more inconvenient to use. Moreover, its development stopped in 2013 and it is therefore dangerous to use.

The two other are fine, however I think they lack a few features, like automatic key rotation and publication of obsolete private keys.

### Why would anyone publish private keys, even obsolete ones? Are you crazy?

DKIM's goal is to fight spam, that's all, and for that it only need the keys to be safe when the recipients receives the email. But because it includes a cryptographic proof over the content it is being used for other usages, mostly as a legal proof long after the email has been sent and received. Publishing the obsolete/revoked private keys allows the sender to regain deniability.

Matthew Green wrote an excellent article on this subject: [Ok Google: please publish your DKIM secret keys](https://blog.cryptographyengineering.com/2020/11/16/ok-google-please-publish-your-dkim-secret-keys/).

### Where is the documentation?

A man page will be available by the time this filter is ready to use.
