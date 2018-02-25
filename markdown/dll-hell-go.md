# DLL Hell in Go

---

## Example

odb -> bosh-utils -> socks5-proxy

\\-> credhub-cli -> socks5-proxy

At least two CF tools use a shared library. Cool?

---

## An innocuous PR
https://github.com/cloudfoundry/socks5-proxy/commit/add0b5c1f03d03067bfac649f70fafb7c008e794

* New parameter to NewHostKeyGetter()

    * CredHub-CLI took the update in their calling code
    * BOSH-Utils did not

* ODB is now broken

---

## Why?

_dep_ package manager

* App declares direct dependencies and desired versions
* _dep_ considers transitive dependencies
* calculates a set of consistent maximal versions
* stores in lock file
* vendors appropriate versions to a single vendor dir
* socks5-proxy does not have versions

---

## Semantic versions

vN.M.P[-pre-release][+build-id]

* A fix which doesn't add or change functionality => P++
* A new feature which preserves existing API and functionality => M++
* A change to existing API or funcionality => N++

---

## SemVer'ed socks5-proxy

socks5-proxy is an young project, so could use v0.M.P numbering

* Pre-commit version 0.2.0, for example
* Then API break => version 0.3.0.

* Then bosh-utils could have dep on ^0.2.0
* credhub-cli could have dep on ^0.3.0

And...

dep would flag there is a version inconsistency :(

---

## How it used to be: _godep_ 

* Direct dependencies are vendored locally
* bosh-utils would have a vendor copy of 0.2.0
* credhub-cli would have a vendor copy of 0.3.0
* _go_ looks in nearest vendor directory first
* Both could be vendored successfully in ODB.

But...

_godep_ is deprecated in favour of _dep_,
and Pivotal has generally moved to _dep_.

---

## gopkg.in

* http://gopkg.in/yaml.v2
* http://gopkg.in/[your-github]/[your-app].v1

Features
* Works on major versions
* Code imports URL as above
* Version omitted when used in code.
* Actually points to your code on github

---

## socks5-proxy and gopkg.in?

* Could have bumped major version when making API change
* bosh-utils would import http://gopkg.in/cloudfoundry/socks5-proxy.v0
* credhub-cli would import http://gopkg.in/cloudfoundry/socks5-proxy.v1

_dep_ would vendor each separately

---

## The future

_dep_ is going to be replaced by _vgo_

* A bit like _dep_ (dependency tree stored locally)
* A bit like _gopkg.in_ (major version are distinct code bases)
* New stuff (package declares lowest acceptable version)

---

## Recommendations

As a library author
* Always use SemVer
* If you change any exported surface, bump the major number
* Use gopkg.in to separate versions of your dependencies
* Document gopkg.in as your import URL

---

## Recommendations

As a library user
* Use a package manager (dep is current stable recommendation)
* Shout if libraries break versioning for you
* Experiment with _vgo_
