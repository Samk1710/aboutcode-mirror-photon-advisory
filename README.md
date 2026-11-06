# Photon OS Advisory Mirror

This repository hosts a **mirror** of the [Photon OS Security Advisories (CVE metadata)](https://packages.broadcom.com/photon/photon_cve_metadata/cve/).

## Sync Frequency

The mirror syncs every day, see the sync workflow [.github/workflows/sync.yml](.github/workflows/sync.yml).

---

## Usage

To use the mirror, clone this repository:

```bash
git clone https://github.com/aboutcode-org/aboutcode-mirror-photon-advisory.git
```

Once cloned, the advisories will be available in the `advisories/` directory organized by year.

---

## License

* **Code** is licensed under the [Apache License 2.0](http://www.apache.org/licenses/LICENSE-2.0).
* **Data** is licensed under [CC-BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/).
