# Dataset acquisition attempt — 2026-10-24

## Objective

Obtain real labelled capture traffic (CTU-13) to test transfer beyond synthetic
loopback scenarios, per the M18 plan.

## Result: blocked by the network path, not by permission or availability

| Probe | Result |
|---|---|
| `DNS mcfp.felk.cvut.cz` | `198.18.0.52` — proxy fake-IP range |
| `http://mcfp.felk.cvut.cz/publicDatasets/CTU-13-Dataset/` | **502** (proxy could not fetch origin) |
| `https://mcfp.felk.cvut.cz/...` | **TLS verify failed** (`CERTIFICATE_VERIFY_FAILED`) |
| `https://www.stratosphereips.org/datasets-ctu13` | 200 — page loads, but every dataset link points at `mcfp.felk.cvut.cz` |
| `https://zenodo.org/` | 403 |
| `https://www.kaggle.com/` | 404 |

The dataset is publicly documented and the index page is reachable; the host
serving the files is not reachable through this machine's proxy. No data was
downloaded and **no synthetic substitute was created**.

## What would unblock it

1. A network path where `mcfp.felk.cvut.cz` resolves to a real address (proxy
   rule change, or a different machine/network).
2. A mirror of CTU-13 that is reachable — Kaggle or a university mirror — with
   the licence and hash recorded before use.
3. An offline copy on removable media.

## Procedure once the host is reachable

```powershell
# 1. download and record provenance before touching the data
#    (size and hash must be recorded in the experiment report)
Invoke-WebRequest "https://mcfp.felk.cvut.cz/publicDatasets/CTU-13-Dataset/CTU-13-Dataset.tar.bz2" `
    -OutFile "D:\datasets\CTU-13-Dataset.tar.bz2"
Get-FileHash "D:\datasets\CTU-13-Dataset.tar.bz2" -Algorithm SHA256

# 2. extract one scenario, keep PCAP + labels together

# 3. export canonical flow features
python scripts/export_flows.py --pcap <capture>.pcap --output D:\datasets\ctu13-flows.csv

# 4. label from the dataset's own flow labels, then validate
python scripts/export_flows.py --validate D:\datasets\ctu13-flows.csv
```

## Constraints to respect

- **Licence:** CTU-13 is distributed for research use; record the licence and
  citation in any report, and do not redistribute the capture.
- **Label semantics:** CTU-13 labels flows as botnet / normal / background.
  "Background" is not benign — it is traffic the labelling tool could not
  attribute. Decide explicitly how to treat it (exclude, or report separately).
- **Feature mapping:** CTU flow records and the 20 canonical features are not
  the same schema. Either export from PCAP with this repository's extractor, or
  document a mapping. Do not silently compare mismatched feature sets.
- **Split by capture**, never by flow.

## Alternative that does not depend on the proxy

A small isolated lab (two VMs on a host-only network, or two machines on an
isolated switch) produces real non-loopback packets with labels from the tool
timestamps. It is more work than a download and weaker than CTU-13 (no genuine
malware traffic), but it is reachable today:

- benign: browsing, file transfer, DNS lookups, package updates;
- attack: `nmap`, `hping3 --flood`, `slowloris` against a target you own;
- capture on the target with `tcpdump`; label by tool start/stop time.

Only ever against systems you own, on a network that cannot reach the internet
or anyone else's systems.

## Consequence for the model work

The 37 % false-positive rate reported in `live-adaptation-2026-10-24.md` cannot
be addressed without a realistic benign distribution. Until one of the routes
above is available, the honest position is that the candidate's false-positive
behaviour is unmeasured outside synthetic loopback traffic.
