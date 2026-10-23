# Feature-parity audit — CICIDS2017 benign vs live benign

Reference: 40000 benign CICIDS2017 rows. Live: 33 flows from 284 packets on `\Device\NPF_{0AFD3ED9-02C8-0811-124D-1682118B6574}`, 30 s.

| Feature | CICIDS mean | Live mean | Std diff | KS | Verdict |
|---|---|---|---|---|---|
| ack_count | 0.4616 | 6.333 | 1.54 | 0.85 | large |
| bwd_packet_length | 130 | 43.69 | 0.40 | 0.62 | large |
| fwd_iat_mean | 2.827e+06 | 7.014e+06 | 0.60 | 0.59 | large |
| flow_rate | 5.23e+05 | 7.583e+04 | 0.05 | 0.51 | large |
| fwd_packet_length | 411.9 | 138 | 0.49 | 0.49 | moderate |
| avg_packet_size | 253.1 | 96.53 | 0.56 | 0.49 | moderate |
| flow_bytes | 7303 | 1457 | 0.13 | 0.48 | moderate |
| flow_duration | 1.797e+07 | 1.176e+07 | 0.26 | 0.45 | moderate |
| idle_time | 9.992e+06 | 9.92e+06 | 0.01 | 0.45 | moderate |
| packet_rate | 8701 | 625.8 | 0.15 | 0.43 | moderate |
| bwd_iat_mean | 2.441e+06 | 5.88e+06 | 0.51 | 0.36 | moderate |
| total_fwd_packets | 5.841 | 4.545 | 0.07 | 0.33 | moderate |
| active_time | 2.132e+05 | 2.169e+05 | 0.00 | 0.30 | moderate |
| fin_count | 0.0036 | 0.4242 | 0.75 | 0.24 | moderate |
| header_length | 319.6 | 151.8 | 0.17 | 0.24 | moderate |
| total_bwd_packets | 7.349 | 4.061 | 0.14 | 0.23 | moderate |
| down_up_ratio | 1.732 | 0.6667 | 0.75 | 0.23 | moderate |
| syn_count | 0.08438 | 0.3636 | 0.47 | 0.18 | small |
| flow_packets | 13.19 | 8.606 | 0.11 | 0.11 | small |
| rst_count | 0.000125 | 0.1212 | 0.41 | 0.09 | small |

## Reading this

- Large-shift features: bwd_packet_length, flow_rate, ack_count, fwd_iat_mean
- Small-shift features: flow_packets, syn_count, rst_count
- A large KS statistic means the feature is distributed differently even for benign traffic; a model leaning on it will misjudge live flows.

## Limits

- Name-level parity only: the CICIDS columns come from its own flow pipeline, so identical names do not prove identical definitions.
- One host, 30 seconds, mostly DNS and blocked HTTPS attempts — not a network population.
- CICIDS benign is testbed traffic, not a random sample of the internet.
- This does not by itself prove H1; it ranks which features are most likely to be mismatched and therefore worth checking definition-by- definition.
