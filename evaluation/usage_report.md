# Usage and cost report

## Final full-dataset run

The final prediction run processed all 518 rows in `dataset/deletion_requests.csv` and wrote the root-level `output.csv`.

| Measure | Overall | Per request |
|---|---:|---:|
| Model provider | None | None |
| Model name | None (deterministic local Python) | None |
| Model calls | 0 | 0 |
| Input tokens | 0 | 0 |
| Output tokens | 0 | 0 |
| Total tokens | 0 | 0 |
| Estimated cost | $0.00 | $0.00 |

No hosted or local language model is called by the submitted prediction program, so there are no model token counts or provider charges. This report describes the program run that generated `output.csv`; it does not estimate the separate development conversation’s usage because no authoritative billing or token-usage record was available to the program.

The run emitted 518 rows: 181 `COMPLETE`, 316 `INCOMPLETE`, and 21 `NOT_APPLICABLE`. It inspected 4,718 evidence observations extracted from 94 manifested evidence files. The final implementation used zero hosted-model calls and estimated $0.00 model cost.
