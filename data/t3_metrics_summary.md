# T3 Metrics Summary

## Final accepted dataset summary
- Accepted dataset file: `adversarial_dataset.csv`
- Total accepted adversarial queries: **146**
- Total rejected candidates: **242**
- End-to-end acceptance rate: **37.63%**

## Accepted context breakdown
- login: 77
- search: 69

## Accepted attack-category breakdown
- blind_time: 22
- union_based: 20
- stacked_queries: 20
- comment_obfuscation: 18
- encoding_obfuscation: 18
- tautology: 17
- blind_boolean: 17
- nested_injection: 14

## Accepted sandbox exploit-type breakdown
- comment_obfuscation: 49
- stacked_queries: 27
- blind_time: 24
- tautology: 20
- blind_boolean: 15
- union_based: 6
- nested_injection: 5

## Judge quality-score distribution
- 5: 146

## Rejected failure-stage breakdown
- judge: 190
- sandbox: 52

## Rejected context breakdown
- comment_insert: 74
- order_filter: 72
- user_lookup: 68
- search: 17
- login: 11

## Notes
- `label` should remain `1` for all final malicious samples.
- The final accepted dataset should only contain the project-supported contexts for retraining.
- Use this file together with `adversarial_dataset.csv` when handing metrics to the retraining / analysis owner.