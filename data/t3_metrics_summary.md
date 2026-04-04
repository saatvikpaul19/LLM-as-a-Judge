# T3 Metrics Summary

## Final dataset summary
- Input accepted file: `accepted_candidates.csv`
- Input rejected file: `rejected_candidates.csv`
- Total accepted queries: **110**
- Total rejected queries: **36**
- Acceptance rate: **75.34%**

## Accepted context breakdown
- login: 60
- search: 50

## Accepted attack-category breakdown
- tautology: 17
- blind_time: 17
- stacked_queries: 17
- union_based: 16
- blind_boolean: 15
- comment_obfuscation: 12
- nested_injection: 11
- encoding_obfuscation: 5

## Accepted judge score distribution
- 4: 110

## Most common acceptance reasons
- The candidate payload is a tautology attack in the login context, demonstrates non-trivial mutation from the seed, and is realistic for the login scenario.: 3
- The candidate payload is a tautology attack that is realistic for the search context, shows non-trivial mutation from the seed, and maintains malicious intent.: 2
- The candidate payload is a valid union-based SQL injection attempt that matches the search context and demonstrates non-trivial mutation from the seed payload.: 2
- The candidate payload is a union-based SQL injection attack that matches the login context and demonstrates non-trivial mutation from the seed payload.: 2
- The candidate payload is a union-based SQL injection attack that is plausible for the 'search' context, shows non-trivial mutation from the seed, and maintains malicious intent.: 2
- The candidate payload is a meaningful malicious SQL injection attempt that matches the login context and is a non-trivial mutation from the seed payload.: 2
- The candidate payload is a valid blind boolean attack in the login context, showing non-trivial mutation from the seed and maintaining malicious intent.: 2
- The candidate payload is a valid SQL injection attempt that maintains malicious intent, is realistic for the login context, and represents a non-trivial mutation from the seed payload.: 2

## Rejected failure-stage breakdown
- sandbox: 36

## Rejected context breakdown
- search: 19
- login: 17

## Most common rejection reasons
- Sandbox returned benign. Reason: AST validation failed or query did not parse cleanly: 36

## Interpretation
- Accepted rows represent candidate SQLi samples that passed deterministic checks and the LLM judge rubric.
- Rejected rows failed either deterministic validation (sandbox/AST) or the judge rubric for realism, maliciousness preservation, or non-triviality.
- This file can be used directly in the report/presentation for the statistics and analysis section.