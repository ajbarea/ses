# SES Rule Engines

The Security Evaluation System (SES) features two different rule engine implementations that serve the same purpose: evaluating system security metrics and generating findings, scores, and recommendations.

## Overview

The system includes:

1. **Legacy Python Rule Engine**

   - Implemented in `src/rules.py`
   - Always available as a fallback
   - Simpler, procedural approach using Python functions

2. **CLIPS Expert System**
   - Implemented in `src/clips_evaluator.py` and `src/clips_rules/*.clp`
   - Available only when PyCLIPS is installed
   - More sophisticated with rule chaining and pattern matching

## Selection Strategy

The system decides which rule engine to use based on availability of the CLIPS engine (requires PyCLIPS package)

This logic is implemented in the `evaluate()` function in `src/rules.py`:

```python
def evaluate(metrics: dict, use_clips: Optional[bool] = None) -> dict:
    # Determine evaluation engine based on preference and availability
    should_use_clips = CLIPS_AVAILABLE
    if use_clips is not None:
        should_use_clips = use_clips

    # Run appropriate evaluation
    if should_use_clips and CLIPS_AVAILABLE:
        logger.info("Using CLIPS evaluation engine.")
        result = _evaluate_clips(metrics)
    else:
        if should_use_clips and not CLIPS_AVAILABLE:
            logger.warning(
                "CLIPS evaluation requested but CLIPS is not available. Falling back to legacy."
            )
        logger.info("Using legacy Python evaluation engine.")
        result = _evaluate_legacy(metrics)
```

## Expected Consistency

While both engines evaluate the same security metrics, there are some key differences:

### Consistent Behaviors

These behaviors should be identical across both engines:

- Critical security issues (e.g., missing patches, disabled firewall, no antivirus) should be detected by both engines
- The same security grade categories are used by both engines
- The presence of critical findings should result in a "Critical Risk" grade in both engines
- Score calculation follows similar principles, with penalties for vulnerabilities

### Allowed Differences

These aspects may differ between engines:

- CLIPS may detect more nuanced security issues due to rule chaining capability
- Score values may differ by small amounts (±5 points) due to different scoring algorithms
- The exact wording of findings and recommendations may be different
- CLIPS provides rule activation tracing and explanations that aren't available in the legacy engine

## Testing Strategy

To ensure consistency between the two engines, automated tests compare:

1. Detection of critical security issues
2. Score values within acceptable margins
3. Grade determinations
4. Overall finding counts and severity distributions
