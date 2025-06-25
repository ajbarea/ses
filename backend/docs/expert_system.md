# Expert System Documentation

This document provides an overview of the CLIPS-based expert system implemented in `clips_evaluator.py`. The system uses rule-based artificial intelligence to evaluate Windows security metrics and generate security assessments with explanations.

## Overview

The expert system serves as an alternative to a basic rule engine, providing pattern matching, rule chaining, and scoring capabilities. It leverages the CLIPS (C Language Integrated Production System) engine to process security facts and fire rules.

## System Architecture (`SecurityExpertSystem`)

The core of the expert system is the `SecurityExpertSystem` class, which acts as a bridge between Python and the CLIPS inference engine.

### Key Components

- **CLIPS Environment**: The underlying inference engine that processes facts and rules
- **Template Definitions**: Structured data schemas for security metrics and findings
- **Rule Files**: External `.clp` files containing domain-specific security rules
- **Fact Conversion**: Transforms Python dictionaries into CLIPS facts
- **Inference Engine**: Processes facts against rules to generate findings

## Template System

The expert system defines structured templates that serve as schemas for different types of data. These templates are defined in the `_load_templates()` method.

### Core Data Types

- **Patch Information**: System update status and hotfix data (`patch-status` template)
- **Port Information**: Network port listings (`open-port` template)
- **Service Details**: Windows service names and states (`service` template)
- **Firewall Configuration**: Profile states for domain, private, and public networks (`firewall` template)
- **Antivirus Information**: Product details and status codes (`antivirus-product` and `antivirus-info` templates)
- **Password Policy**: Security policy settings including minimum length, complexity, lockout threshold, history size, and maximum age (`password-policy` template)
- **Findings**: Security issues discovered by rules with rule name, level, description, details, and recommendations (`finding` template)
- **Scoring**: Score modifications with rule name, value, and type (penalty/bonus/neutral/final) (`score` template)

## Fact Conversion Process

The system converts Python security metrics into CLIPS facts through specialized assertion methods in `SecurityExpertSystem`.

### Conversion Strategy

```python
# Python metrics
metrics = {
    "patch": {"status": "out-of-date", "hotfixes": ["KB1", "KB2"]},
    "firewall": {"profiles": {"domain": "ON", "private": "OFF", "public": "ON"}}
}

# Converted to CLIPS facts via assert_* methods
```

### Special Handling

- **Antivirus Status Processing**: Multiple antivirus products analyzed for overall protection status using `_determine_antivirus_status()` method which evaluates product state values to determine if antivirus is enabled, disabled, or partially functional
- **String Formatting**: Proper escaping for CLIPS string handling in fact assertions, particularly for rule names and descriptions
- **Default Values**: Missing data receives appropriate defaults (e.g., "unknown" for antivirus status, "not-defined" for lockout threshold)
- **Score Impact Resolution**: Multiple strategies for determining score impacts including direct rule linking, activation matching, and fallback to level-based defaults

## Rule Processing and Inference

The expert system loads rules from `.clp` files in the `clips_rules` directory and processes them through the CLIPS inference engine.

### Rule Execution Flow

1. **Environment Setup**: CLIPS environment initialized with templates via `_load_templates()`
2. **Rule Loading**: `.clp` files loaded from rules directory via `_load_rules()`
3. **Fact Assertion**: Security metrics converted and asserted as facts via `convert_metrics_to_facts()`
4. **Inference**: CLIPS runs inference via `run_evaluation()` with optional rule tracing
5. **Result Collection**: Facts extracted via `get_findings()` and `get_score()`, then converted back to Python objects
6. **Rule Trace**: Rule activations captured through CLIPS watch functionality or reconstructed from findings

### Available Rule Files

Based on the clips_rules directory structure:

- **patch_rules.clp**: Evaluate system update status
- **port_rules.clp**: Assess network exposure risks
- **firewall_rules.clp**: Check firewall configuration
- **password_rules.clp**: Validate password policies
- **antivirus_rules.clp**: Evaluate malware protection

## Scoring and Grade Assignment

The expert system uses a scoring mechanism to provide security assessments:

### Scoring Logic

The scoring system uses a sophisticated approach that considers both rule-generated score impacts and finding levels:

1. **Score Facts**: Rules can assert score facts with specific values and types (penalty, bonus, neutral, final)
2. **Finding Impact**: Each finding level has a default score impact:
   - **Critical**: -30 points (penalty)
   - **Warning**: -10 points (penalty)
   - **Minor**: -3 points (penalty)
   - **Info**: 0 points (neutral)
3. **Final Score Calculation**: If a "final" score fact exists, it overrides all other calculations. Otherwise, impacts are applied to the base score (default 100)
4. **Score Clamping**: Final scores are bounded between 0 and 100

### Grade Assignment

The grading system assigns letter grades based on the final score and critical findings:

- **Excellent**: Score ≥ 90 with no critical findings
- **Good**: Score ≥ 80 with no critical findings
- **Fair**: Score ≥ 60 with no critical findings
- **Poor**: Score ≥ 40 OR any critical findings present
- **Critical Risk**: Score < 40 with critical findings

Critical findings automatically impact the grade through an effective score reduction mechanism.

## Integration with Legacy System

The expert system integrates with the existing security evaluation framework:

### Evaluation Flow

```python
def evaluate(metrics: dict, use_clips: Optional[bool] = None) -> dict:
    """Main evaluation entry point with engine selection."""
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

    # Add metadata to result
    result["timestamp"] = datetime.now(timezone.utc).isoformat()
    result["metrics"] = metrics

    return result

def _evaluate_clips(metrics: dict) -> dict:
    """Evaluate metrics with the CLIPS expert system rule engine."""
    try:
        from src.clips_evaluator import SecurityExpertSystem
        expert_system = SecurityExpertSystem()
        result = expert_system.evaluate(metrics)
        return result
    except Exception as e:
        logger.error(f"Error using CLIPS evaluator: {e}. Falling back to legacy evaluator.")
        return _evaluate_legacy(metrics)
```

### Compatibility Features

- **Consistent Output Format**: Same result structure as basic rule engine including fields like `score`, `grade`, `findings`, `positive_findings`, `negative_findings`, `neutral_findings`, `impact_summary`, `score_changes`, `rules_fired`, and `explanations`
- **Graceful Degradation**: Falls back to basic rules if CLIPS import fails or expert system evaluation raises an exception
- **Error Handling**: Robust exception handling with comprehensive logging at error and warning levels
- **Availability Detection**: Automatic CLIPS availability checking via import testing with `CLIPS_AVAILABLE` flag
- **Rule Tracing**: Advanced rule activation tracing with fallback to findings-based reconstruction when CLIPS watch functionality is unavailable

## Advanced Features

## Advanced CLIPS Features

### Pattern Matching

CLIPS enables sophisticated pattern matching capabilities:

- **Variable Binding**: Extract and manipulate data within rules using variables like `?port`, `?len`, `?count`
- **Conditional Elements**: Logical combinations using `and`, `or`, `not` operators
- **Constraint Satisfaction**: Mathematical and logical constraints like `?port&:(or (= ?port 21) (= ?port 23))`
- **Multi-slot Matching**: Pattern matching against lists and collections

### Rule Chaining

Rules can build upon each other's conclusions through forward chaining:

- **Forward Chaining**: Facts trigger rules that assert new facts, creating reasoning chains
- **Inference Networks**: Complex reasoning networks where conclusions become premises for other rules
- **Dynamic Rule Selection**: Context-sensitive rule activation based on current fact state
- **Conflict Resolution**: CLIPS built-in conflict resolution strategies for competing rules
- **Fact Dependencies**: Rules can depend on combinations of facts and intermediate conclusions

## Extensibility

The expert system is designed for extension through additional rule files:

### Adding New Rule Types

1. **Define Templates**: Create CLIPS templates for new data types
2. **Add Fact Conversion**: Implement Python-to-CLIPS conversion methods
3. **Write Rules**: Create `.clp` files with domain-specific logic

### Rule Development Guidelines

- **Modular Design**: Keep rules focused on specific security domains
- **Clear Naming**: Use descriptive rule and fact names
- **Documentation**: Include comments explaining rule logic
- **Testing**: Validate rules against known security scenarios

## Rule Tracing and Debugging

The expert system provides comprehensive rule tracing capabilities to understand evaluation decisions:

### Tracing Methods

1. **CLIPS Watch**: Primary method using CLIPS built-in watch functionality

   - Captures rule firing events in real-time
   - Provides detailed activation information
   - Automatically falls back if watch is unavailable

2. **Findings-based Reconstruction**: Fallback tracing method

   - Reconstructs rule activations from generated findings
   - Used when CLIPS watch functionality raises exceptions
   - Ensures tracing availability across different CLIPS versions

3. **Activation Parsing**: Processes CLIPS watch output
   - Extracts rule names and activation details
   - Formats trace information for user consumption

### Error Handling Strategies

The expert system implements robust error handling at multiple levels:

1. **Import-level**: Graceful degradation when CLIPS is unavailable
2. **Template-level**: Error handling during template definition
3. **Rule-level**: Continued operation despite individual rule failures
4. **Evaluation-level**: Fallback to legacy engine on expert system failures
5. **Tracing-level**: Alternative tracing methods when watch fails

## Comparison with Legacy System

| Feature              | Legacy System         | Expert System           |
| -------------------- | --------------------- | ----------------------- |
| **Rule Language**    | Python functions      | CLIPS rules             |
| **Pattern Matching** | Manual coding         | Built-in engine         |
| **Rule Chaining**    | Limited               | Full support            |
| **Explanations**     | Basic                 | Detailed trace          |
| **Extensibility**    | Code changes required | Rule file additions     |
| **Dependencies**     | Python only           | Requires PyCLIPS        |
| **Complexity**       | Simple logic          | Sophisticated reasoning |
| **Scoring**          | Level-based penalties | Flexible score facts    |
| **Rule Tracing**     | Not available         | CLIPS watch + fallbacks |
| **Fact Management**  | Manual                | CLIPS environment       |
