# Expert System Implementation

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

- **Patch Information**: System update status and hotfix data
- **Port Information**: Network port listings
- **Service Details**: Windows service names and states
- **Firewall Configuration**: Profile states for domain, private, and public networks
- **Antivirus Information**: Product details and status codes
- **Password Policy**: Security policy settings
- **Findings**: Security issues discovered by rules
- **Scoring**: Score modifications

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

- **Antivirus Status Processing**: Multiple antivirus products analyzed for overall protection
- **String Formatting**: Proper escaping for CLIPS string handling
- **Default Values**: Missing data receives defaults

## Rule Processing and Inference

The expert system loads rules from `.clp` files in the `clips_rules` directory and processes them through the CLIPS inference engine.

### Rule Execution Flow

1. **Environment Setup**: CLIPS environment initialized with templates
2. **Rule Loading**: `.clp` files loaded from rules directory
3. **Fact Assertion**: Security metrics converted and asserted as facts
4. **Inference**: CLIPS runs inference to fire matching rules
5. **Result Collection**: Facts extracted and converted back to Python objects

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

The scoring logic is determined by the rules that are fired and the facts that are asserted.

### Grade Assignment

The grading system assigns a grade based on the final score and findings.

## Integration with Legacy System

The expert system integrates with the existing security evaluation framework:

### Evaluation Flow

```python
def evaluate(metrics, use_clips=None):
    """Main evaluation entry point with engine selection."""
    if should_use_clips_engine(use_clips):
        try:
            from .clips_evaluator import SecurityExpertSystem
            expert_system = SecurityExpertSystem(rules_dir="clips_rules")
            return expert_system.evaluate(metrics)
        except Exception:
            logger.warning("CLIPS evaluation failed, falling back to basic rules")

    return _evaluate_legacy(metrics)
```

### Compatibility Features

- **Consistent Output Format**: Same result structure as basic rule engine
- **Graceful Degradation**: Falls back to basic rules if CLIPS fails
- **Error Handling**: Robust exception handling with logging
- **Availability Detection**: Automatic CLIPS availability checking

## Advanced Features

### Pattern Matching

CLIPS enables pattern matching:

- **Variable Binding**: Extract and manipulate data within rules
- **Conditional Elements**: Logical combinations
- **Constraint Satisfaction**: Mathematical and logical constraints

### Rule Chaining

Rules can build upon each other's conclusions:

- **Forward Chaining**: Facts trigger rules that assert new facts
- **Inference Networks**: Reasoning chains
- **Dynamic Rule Selection**: Context determines which rules apply
- **Conflict Resolution**: Priority systems for competing rules

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

## Comparison with Legacy System

| Feature              | Legacy System         | Expert System            |
| -------------------- | --------------------- | ------------------------ |
| **Rule Language**    | Python functions      | CLIPS rules              |
| **Pattern Matching** | Manual coding         | Built-in engine          |
| **Rule Chaining**    | Limited               | Full support             |
| **Explanations**     | Basic                 | Detailed trace           |
| **Extensibility**    | Code changes required | Rule file additions      |
| **Dependencies**     | Python only           | Requires PyCLIPS         |
| **Complexity**       | Simple logic          | Sophisticated reasoning  |
| **Scoring**          | Binary critical logic | Nuanced grade assignment |
