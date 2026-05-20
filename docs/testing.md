# Testing

The test suite validates every shipped rule with 100% coverage:

```bash
# Full pytest suite (includes multi-file integration + CLI UX tests):
python task.py test

# Filtered run:
python task.py test -- -k output_per_file

# Or directly with pytest (virtualenv must have dev deps):
pytest tests/ -v

# Or run the integration suite standalone:
python tests/test_integration.py
```

## What the tests verify

- **`bad_example.yml`** -- triggers every single shipped rule
- **`clean_example.yml`** -- produces zero findings (false-positive check)
- **`multi_example_bad/`** -- 6-file role fixture that exercises cross-file
  taint, role-task AST parsing, and deterministic finding counts across a
  realistic layout
- **`multi_example_clean/`** -- 6-file hardened role fixture, zero findings
  expected (multi-file false-positive guard)
- **No duplicate pattern IDs** across all YAML files
- **All regexes compile** without errors
- **Category field matches filename** for every pattern
- **CLI behaviours** -- format inference from `--output` extension, per-file
  report mode, `--output` overwrite protection, smart default output directory
