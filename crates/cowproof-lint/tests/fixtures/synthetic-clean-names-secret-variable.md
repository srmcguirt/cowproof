<!-- lane {"id": "lane-provider-contract", "runner": "codex", "class": "light", "owns": ["docs/contracts/provider-v1.md", "docs/handoffs/handoff-lane-provider-contract.md"], "timeoutMin": 120} -->

# Lane: write the provider contract

Synthetic fixture for packet lint. Documentation only. The provider's key is read at runtime from the `EXAMPLE_PROVIDER_API_KEY` environment variable and a bearer header; never write a key, token or secret value into any file.

## Checks

```
git diff --check
```

## Handoff

`docs/handoffs/handoff-lane-provider-contract.md`: decisions, open questions with a recommended answer.
