# Taint analysis

The executable runs the interprocedural taint fixpoint for one JPAMB entry
method and prints JSON hints for the directed fuzzer.

```bash
uv run --project solutions/taint taint-analysis \
  'jpamb.cases.advanced.CWE470.unsafe_dispatcher:(Ljava/lang/String;)V'
```

In the integrated pipeline, the syntactic stage should build the call graph
once and share the resulting artifact with both the taint analysis and the
fuzzer:

```bash
JPAMB_CALL_GRAPH_PATH=call-graph.json \
uv run --project solutions/taint taint-analysis \
  'jpamb.cases.advanced.CWE470.unsafe_dispatcher:(Ljava/lang/String;)V'
```

If `JPAMB_CALL_GRAPH_PATH` is absent, the command invokes
`solutions/syntactic/src/call_graph.py` as a standalone fallback. The JSON
output must contain:

- `graph`: method-to-method edges used to compute distances;
- `call_sites`: caller, opcode-list `instruction_index`, and
  `resolved_callees` for each invocation;
- `exploit_targets`: final canary methods.

The output classifies the method as `unflagged` or `flagged_unverified` and
lists the taint sink, source labels, relevant entry parameters, and distance
to the exploit target for every finding. Dynamic execution is responsible for
upgrading a verified finding to `vulnerable`.

During the configuration-name transition, the call-graph loader also accepts
the old `sinks` field as an alias for `exploit_targets`.
