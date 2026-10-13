# SDD ledger — plan: x/docs/superpowers/plans/2026-10-07-tun-device-probe.md

Ruling: sdd-workspace script absent in this skill install (only task-start/task-done exist) — workspace created manually at x/.superpowers/sdd/2026-10-07-tun-device-probe/. Cost if wrong: none, git-ignored scratch.

Pre-flight shared-interface rows:
- T1→T2: md.probe/probeReport + runDeviceProbe signature. Plan pins report func(sentDelta, ackedDelta uint64); runDeviceProbe assumes non-nil (nil guard lives in probeDevice). No conflict.
- T1+T2→T3: h.md.probe/probeReport, runDeviceProbe, handleClient iterCtx/conn/ips. handleClient shape to verify in code recon before wiring.
- T3→T4: only files + green suite; no interface.

Task 1: complete (no commit per plan Global Constraints; tests: go test -count=1 ./handler/tun/ ./observer/stats/ → both ok, tun 14.356s).
Ruling: metadata constructor alias is xmd (github.com/go-gost/x/metadata), not mdx as plan Step 1 guessed — plan told me to grep first, did. Cost if wrong: nil.
Task 2: complete (no commit per plan Global Constraints; tests: go test -count=1 ./handler/tun/ → ok 14.987s).
Ruling: probeInterval/probeRecvTimeout are vars not consts (plan pinned values 30s/5s kept; tests override). Pinned signature runDeviceProbe(ctx,dev,ip,report,log) unchanged. Cost if wrong: nil.
Ruling: wrote runDeviceProbe impl before its loop test, caught it, deleted impl, re-did RED (undefined) → GREEN. Cost if wrong: unproven test.
Ruling: loop tests use atomic counters + polling (net.Pipe Read returns before writer Write/report; plain vars would race). Plan sketch used plain vars. Cost if wrong: flaky test.
Task 3: complete (no commit per plan Global Constraints; tests: go test -count=1 ./handler/tun/ ./observer/stats/ → both ok).
Note: gofmt -l flags observer/stats/wrapper/io_test.go — pre-existing, untouched (not in git status). My files clean; go vet clean.
Ruling: probeDevice takes no log param (uses h.options.Logger, same as keepalive); conn at the wire site IS the tun device (transportClient(ctx, tun=conn, ...) proves it). Cost if wrong: probe writes into the tunnel stream.
Task 4: green to the release gate (build ./... + both suites PASS). STOPPING before tag+push: publish side effect, maintainer-manual per plan + repo no-push norm. Awaiting human: commit + tag v0.23.0.
Final: fresh review via subagent. C1 (UDP length 16→must be 24, acked could never fire on real device) — confirmed real, re-graded Critical stands.
Final: fixed C1 — TestBuildProbePacket UDP-length assertion RED→GREEN, suite handler/tun ok.
Final: fixed I1 (Reset forgot probe counters) — TestStatsProbeReset RED→GREEN, suite observer/stats ok.
Final: minor (deferred): M1 redial overlap — old probe writes ≤5s alongside new after iterCtx cancel; datagram-atomic, self-healing.
Final: minor (deferred): M2 log assumed non-nil in probe paths.
Final: minor (deferred): M3 gate goroutine spawn on probeReport != nil to avoid one throwaway goroutine per redial on gost path.
Final: reviewer declined go toolchain — overruled, tests ran under /root/.local/go/bin (see memory dev-container-toolchain); kernel trim-vs-drop of len-16 packet no longer matters post-fix; water-driver atomicity stands on datagram semantics + keepalive precedent.
Pre-release workspace check (GOWORK=/root/opencode/probework/go.work, x+wisper+gost): go build ./... all three OK; wisper ./tunnel/... PASS (14.6s/15.3s); x handler/tun + observer/stats PASS.
