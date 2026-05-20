#!/usr/bin/env python3
"""
Kubernetes insecure-spec remediation generator.

Covers rules from patterns/k8s_insecure_spec.yml:
  - k8s_privileged_container
  - k8s_host_network / k8s_host_pid / k8s_host_ipc
  - k8s_capabilities_add_dangerous
  - k8s_run_as_root
  - k8s_default_service_account
  - k8s_automount_sa_token
  - k8s_allow_privilege_escalation
  - k8s_readonly_root_filesystem_false
  - k8s_hostpath_volume
  - k8s_seccomp_unconfined / k8s_apparmor_unconfined
  - k8s_wildcard_rbac
  - k8s_image_latest_or_untagged
  - k8s_ephemeral_debug_container
  - k8s_hostport_privileged / k8s_service_nodeport
  - k8s_no_resource_limits
"""

from .base import BaseRemediationGenerator


class K8sInsecureSpecRemediationGenerator(BaseRemediationGenerator):
    """Remediations for insecure Kubernetes pod/workload specs."""

    _FIX_MAP = {
        "k8s_allow_privilege_escalation": "_fix_allow_priv_esc",
        "k8s_apparmor_unconfined": "_fix_apparmor_unconfined",
        "k8s_automount_sa_token": "_fix_automount_sa",
        "k8s_capabilities_add_dangerous": "_fix_capabilities",
        "k8s_default_service_account": "_fix_default_sa",
        "k8s_ephemeral_debug_container": "_fix_ephemeral_debug",
        "k8s_host_ipc": "_fix_host_ipc",
        "k8s_host_network": "_fix_host_network",
        "k8s_host_pid": "_fix_host_pid",
        "k8s_hostpath_volume": "_fix_hostpath",
        "k8s_hostport_privileged": "_fix_hostport_privileged",
        "k8s_image_latest_or_untagged": "_fix_image_latest",
        "k8s_no_resource_limits": "_fix_no_resource_limits",
        "k8s_privileged_container": "_fix_privileged",
        "k8s_readonly_root_filesystem_false": "_fix_readonly_rootfs",
        "k8s_run_as_root": "_fix_run_as_root",
        "k8s_seccomp_unconfined": "_fix_seccomp_unconfined",
        "k8s_service_nodeport": "_fix_service_nodeport",
        "k8s_wildcard_rbac": "_fix_wildcard_rbac",
    }

    _BASELINE_POD_SPEC = """\
# Baseline hardened pod spec - apply unless the workload has a documented exception
spec:
  automountServiceAccountToken: false
  serviceAccountName: app-ro                 # dedicated SA, least-privilege RBAC
  securityContext:
    runAsNonRoot: true
    runAsUser: 10001
    runAsGroup: 10001
    fsGroup: 10001
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: app
      image: ghcr.io/example/app@sha256:<digest>
      imagePullPolicy: IfNotPresent
      securityContext:
        allowPrivilegeEscalation: false
        privileged: false
        readOnlyRootFilesystem: true
        capabilities:
          drop: ["ALL"]
      resources:
        limits:   { cpu: "500m", memory: "512Mi" }
        requests: { cpu: "100m", memory: "128Mi" }
"""

    def generate_k8s_insecure_spec_fix(self, rule_id: str, code_snippet: str) -> str:
        return self._dispatch_fix(rule_id, code_snippet, self._fix_generic)

    # per-rule fixes

    def _fix_privileged(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 privileged: true = full root on the node:**
A privileged container has all capabilities, sees all devices, and can load kernel modules. Any RCE inside the container is effectively RCE on the node. This is the single most dangerous pod-spec setting.

**✅ Secure Fix - Drop privileged, add only needed capabilities:**
```yaml
- name: create hardened pod
  kubernetes.core.k8s:
    definition:
      apiVersion: v1
      kind: Pod
      metadata:
        name: app
      spec:
        securityContext:
          runAsNonRoot: true
          runAsUser: 10001
        containers:
          - name: app
            image: ghcr.io/example/app@sha256:<digest>
            securityContext:
              privileged: false                      # explicit
              allowPrivilegeEscalation: false
              readOnlyRootFilesystem: true
              capabilities:
                drop: ["ALL"]
                add: ["NET_BIND_SERVICE"]            # only if binding < 1024
```

**✅ Cluster-level guardrail (Pod Security Standard):**
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: workloads
  labels:
    pod-security.kubernetes.io/enforce: restricted   # blocks privileged pods
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

**🔐 Hardening:**
- Treat `privileged: true` as a security incident - it requires a documented, time-boxed exception.
- Use Gatekeeper/Kyverno admission policies to auto-reject privileged pods cluster-wide.
- Audit with: `kubectl get pods -A -o json | jq '.items[] | select(.spec.containers[]?.securityContext.privileged==true) | .metadata.namespace+"/"+.metadata.name'`

"""

    def _fix_host_network(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 hostNetwork: true bypasses NetworkPolicies:**
Pod shares the node's network namespace - can sniff every packet, bind to privileged ports on the node, and completely ignore NetworkPolicies (which only apply to pod-network traffic).

**✅ Secure Fix - Use pod networking + Service:**
```yaml
- name: app pod + service (no hostNetwork)
  kubernetes.core.k8s:
    definition:
      apiVersion: v1
      kind: Pod
      metadata: {{ name: app }}
      spec:
        hostNetwork: false                 # explicit
        containers:
          - name: app
            image: ghcr.io/example/app@sha256:<digest>
            ports:
              - containerPort: 8080
---
apiVersion: v1
kind: Service
metadata: {{ name: app }}
spec:
  selector: {{ app: app }}
  ports:
    - port: 80
      targetPort: 8080
```

**✅ If host access is truly needed (CNI/monitoring):**
```yaml
# Run as a DaemonSet in its OWN namespace with a PSS exception.
apiVersion: apps/v1
kind: DaemonSet
metadata:
  namespace: kube-system-extensions
spec:
  template:
    spec:
      hostNetwork: true                    # documented, namespaced, auditable
      nodeSelector: {{ node-role.kubernetes.io/infra: "true" }}
      tolerations:
        - operator: Exists
```

**🔐 Hardening:**
- Require `hostNetwork: false` in the `restricted` Pod Security Standard.
- Audit: `kubectl get pods -A -o json | jq '.items[] | select(.spec.hostNetwork==true) | .metadata.name'`
- NetworkPolicies are ineffective against hostNetwork pods - track them separately.

"""

    def _fix_host_pid(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 hostPID: true = trivial container escape:**
Pod sees every process on the node. Attacker can read env vars of other pods (credentials), signal kubelet, and access `/proc/1/root/` for direct node filesystem access.

**✅ Secure Fix - Drop hostPID, use pod-scoped process sharing:**
```yaml
spec:
  hostPID: false                   # explicit
  shareProcessNamespace: true      # pod-scoped alternative if sidecars need to see each other
  containers:
    - name: app
      image: ghcr.io/example/app@sha256:<digest>
```

**🔐 Hardening:**
- Use `shareProcessNamespace` (pod-scoped) instead of `hostPID` (node-scoped).
- Blocked by `restricted` Pod Security Standard.

"""

    def _fix_host_ipc(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 hostIPC: true shares kernel IPC with the host:**
Pod can read/write host shared-memory segments (shmget/shmat), message queues, and semaphores - useful for cross-pod credential theft in clusters with co-tenants.

**✅ Secure Fix - Drop hostIPC:**
```yaml
spec:
  hostIPC: false                   # explicit
  containers:
    - name: app
      image: ghcr.io/example/app@sha256:<digest>
```

**🔐 Hardening:**
- If containers truly need shared state, use an `emptyDir.medium: Memory` volume, not hostIPC.
- Blocked by `restricted` Pod Security Standard.

"""

    def _fix_capabilities(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Dangerous Linux capability added:**
SYS_ADMIN is effectively `privileged: true`. NET_ADMIN + SYS_PTRACE + DAC_READ_SEARCH + SYS_MODULE each enable specific container-escape paths. Grant each with a documented reason or not at all.

**✅ Secure Fix - Drop ALL, add only what's justified:**
```yaml
securityContext:
  capabilities:
    drop: ["ALL"]
    add: []              # nothing; if you need any, document in a comment
    # add: ["NET_BIND_SERVICE"]   # only for binding to < 1024
    # add: ["CHOWN", "FOWNER"]    # only during image-build entrypoint setup
```

**✅ Capability reference (avoid):**
| Capability        | Enables                                             |
|-------------------|-----------------------------------------------------|
| SYS_ADMIN         | Near-equivalent to privileged; mount, cgroup writes |
| NET_ADMIN         | iptables, tc, raw sockets                           |
| SYS_PTRACE        | Attach/debug any process in the container           |
| DAC_READ_SEARCH   | Read any file regardless of DAC                     |
| SYS_MODULE        | Load kernel modules                                 |
| SYS_RAWIO         | Direct hardware I/O                                 |
| SYS_BOOT          | Reboot the host                                     |
| SYS_TIME          | Change the system clock                             |

**🔐 Hardening:**
- Default to `drop: ["ALL"]`. Any `add:` entry must be reviewed.
- Use Gatekeeper/Kyverno to enforce an allow-list of addable capabilities.

"""

    def _fix_run_as_root(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Container runs as UID 0:**
Every RCE becomes root-in-container. Combined with any container-escape primitive, this is root-on-node.

**✅ Secure Fix - Run as a non-root UID:**
```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 10001
  runAsGroup: 10001
  fsGroup: 10001
```

**✅ At container level (overrides pod-level):**
```yaml
containers:
  - name: app
    securityContext:
      runAsNonRoot: true
      runAsUser: 10001
```

**✅ Build a distroless/minimal image with non-root user:**
```dockerfile
FROM gcr.io/distroless/static:nonroot
COPY app /app
USER nonroot:nonroot
ENTRYPOINT ["/app"]
```

**🔐 Hardening:**
- Chown writable paths at build time so the entrypoint does not need UID 0.
- Admission rule: reject pods with `runAsNonRoot != true` OR `runAsUser == 0`.
- Required by the `restricted` Pod Security Standard.

"""

    def _fix_default_sa(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Uses the `default` ServiceAccount:**
In most clusters the `default` SA has legacy read/list permissions and its token is auto-mounted. RCE in the pod = kubeconfig for the SA = cluster recon at minimum.

**✅ Secure Fix - Dedicated SA + least-privilege Role:**
```yaml
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: app-ro
  namespace: workloads
automountServiceAccountToken: false
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: app-ro
  namespace: workloads
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get", "list"]          # only what's needed
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {{ name: app-ro, namespace: workloads }}
subjects: [{{ kind: ServiceAccount, name: app-ro, namespace: workloads }}]
roleRef: {{ kind: Role, name: app-ro, apiGroup: rbac.authorization.k8s.io }}
---
apiVersion: v1
kind: Pod
metadata: {{ name: app, namespace: workloads }}
spec:
  serviceAccountName: app-ro
  automountServiceAccountToken: true   # only if the pod actually calls the API
```

**✅ Harden the `default` SA cluster-wide:**
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: default
  namespace: workloads
automountServiceAccountToken: false      # stop auto-mounting everywhere
```

**🔐 Hardening:**
- One SA per workload; never share SAs across apps.
- Disable auto-mount on `default` in every namespace.
- Use OPA/Kyverno to reject pods with `serviceAccountName: default`.

"""

    def _fix_automount_sa(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Pod auto-mounts its SA token:**
Even if the workload does not call the API, its SA token is mounted at `/var/run/secrets/kubernetes.io/serviceaccount/token`. Any RCE reads the token, then talks to the API as the SA.

**✅ Secure Fix - Disable auto-mount:**
```yaml
spec:
  automountServiceAccountToken: false      # pod-level override
  serviceAccountName: app-ro
  containers:
    - name: app
      image: ghcr.io/example/app@sha256:<digest>
```

**✅ Only if the pod actually calls the API - use projected token volume:**
```yaml
spec:
  automountServiceAccountToken: false
  serviceAccountName: app-api
  containers:
    - name: app
      volumeMounts:
        - name: api-token
          mountPath: /var/run/secrets/tokens
          readOnly: true
  volumes:
    - name: api-token
      projected:
        sources:
          - serviceAccountToken:
              path: token
              expirationSeconds: 600       # short-lived, auto-rotated
              audience: kubernetes.default.svc
```

**🔐 Hardening:**
- Default to `automountServiceAccountToken: false` at both SA and Pod level.
- Prefer projected tokens with short `expirationSeconds` to static SA tokens.

"""

    def _fix_allow_priv_esc(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 allowPrivilegeEscalation: true permits setuid escalation:**
setuid binaries inside the container (e.g. `sudo`, `su`, `ping`) can elevate to root even when the container runs as a non-root user. Blocking this closes a common escape path.

**✅ Secure Fix:**
```yaml
securityContext:
  allowPrivilegeEscalation: false      # required by restricted PSS
  runAsNonRoot: true
  capabilities:
    drop: ["ALL"]
```

**🔐 Hardening:**
- Combine with `readOnlyRootFilesystem: true` to block attackers from dropping setuid binaries.
- Required by the `restricted` Pod Security Standard.

"""

    def _fix_readonly_rootfs(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Writable container rootfs aids persistence:**
An attacker who lands an RCE can drop shell scripts, binaries, or backdoors into `/tmp`, `/var/`, or `/etc/` and survive container restarts if there's an init hook.

**✅ Secure Fix - Read-only rootfs + targeted writable volumes:**
```yaml
spec:
  containers:
    - name: app
      image: ghcr.io/example/app@sha256:<digest>
      securityContext:
        readOnlyRootFilesystem: true
      volumeMounts:
        - name: tmp
          mountPath: /tmp
        - name: cache
          mountPath: /var/cache/app
  volumes:
    - name: tmp
      emptyDir: {{ medium: Memory, sizeLimit: 64Mi }}
    - name: cache
      emptyDir: {{ sizeLimit: 256Mi }}
```

**🔐 Hardening:**
- Audit writable paths in the image: `docker run --read-only image:tag -c "your-app"` and fix writes one by one.
- Pair with `allowPrivilegeEscalation: false` to prevent setuid drops.

"""

    def _fix_hostpath(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 hostPath volume is a container-escape superhighway:**
`/etc/`, `/root/`, `/var/run/docker.sock`, `/var/lib/kubelet/` all enable trivial escape. Even read-only hostPath of sensitive paths leaks host secrets.

**✅ Secure Fix - Use pod-scoped volumes:**
```yaml
volumes:
  - name: workdir
    emptyDir: {{ sizeLimit: 512Mi }}
  - name: config
    configMap:
      name: app-config
  - name: tls
    secret:
      secretName: app-tls
  - name: persistent
    persistentVolumeClaim:
      claimName: app-data
```

**✅ If hostPath is truly required (CSI/logging):**
```yaml
# Restrict to a specific, audit-able path; DaemonSet only; namespace pinned.
volumes:
  - name: logs
    hostPath:
      path: /var/log/pods/myapp        # narrow, not /var/log
      type: DirectoryOrCreate
```

**✅ Admission policy to restrict hostPath allow-list:**
```yaml
# Kyverno ClusterPolicy example
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata: {{ name: restrict-hostpath }}
spec:
  validationFailureAction: enforce
  rules:
    - name: restrict-hostpath-paths
      match:
        any:
        - resources: {{ kinds: [Pod] }}
      validate:
        message: "hostPath is restricted to /var/log/pods/*"
        pattern:
          spec:
            =(volumes):
              - =(hostPath):
                  path: "/var/log/pods/*"
```

**🔐 Hardening:**
- Reject `hostPath: path` matching `/etc`, `/root`, `/var/run/*`, `/var/lib/kubelet/*`, `/proc`, `/sys`, `/dev`, `/boot`, `/home` outright.
- DaemonSets are the only legitimate hostPath use-case in most clusters.

"""

    def _fix_seccomp_unconfined(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 seccompProfile: Unconfined exposes the full kernel syscall surface:**
`RuntimeDefault` blocks ~44 rarely-used syscalls (mount, ptrace, reboot, kexec_load, bpf, userfaultfd, ...) with zero app impact for 99% of workloads. Disabling it turns every kernel CVE - Dirty Pipe, cgroupsv1 release_agent, nf_tables 0-day, io_uring use-after-free - into a one-syscall container escape.

**✅ Secure Fix - RuntimeDefault at the pod level:**
```yaml
spec:
  securityContext:
    seccompProfile:
      type: RuntimeDefault          # inherited by every container
  containers:
    - name: app
      image: ghcr.io/example/app@sha256:<digest>
```

**✅ Tighter - custom profile for a specific workload:**
```yaml
# /var/lib/kubelet/seccomp/profiles/myapp.json  (shipped by a DaemonSet)
# Then in the pod:
spec:
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: profiles/myapp.json
```

**🔐 Hardening:**
- Required by the `restricted` Pod Security Standard (Kubernetes ≥1.25).
- Audit: `kubectl get pods -A -o json | jq '.items[] | select(.spec.securityContext.seccompProfile.type=="Unconfined") | .metadata.namespace+"/"+.metadata.name'`
- Enforce via Kyverno policy that rejects `seccompProfile.type: Unconfined`.

"""

    def _fix_apparmor_unconfined(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 AppArmor unconfined removes LSM defense-in-depth:**
On Debian/Ubuntu-derived nodes, Kubernetes attaches the `runtime/default` AppArmor profile automatically - it blocks `mount`, `ptrace` of non-child processes, raw sockets, and writes to `/proc/sys/`. Explicit `unconfined` removes this entire layer; a generic container-breakout CVE then has no LSM to stop it.

**✅ Secure Fix - use runtime/default (the Kubernetes-managed baseline):**
```yaml
# Legacy annotation form (Kubernetes <1.30):
metadata:
  annotations:
    container.apparmor.security.beta.kubernetes.io/app: runtime/default

# Modern form (Kubernetes ≥1.30):
spec:
  securityContext:
    appArmorProfile:
      type: RuntimeDefault
  containers:
    - name: app
```

**✅ Custom profile for workloads that genuinely need a looser policy:**
```bash
# Load a profile on every node via a DaemonSet that copies to /etc/apparmor.d/
# Then reference it:
```
```yaml
metadata:
  annotations:
    container.apparmor.security.beta.kubernetes.io/app: localhost/myapp-profile
```

**🔐 Hardening:**
- Never use `unconfined` in production - it silently disables a LSM that's already running on every modern distro.
- Check nodes: `ssh node -- aa-status | head`
- Admission policy: reject pods with `...: unconfined` via Kyverno / OPA.

"""

    def _fix_wildcard_rbac(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Wildcard RBAC = effective cluster-admin:**
`verbs: ["*"]` includes `create pods/exec`, `create tokenreviews`, and every impersonation verb - any of which lead to cluster-admin. `resources: ["*"]` includes `secrets` (all keys in the cluster) and `tokenreviews`. `apiGroups: ["*"]` covers every CRD ever installed, including privileged ones from CNI/CSI drivers.

**✅ Secure Fix - enumerate the exact verbs + resources + apiGroups:**
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: app-ro
  namespace: workloads
rules:
  - apiGroups: [""]                        # core API group, not "*"
    resources: ["configmaps", "pods"]      # not "*"
    verbs: ["get", "list", "watch"]        # not "*"
  - apiGroups: ["apps"]
    resources: ["deployments/scale"]
    verbs: ["get", "update"]
```

**✅ Build the allow-list iteratively:**
```bash
# 1. Deploy with an empty Role
# 2. Collect Forbidden events
kubectl logs -n workloads deploy/app | grep -i forbidden
kubectl get events -n workloads | grep Forbidden
# 3. Add only the (apiGroup, resource, verb) tuples that the app actually called
```

**✅ Policy to reject wildcard rules cluster-wide (Kyverno):**
```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata: {{ name: deny-wildcard-rbac }}
spec:
  validationFailureAction: enforce
  rules:
    - name: no-wildcards-in-rules
      match:
        any:
          - resources: {{ kinds: [ClusterRole, Role] }}
      validate:
        message: "RBAC wildcard (* in verbs/resources/apiGroups) is not allowed."
        pattern:
          rules:
            - verbs: "!*"
              resources: "!*"
              apiGroups: "!*"
```

**🔐 Hardening:**
- Audit: `kubectl get clusterroles,roles -A -o json | jq '.items[] | select(.rules[]?.verbs[]? == "*" or .rules[]?.resources[]? == "*") | .metadata.name'`
- Use `kubectl auth can-i --list --as=system:serviceaccount:ns:sa` to verify each workload's effective permissions.
- Review RBAC in PRs; wildcard rules should require a second reviewer.

"""

    def _fix_image_latest(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 :latest is a mutable pointer - two identical manifests can run different code:**
`:latest` is re-pointed on every upstream push. A compromised registry, a supply-chain attack (shai-hulud, xz-utils), or an accidental bad push silently reaches every pod on the next `imagePullPolicy: Always` restart. Rollback by manifest is impossible because the manifest doesn't encode what code was running.

**✅ Secure Fix - pin to an immutable digest:**
```yaml
containers:
  - name: app
    image: ghcr.io/example/app@sha256:7d1a2b3c...64hex...    # immutable
    imagePullPolicy: IfNotPresent
```

**✅ Semver tag (acceptable fallback):**
```yaml
containers:
  - name: app
    image: ghcr.io/example/app:1.2.3                          # specific semver, not :latest
    imagePullPolicy: IfNotPresent                             # resolve once, cache
```

**✅ CI policy to reject :latest:**
```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata: {{ name: disallow-latest-tag }}
spec:
  validationFailureAction: enforce
  rules:
    - name: require-digest-or-semver
      match:
        any:
          - resources: {{ kinds: [Pod, Deployment, StatefulSet, DaemonSet] }}
      validate:
        message: "Image must be pinned to a digest (@sha256:...) or a specific semver tag."
        pattern:
          spec:
            containers:
              - image: "!*:latest | !*"     # tag must be present; not 'latest'
```

**🔐 Hardening:**
- Run Trivy/Grype in CI against the resolved digest, not the tag.
- Use a signing-verify admission controller (Cosign + Sigstore) to require the digest is signed by your CI.
- Audit: `kubectl get pods -A -o jsonpath='{{range .items[*]}}{{.metadata.namespace}}/{{.metadata.name}} {{range .spec.containers[*]}}{{.image}}{{"\\n"}}{{end}}{{end}}' | grep ':latest\\| [^@]*$'`

"""

    def _fix_ephemeral_debug(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Debug ephemeral container = pre-authenticated recon shell for every pod:**
Ephemeral containers share the target pod's PID, network, and mounted volumes - including the SA token at `/var/run/secrets/kubernetes.io/serviceaccount/token`. A `busybox`/`netshoot` sidecar committed to Git ships a debug shell to production that inherits the pod's RBAC and can be reached by anyone with `exec` permission on the namespace.

**✅ Secure Fix - remove from manifest, use kubectl debug on-demand:**
```yaml
spec:
  # NO ephemeralContainers: key in committed manifests.
  containers:
    - name: app
      image: ghcr.io/example/app@sha256:<digest>
```

```bash
# Operators run this only during an active troubleshooting session:
kubectl debug -n workloads app-abc123 \\
  --image=nicolaka/netshoot:latest \\
  --target=app \\
  -ti -- /bin/bash
# The debug container is NOT persisted to the PodSpec - it's gone after the session.
```

**✅ Admission policy to reject committed debug containers:**
```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata: {{ name: deny-ephemeral-containers }}
spec:
  validationFailureAction: enforce
  rules:
    - name: no-ephemeral-in-spec
      match:
        any:
          - resources: {{ kinds: [Pod, Deployment, StatefulSet] }}
      validate:
        message: "ephemeralContainers must not be committed; use `kubectl debug` instead."
        pattern:
          spec:
            =(ephemeralContainers): "null"
```

**🔐 Hardening:**
- Log and alert on every `kubectl debug` call (audit policy level = `RequestResponse` on `pods/ephemeralcontainers`).
- Restrict `pods/ephemeralcontainers` to a `breakglass` Role, bound only to the on-call SA.
- Never install network-tool images (`netshoot`, `dnsutils`) as regular containers - they are debug-only.

"""

    def _fix_hostport_privileged(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 hostPort in the privileged range (<1024) is a cluster-wide ingress hole:**
- The port is bound on every node's primary interface, reachable at `<any-node-ip>:<port>`.
- NetworkPolicies do NOT apply to hostPort traffic (it hits the host stack, not the pod network).
- Privileged ports frequently clash with node-level services (sshd:22, kubelet:10250, kube-proxy:10256).
- A single-pod bind silently blocks scheduling on every other node -> capacity loss.

**✅ Secure Fix - use a Service instead:**
```yaml
---
apiVersion: v1
kind: Pod
metadata: {{ name: app }}
spec:
  containers:
    - name: app
      image: ghcr.io/example/app@sha256:<digest>
      ports:
        - containerPort: 8080           # pod-network, no hostPort
---
apiVersion: v1
kind: Service
metadata: {{ name: app }}
spec:
  type: ClusterIP                       # in-cluster only
  selector: {{ app: app }}
  ports:
    - port: 80
      targetPort: 8080
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: {{ name: app }}
spec:
  tls:
    - hosts: [app.example.com]
      secretName: app-tls
  rules:
    - host: app.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend: {{ service: {{ name: app, port: {{ number: 80 }} }} }}
```

**✅ If a host-local bind is truly required (CNI / CSI):**
```yaml
# DaemonSet in its own namespace with PSS exception
apiVersion: apps/v1
kind: DaemonSet
metadata: {{ namespace: kube-system-extensions }}
spec:
  template:
    spec:
      hostNetwork: true                 # documented, namespaced
      tolerations: [ {{ operator: Exists }} ]
```

**🔐 Hardening:**
- Audit: `kubectl get pods -A -o jsonpath='{{range .items[*]}}{{range .spec.containers[*]}}{{range .ports[*]}}{{.hostPort}}{{" "}}{{end}}{{end}}{{end}}' | tr ' ' '\\n' | grep -E '^([1-9][0-9]{{0,2}}|10[0-1][0-9]|102[0-3])$'`
- Kyverno rule: deny `hostPort < 1024` cluster-wide.
- If you see port 22/53/80/443 as hostPort, you are probably breaking the node.

"""

    def _fix_service_nodeport(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Service type: NodePort exposes a port on every node's external NIC:**
- Default NodePort range is 30000-32767, bound to 0.0.0.0 on every worker.
- Bypasses Ingress controls: no TLS termination, no WAF, no rate limiting, no authentication.
- Turns every node into a direct ingress target - horizontal attack surface scales with cluster size.
- NetworkPolicies don't apply to NodePort ingress traffic.

**✅ Secure Fix - prefer ClusterIP + Ingress, or cloud LoadBalancer:**
```yaml
---
apiVersion: v1
kind: Service
metadata: {{ name: app }}
spec:
  type: ClusterIP                       # internal only
  selector: {{ app: app }}
  ports: [{{ port: 80, targetPort: 8080 }}]
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: app
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/rate-limit-rpm: "600"
spec:
  ingressClassName: nginx
  tls: [{{ hosts: [app.example.com], secretName: app-tls }}]
  rules:
    - host: app.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend: {{ service: {{ name: app, port: {{ number: 80 }} }} }}
```

**✅ Cloud LoadBalancer (managed ingress with security groups):**
```yaml
apiVersion: v1
kind: Service
metadata:
  name: app
  annotations:
    service.beta.kubernetes.io/aws-load-balancer-scheme: internal        # not internet-facing
    service.beta.kubernetes.io/aws-load-balancer-type: "nlb"
spec:
  type: LoadBalancer
  loadBalancerSourceRanges: ["10.0.0.0/8"]                               # restrict source IPs
  selector: {{ app: app }}
  ports: [{{ port: 443, targetPort: 8443 }}]
```

**✅ If NodePort is unavoidable (bare-metal, no LB):**
```yaml
# Pin the port, firewall the node, and document it.
apiVersion: v1
kind: Service
metadata: {{ name: app }}
spec:
  type: NodePort
  externalTrafficPolicy: Local          # only nodes running the pod answer
  selector: {{ app: app }}
  ports: [{{ port: 80, targetPort: 8080, nodePort: 31080 }}]
```
Then restrict with node-level iptables/nftables to trusted source ranges.

**🔐 Hardening:**
- Audit: `kubectl get svc -A -o json | jq '.items[] | select(.spec.type=="NodePort") | .metadata.namespace+"/"+.metadata.name'`
- Prefer `MetalLB` + `LoadBalancer` on bare-metal clusters instead of NodePort.
- NodePort traffic is not governed by NetworkPolicies - track it separately in your threat model.

"""

    def _fix_no_resource_limits(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Missing resource limits enables noisy-neighbor DoS:**
Without `resources.limits`, a single compromised or buggy pod can consume all CPU/memory on its node, triggering OOM-kills of co-tenants and evicting critical pods (ingress, DNS, CNI). For memory specifically, the container can never be OOM-killed early by cgroup - it keeps growing until the kernel OOMs the whole node.

**✅ Secure Fix - set requests AND limits on every container:**
```yaml
containers:
  - name: app
    image: ghcr.io/example/app@sha256:<digest>
    resources:
      requests:                         # baseline, for scheduling
        cpu: "100m"
        memory: "128Mi"
      limits:                           # hard ceiling
        cpu: "500m"
        memory: "512Mi"
```

**✅ Namespace-scoped defaults (belt-and-suspenders):**
```yaml
apiVersion: v1
kind: LimitRange
metadata:
  name: default-limits
  namespace: workloads
spec:
  limits:
    - type: Container
      default:
        cpu: "500m"
        memory: "512Mi"
      defaultRequest:
        cpu: "100m"
        memory: "128Mi"
      max:
        cpu: "4"
        memory: "4Gi"
---
apiVersion: v1
kind: ResourceQuota
metadata:
  name: workloads-quota
  namespace: workloads
spec:
  hard:
    requests.cpu: "20"
    requests.memory: 40Gi
    limits.cpu: "40"
    limits.memory: 80Gi
```

**✅ Admission policy to reject pods without limits:**
```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata: {{ name: require-resource-limits }}
spec:
  validationFailureAction: enforce
  rules:
    - name: require-cpu-memory-limits
      match:
        any:
          - resources: {{ kinds: [Pod] }}
      validate:
        message: "Every container must set resources.limits.cpu and resources.limits.memory."
        pattern:
          spec:
            containers:
              - resources:
                  limits:
                    memory: "?*"
                    cpu: "?*"
```

**🔐 Hardening:**
- Use the Vertical Pod Autoscaler (VPA) in recommendation mode to size limits based on real usage.
- Alert on `oom_kill_events` from the node exporter - indicates under-sized limits or over-subscribed nodes.
- For memory-hungry workloads, set `limits.memory == requests.memory` to get a Guaranteed QoS class and immunity from eviction.

"""

    def _fix_generic(self, code_snippet: str) -> str:
        return f"""
**❌ Vulnerable Code:**
```yaml
{code_snippet}
```

**🚨 Insecure Kubernetes Pod/Workload Spec:**
The pod spec bypasses one or more Kubernetes security defaults. Remediate by applying the baseline hardened spec below and removing any settings that weaken it.

**✅ Baseline Hardened Pod Spec:**
```yaml
{self._BASELINE_POD_SPEC}```

**🔐 Hardening:**
- Enforce `restricted` Pod Security Standard on every application namespace.
- Use Gatekeeper/Kyverno to codify admission policies matching your org's rules.
- Audit with `kube-bench` and `kube-hunter` at least weekly.
"""
