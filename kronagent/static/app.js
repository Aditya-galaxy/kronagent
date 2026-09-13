/* Kronagent Analyst Console Client Application */

document.addEventListener("DOMContentLoaded", () => {
    // State management
    const state = {
        activeTab: "overview",
        activeTenant: "default",
        status: {},
        metrics: {},
        approvals: [],
        audit: [],
        allowlist: [],
        oversight: null,
        operatorId: sessionStorage.getItem("kronagent_operator_id") || "",
        token: sessionStorage.getItem("kronagent_operator_token") || ""
    };

    // DOM Elements
    const elements = {
        navItems: document.querySelectorAll(".nav-item"),
        tabContents: document.querySelectorAll(".tab-content"),
        pageTitle: document.getElementById("page-title"),
        tenantSelect: document.getElementById("tenant-select"),
        
        // Status panel
        dryRun: document.getElementById("status-dryrun"),
        killSwitch: document.getElementById("status-killswitch"),
        integrity: document.getElementById("status-integrity"),

        // KPIs
        kpiFindings: document.getElementById("kpi-findings"),
        kpiPending: document.getElementById("kpi-pending"),
        kpiAutonomous: document.getElementById("kpi-autonomous"),
        kpiHuman: document.getElementById("kpi-human"),
        navPendingBadge: document.getElementById("nav-pending-badge"),
        queuePendingCount: document.getElementById("queue-pending-count"),

        // Lists/Tables
        overviewTimeline: document.getElementById("overview-timeline"),
        overviewEmptyState: document.getElementById("overview-empty-state"),
        queueList: document.getElementById("queue-list"),
        queueEmptyState: document.getElementById("queue-empty-state"),
        oversightBanner: document.getElementById("oversight-banner"),
        auditBody: document.getElementById("audit-table-body"),
        auditSearch: document.getElementById("audit-search"),
        allowlistBody: document.getElementById("allowlist-table-body"),
        allowlistAttentionCount: document.getElementById("allowlist-attention-count"),
        promoteForm: document.getElementById("promote-form"),
        promoteClass: document.getElementById("promote-class"),
        promoteReason: document.getElementById("promote-reason"),
        promoteOwner: document.getElementById("promote-owner"),
        promoteExpires: document.getElementById("promote-expires"),

        // Modals
        authModal: document.getElementById("auth-modal"),
        modalCloseBtn: document.getElementById("modal-close-btn"),
        modalCancelBtn: document.getElementById("modal-cancel-btn"),
        authForm: document.getElementById("auth-form"),
        modalActionTitle: document.getElementById("modal-action-title"),
        modalTargetId: document.getElementById("modal-target-id"),
        modalActionType: document.getElementById("modal-action-type"),
        modalActionClass: document.getElementById("modal-action-class"),
        modalExpiresIn: document.getElementById("modal-expires-in"),
        modalProvider: document.getElementById("modal-provider"),
        modalReasonGroup: document.getElementById("modal-reason-group"),
        modalOwnerGroup: document.getElementById("modal-owner-group"),
        modalOwnerLabel: document.getElementById("modal-owner-label"),
        modalOwnerNote: document.getElementById("modal-owner-note"),
        authOwner: document.getElementById("auth-owner"),
        authOperatorId: document.getElementById("auth-operator-id"),
        authToken: document.getElementById("auth-token"),
        authReason: document.getElementById("auth-reason"),
        sidebarOperatorId: document.getElementById("sidebar-operator-id"),
        sidebarOperatorToken: document.getElementById("sidebar-operator-token"),
        sidebarAuthSave: document.getElementById("sidebar-auth-save")
    };

    // Helper functions
    const formatTime = (ts) => {
        if (!ts) return "N/A";
        // Handles standard epoch ms
        if (typeof ts === "number") {
            return new Date(ts).toLocaleString();
        }
        // Handles ISO string
        try {
            return new Date(ts).toLocaleString();
        } catch {
            return ts;
        }
    };

    const getSeverityClass = (sev) => {
        if (sev >= 9.0) return "critical";
        if (sev >= 7.0) return "high";
        if (sev >= 4.0) return "medium";
        return "low";
    };

    const getSeverityLabel = (sev) => {
        if (sev >= 9.0) return "Critical";
        if (sev >= 7.0) return "High";
        if (sev >= 4.0) return "Medium";
        return "Low";
    };

    // Helper to get headers including optional operator credentials for VIEW permission
    const getHeaders = () => {
        const headers = { "X-Tenant-ID": state.activeTenant };
        if (state.operatorId) {
            headers["X-Operator-ID"] = state.operatorId;
        }
        if (state.token) {
            headers["X-Operator-Token"] = state.token;
        }
        return headers;
    };

    // API fetches
    const fetchStatus = async () => {
        try {
            const res = await fetch("/api/status", {
                headers: getHeaders()
            });
            state.status = await res.json();
            updateStatusUI();
        } catch (e) {
            console.error("Failed fetching status", e);
        }
    };

    const fetchMetrics = async () => {
        try {
            const res = await fetch("/api/metrics", {
                headers: getHeaders()
            });
            state.metrics = await res.json();
            updateMetricsUI();
        } catch (e) {
            console.error("Failed fetching metrics", e);
        }
    };

    const fetchApprovals = async () => {
        try {
            const res = await fetch("/api/approvals", {
                headers: getHeaders()
            });
            state.approvals = await res.json();
            updateApprovalsUI();
        } catch (e) {
            console.error("Failed fetching approvals", e);
        }
    };

    // ----------------------------------------------------------------------
    // Safe-by-default HTML templating.
    //
    // Everything this console renders is attacker-influenced. `target` is a
    // resource id or IP taken verbatim from the finding, so anyone who can name
    // an EC2 instance, an IAM user or an S3 key chooses that string. The three
    // *_summary fields are LLM prose derived from the same finding. All of it
    // was interpolated straight into innerHTML.
    //
    // That is stored XSS with an unusually bad blast radius: this console is
    // the governance surface, and it keeps the operator's APPROVE/PROMOTE token
    // in sessionStorage. Script running here can approve its own containment
    // actions, or promote an action class to auto-execute — turning the defence
    // system into the attack.
    //
    // The fix is a tagged template that escapes every interpolation, rather
    // than 74 hand-placed escape() calls that the 75th render will forget.
    // Markup composed by this file opts out explicitly via raw().
    // ----------------------------------------------------------------------

    class SafeHtml {
        constructor(value) { this.value = String(value); }
        toString() { return this.value; }
    }

    /** Mark a string as already-safe markup. Never call this on server data. */
    const raw = (value) => new SafeHtml(value);

    const escapeHtml = (value) => {
        if (value instanceof SafeHtml) return value.value;
        if (value === null || value === undefined) return "";
        // \x60 is a backtick. Written as an escape so this file contains no
        // backtick outside an actual template literal — which is what lets the
        // invariant in tests/test_console_escaping.py pair them reliably.
        return String(value).replace(/[&<>"'\x60]/g, c => ({
            "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;",
            "'": "&#39;", "\x60": "&#96;"
        }[c]));
    };

    /** Tagged template: h`<p>${untrusted}</p>` escapes every ${...}. */
    const h = (strings, ...values) => raw(
        strings.reduce((out, chunk, i) =>
            out + chunk + (i < values.length ? escapeHtml(values[i]) : ""), ""));

    // Whether the approval queue is still functioning as a control. Deliberately
    // rendered above the queue rather than on a separate dashboard: a metric
    // about rubber-stamping is worth nothing if you have to go looking for it.
    const fetchOversight = async () => {
        try {
            const res = await fetch("/api/oversight", {
                headers: getHeaders()
            });
            state.oversight = await res.json();
            updateOversightUI();
        } catch (e) {
            console.error("Failed fetching oversight metrics", e);
        }
    };

    const fetchAudit = async () => {
        try {
            const res = await fetch("/api/audit", {
                headers: getHeaders()
            });
            state.audit = await res.json();
            updateAuditUI();
        } catch (e) {
            console.error("Failed fetching audit", e);
        }
    };

    // /api/allowlist/review, not /api/allowlist: the console is a governance
    // surface, so it needs the owner, the TTL, and whether the entry has ever
    // actually fired — and it needs lapsed entries to stay visible, since
    // deciding whether to renew one means looking at it.
    const fetchAllowlist = async () => {
        try {
            const res = await fetch("/api/allowlist/review", {
                headers: getHeaders()
            });
            state.allowlist = await res.json();
            updateAllowlistUI();
        } catch (e) {
            console.error("Failed fetching allowlist", e);
        }
    };

    // UI updates
    const updateStatusUI = () => {
        // Dry-run
        if (state.status.dry_run) {
            elements.dryRun.className = "status-indicator";
            elements.dryRun.innerHTML = h`<span class="dot yellow"></span> DRY RUN: ACTIVE`;
        } else {
            elements.dryRun.className = "status-indicator";
            elements.dryRun.innerHTML = h`<span class="dot green"></span> DRY RUN: REAL DISPATCH`;
        }

        // Killswitch
        if (state.status.kill_switch) {
            elements.killSwitch.className = "status-indicator";
            elements.killSwitch.innerHTML = h`<span class="dot red"></span> KILL SWITCH: ENGAGED`;
        } else {
            elements.killSwitch.className = "status-indicator";
            elements.killSwitch.innerHTML = h`<span class="dot green"></span> KILL SWITCH: OFF`;
        }

        // Integrity
        if (state.status.integrity_verified) {
            elements.integrity.className = "status-indicator";
            elements.integrity.innerHTML = h`<span class="dot green"></span> LOG INTEGRITY: VERIFIED`;
        } else {
            elements.integrity.className = "status-indicator";
            elements.integrity.innerHTML = h`<span class="dot red"></span> LOG INTEGRITY: COMPROMISED`;
        }
    };

    const updateMetricsUI = () => {
        elements.kpiFindings.textContent = state.metrics.total_findings || 0;
        elements.kpiPending.textContent = state.metrics.total_pending || 0;
        elements.kpiAutonomous.textContent = state.metrics.total_autonomous_actions || 0;
        elements.kpiHuman.textContent = state.metrics.total_human_overridden_actions || 0;
        
        // Update nav badges
        const pending = state.metrics.total_pending || 0;
        if (pending > 0) {
            elements.navPendingBadge.style.display = "inline-block";
            elements.navPendingBadge.textContent = pending;
            elements.queuePendingCount.textContent = `${pending} Pending`;
        } else {
            elements.navPendingBadge.style.display = "none";
            elements.queuePendingCount.textContent = "0 Pending";
        }
    };

    const updateOversightUI = () => {
        const m = state.oversight;
        const el = elements.oversightBanner;
        if (!m || !el) return;

        if (m.healthy) {
            el.style.display = "none";
            return;
        }
        const stat = (label, value) => h`<span class="oversight-stat">
            <strong>${value}</strong> ${label}</span>`;
        const decideTime = m.median_seconds_to_decide === null
            ? "—"
            : `${Math.round(m.median_seconds_to_decide)}s`;

        el.style.display = "block";
        el.className = "oversight-banner";
        el.innerHTML = h`
            <div class="oversight-head">⚠ This approval queue may no longer be a control</div>
            <div class="oversight-stats">
                ${stat("deny rate", (m.deny_rate * 100).toFixed(1) + "%")}
                ${stat("decisions", m.decided)}
                ${stat("median time to decide", decideTime)}
            </div>
            <ul class="oversight-warnings">
                ${m.warnings.map(w => h`<li>${w}</li>`).join("")}
            </ul>`;
    };

    const updateApprovalsUI = () => {
        const pendingList = state.approvals.filter(a => a.status === "pending");
        if (pendingList.length === 0) {
            elements.queueEmptyState.style.display = "block";
            elements.queueList.innerHTML = "";
            return;
        }

        elements.queueEmptyState.style.display = "none";
        elements.queueList.innerHTML = pendingList.map(req => {
            const plannedCalls = raw(req.planned_api_calls.map(c => h`<li>$ ${c}</li>`).join(""));
            const techniques = raw(req.mitre_techniques.map(t => h`<span class="tech-tag">${t}</span>`).join(""));
            const severityClass = getSeverityClass(req.severity);
            const severityLabel = getSeverityLabel(req.severity);

            return h`
                <div class="request-card" id="card-${req.request_id}">
                    <div class="request-card-header">
                        <div class="request-meta">
                            <h3>${req.action_class} on <code>${req.target}</code></h3>
                            <p>Request ID: <strong>${req.request_id}</strong> | Ingested: ${formatTime(req.created_at)}</p>
                        </div>
                        <span class="severity-badge ${severityClass}">${severityLabel} (${req.severity})</span>
                    </div>
                    <div class="request-body">
                        <div class="intel-box">
                            <p><strong>Finding Target:</strong> ${req.finding_type} (${req.finding_id})</p>
                            <p><strong>Rationale:</strong> <em>${req.rationale}</em></p>
                            <p><strong>Policy gate reason:</strong> ${req.policy_reason}</p>
                            </div>

                            <!-- Model-written context. Kept OUT of the box above, which holds only
                                 what Kronagent computed, because a language model wrote this after
                                 reading the finding - and the finding contains attacker-chosen text.
                                 Rendered beside policy_reason in the same style, a reviewer had no
                                 way to tell Kronagent's reasoning from an LLM's steerable summary. -->
                            ${req.provenance_warning ? h`<div class="model-context">
                                <div class="model-context-head">Written by a language model &middot; context, not evidence</div>
                                <p class="model-context-why">${req.provenance_warning}</p>
                                ${req.threat_intel_summary ? h`<p><strong>Threat intelligence:</strong> ${req.threat_intel_summary}</p>` : ""}
                                ${techniques ? h`<div class="model-context-tags"><span class="model-context-label">MITRE (model-mapped):</span> ${techniques}</div>` : ""}
                                ${req.correlation_summary ? h`<p><strong>Correlation:</strong> ${req.correlation_summary}</p>` : ""}
                                ${req.incident_narrative ? h`<p><strong>Incident narrative:</strong> ${req.incident_narrative}</p>` : ""}
                            </div>` : ""}
                        
                        <div class="api-box">
                            <strong>Planned containment API operations:</strong>
                            <ul style="margin: 8px 0 0 16px; font-size:13px; font-family:var(--font-code); color:#38bdf8;">
                                ${plannedCalls}
                            </ul>
                            <p style="font-size:12px; margin-top:8px; color:var(--text-muted);">
                                <strong>Rollback logic:</strong> ${req.rollback_hint || "N/A"}
                            </p>
                        </div>
                    </div>
                    <div class="request-actions">
                        <button class="btn btn-primary" onclick="openApprovalModal('${req.request_id}', 'approve')">Approve Action</button>
                        <button class="btn btn-danger" onclick="openApprovalModal('${req.request_id}', 'deny')">Deny / Discard</button>
                    </div>
                </div>
            `;
        }).join("");
    };

    const updateAuditUI = () => {
        if (state.audit.length === 0) {
            elements.auditBody.innerHTML = h`<tr><td colspan="4" class="text-center">No audit records found.</td></tr>`;
            elements.overviewTimeline.innerHTML = "";
            elements.overviewEmptyState.style.display = "block";
            return;
        }

        // Render Overview Timeline (Recent 5 events)
        elements.overviewEmptyState.style.display = "none";
        const recentEvents = [...state.audit].reverse().slice(0, 5);
        elements.overviewTimeline.innerHTML = recentEvents.map(event => {
            let stageDesc = "";
            const payload = event.payload || {};
            
            if (event.stage === "triage") {
                stageDesc = `Assessed ${payload.threat_category} | Severity ${payload.severity} | *${payload.justification}*`;
            } else if (event.stage === "policy") {
                const action = payload.action || {};
                const decision = payload.decision || {};
                stageDesc = h`Evaluated ${action.action_class} on ${action.target} | Disposition: <strong>${decision.disposition}</strong> (${decision.reason})`;
            } else if (event.stage === "containment") {
                stageDesc = h`Executed ${payload.action_class} on ${payload.target} | Status: <strong>${payload.executed ? 'Executed' : 'Dry-Run/Pending'}</strong> (${payload.detail})`;
            } else if (event.stage === "approval") {
                stageDesc = h`Human ${payload.decision} for ${payload.action_class} on ${payload.target} by <strong>${payload.operator_id}</strong>`;
            } else if (event.stage === "governance") {
                // `by` covers the system-authored decisions (expiry sweeps and
                // expiry warnings have no operator behind them); operator_id is
                // only present when a human ran the command. Falling through to
                // operator_id alone rendered those as "by **undefined**".
                const actor = payload.operator_id || payload.by || "system";
                if (payload.decision === "allowlist_expired") {
                    stageDesc = h`Autonomy for ${payload.action_class} <strong>lapsed</strong> (TTL elapsed, not renewed) — owner was ${payload.owner || payload.promoted_by}`;
                } else if (payload.decision === "allowlist_expiry_warning") {
                    stageDesc = `Warned ${payload.owner} that ${payload.action_class} is about to lapse${payload.notified ? "" : " (delivery failed — entry still expires on schedule)"}`;
                } else if (payload.decision === "allowlist_review") {
                    stageDesc = h`Allowlist reviewed by <strong>${actor}</strong> — ${(payload.flagged || []).length} of ${payload.entries} entries flagged`;
                } else if (payload.decision === "allowlist_reassign") {
                    stageDesc = h`Ownership of ${payload.action_class} moved ${payload.previous_owner ? `from ${payload.previous_owner} ` : ""}to ${payload.owner} by <strong>${actor}</strong>`;
                } else {
                    stageDesc = h`Allowlist modification: ${payload.decision} of ${payload.action_class} by <strong>${actor}</strong>`;
                }
            } else if (event.stage === "threat_intel") {
                stageDesc = `Threat intelligence update: *${payload.threat_intel_summary || payload.intel_summary || ''}*`;
            } else if (event.stage === "correlation") {
                stageDesc = `Correlated campaign findings: *${payload.correlation_summary || ''}*`;
            } else if (event.stage === "forensics") {
                const items = payload.items || [];
                stageDesc = `Preserved evidence: ${items.map(i => i.kind).join(", ")}`;
            } else if (event.stage === "error") {
                stageDesc = `Pipeline failure: *${payload.error}*`;
            } else {
                stageDesc = JSON.stringify(payload);
            }

            return h`
                <div class="timeline-item ${event.stage}">
                    <div class="timeline-header">
                        <span class="timeline-title">${event.stage.toUpperCase()} (${event.finding_id})</span>
                        <span class="timeline-time">${formatTime(event.ts)}</span>
                    </div>
                    <div class="timeline-desc">${stageDesc}</div>
                </div>
            `;
        }).join("");

        // Render full Audit explorer table
        renderFilteredAudit(elements.auditSearch.value);
    };

    const renderFilteredAudit = (filterText) => {
        const query = filterText.toLowerCase().trim();
        const filtered = state.audit.filter(e => {
            return e.finding_id.toLowerCase().includes(query) || 
                   e.stage.toLowerCase().includes(query) ||
                   JSON.stringify(e.payload).toLowerCase().includes(query);
        });

        if (filtered.length === 0) {
            elements.auditBody.innerHTML = h`<tr><td colspan="4" class="text-center">No matching audit records found.</td></tr>`;
            return;
        }

        elements.auditBody.innerHTML = filtered.map(event => {
            return h`
                <tr>
                    <td style="font-family:var(--font-code); font-size:12px; color:var(--text-secondary); white-space:nowrap;">${formatTime(event.ts)}</td>
                    <td><code>${event.finding_id}</code></td>
                    <td><span class="severity-badge ${event.stage === 'error' ? 'critical' : 'medium'}" style="text-transform:uppercase; font-size:11px;">${event.stage}</span></td>
                    <td style="font-size:13px; color:var(--text-secondary); max-width: 500px; overflow-wrap: break-word;"><pre style="font-family:var(--font-code); background:none; padding:0; overflow-x:auto;">${JSON.stringify(event.payload, null, 2)}</pre></td>
                </tr>
            `;
        }).join("");
    };

    const DAY_MS = 86400000;
    const EXPIRING_SOON_MS = 14 * DAY_MS;

    // Coarse on purpose: governance review is a days-and-weeks conversation.
    const humanizeMs = (ms) => {
        const abs = Math.abs(ms);
        if (abs < 3600000) return `${Math.round(abs / 60000)}m`;
        if (abs < DAY_MS) return `${Math.round(abs / 3600000)}h`;
        return `${Math.round(abs / DAY_MS)}d`;
    };

    const expiryCell = (entry) => {
        if (!entry.expires_at) {
            return h`<span class="text-muted">never</span>
                    <div class="cell-sub">standing authority</div>`;
        }
        const ms = new Date(entry.expires_at).getTime() - Date.now();
        if (entry.expired) {
            return h`<span class="text-danger">lapsed ${humanizeMs(ms)} ago</span>
                    <div class="cell-sub">${formatTime(entry.expires_at)}</div>`;
        }
        const cls = ms <= EXPIRING_SOON_MS ? "text-warning" : "";
        return h`<span class="${cls}">in ${humanizeMs(ms)}</span>
                <div class="cell-sub">${formatTime(entry.expires_at)}</div>`;
    };

    const firedCell = (entry) => {
        if (entry.never_fired) {
            return h`<span class="text-muted">never</span>
                    <div class="cell-sub">authorized nothing since promotion</div>`;
        }
        const ms = Date.now() - new Date(entry.last_fired_at).getTime();
        return h`<span>${humanizeMs(ms)} ago</span>
                <div class="cell-sub">${entry.fire_count}&times; total</div>`;
    };

    // Worst-first: an operator scanning this column should hit the thing that
    // needs a decision before the things that don't.
    const statusBadges = (entry) => {
        const badges = [];
        if (!entry.known_action_class) {
            badges.push(h`<span class="severity-badge critical">UNKNOWN CLASS</span>`);
        } else if (!entry.auto_eligible) {
            badges.push(h`<span class="severity-badge critical">NOT AUTO-ELIGIBLE</span>`);
        }
        if (entry.expired) {
            badges.push(h`<span class="severity-badge critical">EXPIRED</span>`);
        } else if (entry.expires_at &&
                   new Date(entry.expires_at).getTime() - Date.now() <= EXPIRING_SOON_MS) {
            badges.push(h`<span class="severity-badge high">EXPIRING SOON</span>`);
        }
        if (entry.never_fired) {
            badges.push(h`<span class="severity-badge medium">NEVER FIRED</span>`);
        } else if (entry.stale) {
            badges.push(h`<span class="severity-badge medium">STALE</span>`);
        }
        if (!entry.expires_at) {
            badges.push(h`<span class="severity-badge medium">NO TTL</span>`);
        }
        if (badges.length === 0) {
            badges.push(h`<span class="severity-badge low">ACTIVE</span>`);
        }
        return h`<div class="status-badges">${raw(badges.join(""))}</div>`;
    };

    const needsDecision = (entry) =>
        entry.expired || entry.stale || entry.never_fired || !entry.expires_at ||
        !entry.auto_eligible || !entry.known_action_class;

    // The policy engine's own classification, served by the API rather than
    // guessed here from the class name — the console used to guess and got it
    // wrong, reporting block_ip as subnet-wide and revoke_role_sessions as
    // account-wide when the policy table calls both single-resource.
    const classificationCell = (entry) => {
        if (!entry.known_action_class) {
            return `not in the action taxonomy`;
        }
        const blast = (entry.blast_radius || "").replace(/_/g, " ");
        return `${entry.reversible ? "reversible" : "irreversible"} &middot; ${blast}`;
    };

    const updateAllowlistUI = () => {
        if (state.allowlist.length === 0) {
            elements.allowlistBody.innerHTML = h`<tr><td colspan="6" class="text-center">No allowlist entries configured — every action requires human approval.</td></tr>`;
            elements.allowlistAttentionCount.textContent = "0 need a decision";
            return;
        }

        const flagged = state.allowlist.filter(needsDecision).length;
        elements.allowlistAttentionCount.textContent =
            `${flagged} of ${state.allowlist.length} need a decision`;

        elements.allowlistBody.innerHTML = state.allowlist.map(entry => {
            const ac = entry.action_class;
            // Deliberately NOT flagging owner !== promoted_by as "reassigned":
            // promoting on someone else's behalf produces exactly that shape at
            // promotion time, so the claim would be false on every such row. A
            // real reassignment is an audit event, not something the entry shows.
            return h`
                <tr class="${entry.expired ? "row-lapsed" : ""}">
                    <td>
                        <code>${ac}</code>
                        <div class="cell-sub" title="${entry.reason}">${entry.reason}</div>
                        <div class="cell-sub">${classificationCell(entry)}</div>
                    </td>
                    <td>
                        ${entry.owner}
                        <div class="cell-sub">promoted by ${entry.promoted_by}</div>
                    </td>
                    <td>${statusBadges(entry)}</td>
                    <td>${expiryCell(entry)}</td>
                    <td>${firedCell(entry)}</td>
                    <td class="governance-actions">
                        <button class="btn btn-primary btn-small" onclick="openAllowlistModal('${ac}', 'promote')">${entry.expired ? "Renew" : "Extend"}</button>
                        <button class="btn btn-secondary btn-small" onclick="openAllowlistModal('${ac}', 'reassign')">Reassign</button>
                        <button class="btn btn-danger btn-small" onclick="openAllowlistModal('${ac}', 'demote')">Demote</button>
                    </td>
                </tr>
            `;
        }).join("");
    };

    // Modal Actions (Exposed to window so HTML onclick attributes can invoke them)
    const resetAuthModal = () => {
        elements.authOperatorId.value = "";
        elements.authToken.value = "";
        elements.authReason.value = "";
        elements.authOwner.value = "";
        elements.modalExpiresIn.value = "";
        elements.modalProvider.value = "";
        elements.modalOwnerGroup.style.display = "none";
        elements.authOwner.required = false;
        elements.modalReasonGroup.style.display = "flex";
        elements.authReason.required = true;
    };

    window.openApprovalModal = (requestId, type) => {
        resetAuthModal();
        elements.modalActionTitle.textContent = type === "approve" ? "Authorize Action Execution" : "Reject Action Request";
        elements.modalTargetId.value = requestId;
        elements.modalActionType.value = type;
        elements.modalActionClass.value = "";
        elements.authModal.classList.add("active");
    };

    const ALLOWLIST_MODAL_TITLES = {
        promote: "Renew Autonomy for This Class",
        demote: "Demote Class from Allowlist",
        reassign: "Reassign Ownership"
    };

    window.openAllowlistModal = (actionClass, type) => {
        resetAuthModal();
        elements.modalActionTitle.textContent = ALLOWLIST_MODAL_TITLES[type] || "Authorize Action";
        elements.modalTargetId.value = "_governance";
        elements.modalActionType.value = type;
        elements.modalActionClass.value = actionClass;

        if (type === "reassign") {
            elements.modalOwnerGroup.style.display = "flex";
            elements.authOwner.required = true;
            elements.modalOwnerLabel.textContent = "New Owner";
            elements.modalOwnerNote.textContent =
                "Ownership moves; the promotion record (who promoted it, when, and why) does not.";
        }
        if (type === "promote") {
            // Renewing from the table is a fresh 90-day grant. The reason field
            // stays empty and required on purpose: re-earning autonomy means
            // stating why it still applies, not re-submitting the old answer.
            elements.modalExpiresIn.value = "90d";
        }
        elements.authModal.classList.add("active");
    };

    // Navigation switching
    elements.navItems.forEach(item => {
        item.addEventListener("click", () => {
            const tabId = item.getAttribute("data-tab");
            
            elements.navItems.forEach(i => i.classList.remove("active"));
            elements.tabContents.forEach(c => c.classList.remove("active"));
            
            item.classList.add("active");
            document.getElementById(`tab-${tabId}`).classList.add("active");
            
            state.activeTab = tabId;
            // The nav label is "<icon> Some Name" plus, on the queue, a count badge.
            // Splitting on whitespace and taking [1] truncated three of the four
            // titles ("Approval", "Audit", "Allowlist"); read the label instead.
            elements.pageTitle.textContent = item.querySelector(".nav-label").textContent.trim();
            
            refreshData();
        });
    });

    // Modal close events
    const closeModal = () => {
        elements.authModal.classList.remove("active");
    };
    elements.modalCloseBtn.addEventListener("click", closeModal);
    elements.modalCancelBtn.addEventListener("click", closeModal);

    // Form Submissions
    elements.authForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        
        const type = elements.modalActionType.value;
        const targetId = elements.modalTargetId.value;
        const actionClass = elements.modalActionClass.value;
        const operatorId = elements.authOperatorId.value;
        const token = elements.authToken.value;
        const reason = elements.authReason.value;

        const submitBtn = document.getElementById("modal-submit-btn");
        submitBtn.disabled = true;
        submitBtn.textContent = "Processing...";

        try {
            if (type === "approve" || type === "deny") {
                const res = await fetch(`/api/approvals/${targetId}/action`, {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "X-Tenant-ID": state.activeTenant
                    },
                    body: JSON.stringify({
                        action: type,
                        operator_id: operatorId,
                        token: token,
                        reason: reason
                    })
                });
                
                const data = await res.json();
                if (res.ok) {
                    alert(`Action completed successfully: ${data.detail || "Executed successfully"}`);
                    closeModal();
                    refreshData();
                } else {
                    alert(`Authentication/Authorization failed: ${data.detail}`);
                }
            } else if (type === "promote") {
                const res = await fetch("/api/allowlist/promote", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "X-Tenant-ID": state.activeTenant
                    },
                    body: JSON.stringify({
                        action_class: actionClass,
                        operator_id: operatorId,
                        token: token,
                        reason: reason,
                        owner: elements.authOwner.value.trim() || null,
                        expires_in: elements.modalExpiresIn.value || null,
                        // The provider the option was labelled with. Empty on a
                        // renewal, which keeps the entry's existing scope.
                        providers: elements.modalProvider.value ? [elements.modalProvider.value] : null
                    })
                });

                const data = await res.json();
                if (res.ok) {
                    alert(data.expires_at
                        ? `${actionClass} is autonomous until ${formatTime(data.expires_at)}. `
                          + `Owner: ${data.owner}. After that it requires human approval again `
                          + `unless renewed.`
                        : `${actionClass} promoted with no expiry — standing authority until `
                          + `someone demotes it. Owner: ${data.owner}.`);
                    closeModal();
                    refreshData();
                } else {
                    alert(`Failed to promote class: ${data.detail}`);
                }
            } else if (type === "reassign") {
                const res = await fetch("/api/allowlist/reassign", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "X-Tenant-ID": state.activeTenant
                    },
                    body: JSON.stringify({
                        action_class: actionClass,
                        operator_id: operatorId,
                        token: token,
                        reason: reason,
                        owner: elements.authOwner.value.trim()
                    })
                });

                const data = await res.json();
                if (res.ok) {
                    alert(data.status === "noop"
                        ? data.detail
                        : `${actionClass} is now owned by ${data.owner}. The promotion record is unchanged.`);
                    closeModal();
                    refreshData();
                } else {
                    alert(`Failed to reassign owner: ${data.detail}`);
                }
            } else if (type === "demote") {
                const res = await fetch("/api/allowlist/demote", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "X-Tenant-ID": state.activeTenant
                    },
                    body: JSON.stringify({
                        action_class: actionClass,
                        operator_id: operatorId,
                        token: token,
                        reason: reason
                    })
                });
                
                const data = await res.json();
                if (res.ok) {
                    alert(`Successfully demoted ${actionClass} from allowlist.`);
                    closeModal();
                    refreshData();
                } else {
                    alert(`Failed to demote class: ${data.detail}`);
                }
            }
        } catch (error) {
            console.error("Action error", error);
            alert("Network connection error.");
        } finally {
            submitBtn.disabled = false;
            submitBtn.textContent = "Submit Decision";
        }
    });

    // Promotion form submit
    elements.promoteForm.addEventListener("submit", (e) => {
        e.preventDefault();

        // Reuse OIDC/local prompt auth modal for promotion
        resetAuthModal();
        elements.modalActionTitle.textContent = "Authorize Class Promotion";
        elements.modalTargetId.value = "_governance";
        elements.modalActionType.value = "promote";
        elements.modalActionClass.value = elements.promoteClass.value;
        elements.modalExpiresIn.value = elements.promoteExpires.value;
        // Scope the promotion to the provider the operator was shown. Without
        // it, "block_ip (AWS)" would silently cover every provider's block_ip.
        const chosen = elements.promoteClass.selectedOptions[0];
        elements.modalProvider.value = (chosen && chosen.dataset.provider) || "";

        // Carry the owner through the auth step so it can be set by whoever is
        // promoting on someone else's behalf, and stays visible/editable there.
        elements.modalOwnerGroup.style.display = "flex";
        elements.modalOwnerLabel.textContent = "Owner";
        elements.modalOwnerNote.textContent =
            "Who gets asked to renew this entry. Leave blank to own it yourself.";
        elements.authOwner.value = elements.promoteOwner.value.trim();
        elements.authReason.value = elements.promoteReason.value; // Seed justification

        elements.authModal.classList.add("active");
    });

    // Live search
    elements.auditSearch.addEventListener("input", (e) => {
        renderFilteredAudit(e.target.value);
    });

    // Tenant selection listener
    elements.tenantSelect.addEventListener("change", (e) => {
        state.activeTenant = e.target.value;
        refreshData();
    });

    // Refresh orchestration
    const refreshData = () => {
        fetchStatus();
        fetchMetrics();
        
        if (state.activeTab === "overview") {
            fetchAudit();
        } else if (state.activeTab === "queue") {
            fetchApprovals();
            fetchOversight();
        } else if (state.activeTab === "audit") {
            fetchAudit();
        } else if (state.activeTab === "allowlist") {
            fetchAllowlist();
        }
    };

    // Auto-refresh stats every 8 seconds
    setInterval(() => {
        fetchStatus();
        fetchMetrics();
        if (state.activeTab === "overview" || state.activeTab === "queue") {
            refreshData();
        }
    }, 8000);

    // Initialize sidebar inputs from state
    if (elements.sidebarOperatorId && elements.sidebarOperatorToken) {
        elements.sidebarOperatorId.value = state.operatorId;
        elements.sidebarOperatorToken.value = state.token;
    }

    if (elements.sidebarAuthSave) {
        elements.sidebarAuthSave.addEventListener("click", () => {
            const opId = elements.sidebarOperatorId.value.trim();
            const tok = elements.sidebarOperatorToken.value.trim();
            sessionStorage.setItem("kronagent_operator_id", opId);
            sessionStorage.setItem("kronagent_operator_token", tok);
            state.operatorId = opId;
            state.token = tok;
            refreshData();
            alert("Credentials applied to session.");
        });
    }

    // Initial load
    refreshData();
});
