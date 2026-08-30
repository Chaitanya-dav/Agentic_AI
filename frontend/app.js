/**
 * Agentic AI Secure Execution System - Frontend Logic
 */

const API_BASE = "";

// State
let currentActions = [];
let activeApprovalAction = null;

// DOM Elements
const metricTotal = document.getElementById("metric-total");
const metricPending = document.getElementById("metric-pending");
const metricApproved = document.getElementById("metric-approved");
const metricExecuted = document.getElementById("metric-executed");
const metricRefused = document.getElementById("metric-refused");
const metricAttacks = document.getElementById("metric-attacks");

const actionsTableBody = document.getElementById("actions-table-body");
const agentTimeline = document.getElementById("agent-timeline");
const explanationBox = document.getElementById("explanation-text");
const matrixBadge = document.getElementById("matrix-aggregate-badge");

const nlPromptInput = document.getElementById("nl-prompt");
const creatorSelect = document.getElementById("creator-select");
const previewCanonical = document.getElementById("preview-canonical");
const previewHash = document.getElementById("preview-hash");
const previewRiskBadge = document.getElementById("preview-risk-badge");
const actionForm = document.getElementById("action-create-form");

const envRisk = document.getElementById("env-risk");
const envRecipient = document.getElementById("env-recipient");
const envAccount = document.getElementById("env-account");
const envTxLimit = document.getElementById("env-tx-limit");

const approvalModal = document.getElementById("approval-modal");
const modalActionSummary = document.getElementById("modal-action-summary");
const modalApproverSelect = document.getElementById("modal-approver-select");
const modalComment = document.getElementById("modal-comment");
const btnCloseModal = document.getElementById("btn-close-modal");
const btnModalApprove = document.getElementById("btn-modal-approve");
const btnModalReject = document.getElementById("btn-modal-reject");

// SHA-256 Client-Side Calculator for real-time live typing preview
async function sha256Client(message) {
    const msgBuffer = new TextEncoder().encode(message);
    const hashBuffer = await crypto.subtle.digest("SHA-256", msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
}

// Live typing preview handler
async function updateNlPreview() {
    const text = nlPromptInput.value.trim();
    const creator = creatorSelect.value || "alice";
    
    if (!text) {
        previewCanonical.textContent = "action_type=PAYMENT|amount=0.00|creator=" + creator + "|currency=INR|description=|recipient=";
        previewHash.textContent = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        previewRiskBadge.textContent = "Risk: Baseline";
        previewRiskBadge.className = "badge badge-info";
        return;
    }

    // Basic heuristic for client preview before server extraction
    let amt = "50000.00";
    let curr = "INR";
    let rec = "RAVI";
    let actType = "PAYMENT";

    if (text.includes("$") || text.toLowerCase().includes("usd")) curr = "USD";
    if (text.toLowerCase().includes("transfer") || text.toLowerCase().includes("wire")) actType = "TRANSFER";
    if (text.toLowerCase().includes("access") || text.toLowerCase().includes("admin")) actType = "ACCESS_GRANT";

    const amtMatch = text.match(/([0-9]{1,3}(?:,[0-9]{3})*(?:\.[0-9]+)?|[0-9]+(?:\.[0-9]+)?)/);
    if (amtMatch) {
        const num = parseFloat(amtMatch[1].replace(/,/g, ""));
        if (!isNaN(num)) amt = num.toFixed(2);
    }

    const toMatch = text.match(/\b(?:to|pay|for)\s+([A-Za-z0-9_\-]+)/i);
    if (toMatch && !["the", "a", "an"].includes(toMatch[1].toLowerCase())) {
        rec = toMatch[1].toUpperCase();
    }

    const canonical = `action_type=${actType}|amount=${amt}|creator=${creator.toLowerCase()}|currency=${curr}|description=${text}|recipient=${rec}`;
    const hash = await sha256Client(canonical);

    previewCanonical.textContent = canonical;
    previewHash.textContent = hash;

    const numAmt = parseFloat(amt);
    if (numAmt >= 25000 || actType === "ACCESS_GRANT") {
        previewRiskBadge.textContent = "Risk: HIGH (Requires Admin Four-Eyes)";
        previewRiskBadge.className = "badge badge-danger";
    } else if (numAmt >= 1000) {
        previewRiskBadge.textContent = "Risk: MEDIUM (Manager Approval)";
        previewRiskBadge.className = "badge badge-warning";
    } else {
        previewRiskBadge.textContent = "Risk: LOW";
        previewRiskBadge.className = "badge badge-info";
    }
}

// Preset template chips
document.querySelectorAll(".chip").forEach(chip => {
    chip.addEventListener("click", () => {
        nlPromptInput.value = chip.dataset.prompt;
        updateNlPreview();
    });
});

nlPromptInput.addEventListener("input", updateNlPreview);
creatorSelect.addEventListener("change", updateNlPreview);

// Fetch Metrics
async function fetchMetrics() {
    try {
        const res = await fetch(`${API_BASE}/api/metrics`);
        if (res.ok) {
            const data = await res.json();
            metricTotal.textContent = data.total_actions;
            metricPending.textContent = data.pending_approvals;
            metricApproved.textContent = data.approved_actions;
            metricExecuted.textContent = data.executed_actions;
            metricRefused.textContent = data.refused_actions;
            metricAttacks.textContent = data.attacks_blocked;
        }
    } catch (e) {
        console.error("Failed to load metrics", e);
    }
}

// Fetch Actions List
async function fetchActions() {
    try {
        const res = await fetch(`${API_BASE}/api/actions?limit=50`);
        if (res.ok) {
            currentActions = await res.json();
            renderActionsTable(currentActions);
        }
    } catch (e) {
        console.error("Failed to load actions", e);
    }
}

// Render Actions Table
function renderActionsTable(actions) {
    if (!actions || actions.length === 0) {
        actionsTableBody.innerHTML = `
            <tr>
                <td colspan="7" class="text-center text-muted">No actions recorded yet. Create an action or run a test scenario above.</td>
            </tr>`;
        return;
    }

    actionsTableBody.innerHTML = actions.map(act => {
        const approval = act.approval;
        let statusBadge = `<span class="badge badge-pending">PENDING</span>`;
        if (act.status === "APPROVED") statusBadge = `<span class="badge badge-approved">APPROVED</span>`;
        if (act.status === "EXECUTED") statusBadge = `<span class="badge badge-executed">EXECUTED</span>`;
        if (act.status === "REFUSED") statusBadge = `<span class="badge badge-refused">REFUSED</span>`;
        if (act.status === "REJECTED") statusBadge = `<span class="badge badge-rejected">REJECTED</span>`;

        const shortHash = act.payload_hash ? `${act.payload_hash.substring(0, 12)}...` : "N/A";
        const apprId = approval ? approval.approval_id : "None";

        let actionBtns = ``;
        if (act.status === "PENDING_APPROVAL" && approval && approval.status === "PENDING") {
            actionBtns = `
                <button class="btn btn-warning btn-sm" onclick="openApprovalModal(${act.id})">
                    ✍️ Review & Approve
                </button>
            `;
        } else if (act.status === "APPROVED" || (approval && approval.status === "APPROVED" && !approval.is_consumed)) {
            actionBtns = `
                <button class="btn btn-primary btn-sm" onclick="resumeAction(${act.id})">
                    🚀 Resume & Execute
                </button>
            `;
        } else {
            actionBtns = `
                <button class="btn btn-outline btn-sm" onclick="verifyActionOnly(${act.id})">
                    🔍 Inspect 9-Gates
                </button>
            `;
        }

        return `
            <tr>
                <td><strong>#${act.id}</strong></td>
                <td><span class="badge badge-info">${act.action_type}</span></td>
                <td>
                    <strong>${act.currency} ${parseFloat(act.amount).toLocaleString('en-IN', {minimumFractionDigits: 2})}</strong>
                    <div class="text-muted" style="font-size: 11px;">To: <code>${act.recipient}</code></div>
                </td>
                <td><code>${act.creator}</code></td>
                <td>
                    ${statusBadge}
                    <div class="text-muted" style="font-size: 10px; font-family: var(--font-mono);">${apprId}</div>
                </td>
                <td><code title="${act.payload_hash}">${shortHash}</code></td>
                <td>${actionBtns}</td>
            </tr>
        `;
    }).join("");
}

// Fetch Audit Timeline
async function fetchAuditTimeline() {
    try {
        const res = await fetch(`${API_BASE}/api/audit?limit=25`);
        if (res.ok) {
            const logs = await res.json();
            if (logs.length === 0) {
                agentTimeline.innerHTML = `<div class="timeline-empty text-muted">Awaiting system events...</div>`;
                return;
            }

            agentTimeline.innerHTML = logs.map(l => {
                const date = new Date(l.timestamp);
                const timeStr = date.toLocaleTimeString();
                let statusBadge = l.status === "PASS" ? "✅" : (l.status === "FAIL" ? "❌" : "ℹ️");

                return `
                    <div class="timeline-item stage-${l.stage}">
                        <div class="timeline-time">${timeStr}</div>
                        <div class="timeline-content">
                            <div class="timeline-agent">${statusBadge} ${l.agent_name} <span class="text-muted" style="font-size: 10px;">[${l.stage}]</span></div>
                            <div class="timeline-text">${escapeHtml(l.details)}</div>
                        </div>
                    </div>
                `;
            }).join("");
        }
    } catch (e) {
        console.error("Failed to load audit logs", e);
    }
}

// Fetch Environment State
async function fetchEnvironmentState() {
    try {
        const res = await fetch(`${API_BASE}/api/environment`);
        if (res.ok) {
            const env = await res.json();
            envRisk.value = env.risk_level;
            envRecipient.value = env.recipient_status;
            envAccount.value = env.account_status;
            envTxLimit.value = env.transaction_limit;
        }
    } catch (e) {
        console.error("Failed to load environment state", e);
    }
}

// Save Environment State
async function saveEnvironmentState() {
    try {
        const payload = {
            risk_level: envRisk.value,
            recipient_status: envRecipient.value,
            account_status: envAccount.value,
            transaction_limit: parseFloat(envTxLimit.value),
        };
        const res = await fetch(`${API_BASE}/api/environment`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
        });
        if (res.ok) {
            refreshAll();
            alert("Policy boundaries successfully updated!");
        }
    } catch (e) {
        alert("Failed to save environment settings: " + e.message);
    }
}

// Reset Environment State
async function resetEnvironmentState() {
    try {
        const res = await fetch(`${API_BASE}/api/environment/reset`, { method: "POST" });
        if (res.ok) {
            await fetchEnvironmentState();
            refreshAll();
        }
    } catch (e) {
        console.error("Failed to reset environment", e);
    }
}

// Create Action Form Submit
actionForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const prompt = nlPromptInput.value.trim();
    const creator = creatorSelect.value;
    if (!prompt) return;

    try {
        const res = await fetch(`${API_BASE}/api/actions`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ natural_language_prompt: prompt, creator: creator }),
        });

        if (res.ok) {
            nlPromptInput.value = "";
            updateNlPreview();
            refreshAll();
            document.getElementById("section-security-matrix").scrollIntoView({ behavior: "smooth" });
        } else {
            const err = await res.json();
            alert("Failed to create action: " + (err.detail || "Server error"));
        }
    } catch (e) {
        alert("Network error: " + e.message);
    }
});

// Modal Handlers
window.openApprovalModal = function(actionId) {
    const action = currentActions.find(a => a.id === actionId);
    if (!action || !action.approval) return;

    activeApprovalAction = action;
    modalActionSummary.innerHTML = `
        <div><strong>Action #${action.id}:</strong> ${action.action_type} of <strong>${action.currency} ${parseFloat(action.amount).toLocaleString('en-IN', {minimumFractionDigits: 2})}</strong> to <code>${action.recipient}</code></div>
        <div class="text-muted" style="font-size: 11px; margin-top: 4px;">Initiator: <code>${action.creator}</code> • Approval ID: <code>${action.approval.approval_id}</code></div>
    `;

    // Default select Bob (Manager)
    modalApproverSelect.value = "bob";
    approvalModal.style.display = "flex";
};

btnCloseModal.addEventListener("click", () => {
    approvalModal.style.display = "none";
    activeApprovalAction = null;
});

btnModalApprove.addEventListener("click", async () => {
    if (!activeApprovalAction) return;
    const approvalId = activeApprovalAction.approval.approval_id;
    const approver = modalApproverSelect.value;
    const comment = modalComment.value;

    try {
        const res = await fetch(`${API_BASE}/api/approvals/${approvalId}/approve`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ approver_id: approver, comment: comment }),
        });

        if (res.ok) {
            approvalModal.style.display = "none";
            refreshAll();
        } else {
            const err = await res.json();
            alert("Approval Refused: " + (err.detail || "Error"));
            approvalModal.style.display = "none";
            refreshAll();
        }
    } catch (e) {
        alert("Error approving action: " + e.message);
    }
});

btnModalReject.addEventListener("click", async () => {
    if (!activeApprovalAction) return;
    const approvalId = activeApprovalAction.approval.approval_id;
    const approver = modalApproverSelect.value;
    const comment = modalComment.value;

    try {
        const res = await fetch(`${API_BASE}/api/approvals/${approvalId}/reject`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ approver_id: approver, reason: comment }),
        });

        if (res.ok) {
            approvalModal.style.display = "none";
            refreshAll();
        } else {
            const err = await res.json();
            alert("Rejection Error: " + (err.detail || "Error"));
        }
    } catch (e) {
        alert("Error rejecting action: " + e.message);
    }
});

// Resume Action and Trigger Deterministic Verification
window.resumeAction = async function(actionId) {
    try {
        const res = await fetch(`${API_BASE}/api/actions/${actionId}/resume`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
        });

        if (res.ok) {
            const data = await res.json();
            renderVerificationMatrix(data.verification_result, data.message);
            refreshAll();
            document.getElementById("section-security-matrix").scrollIntoView({ behavior: "smooth" });
        } else {
            const err = await res.json();
            alert("Execution Error: " + (err.detail || "Error"));
        }
    } catch (e) {
        alert("Error resuming action: " + e.message);
    }
};

window.verifyActionOnly = async function(actionId) {
    try {
        const res = await fetch(`${API_BASE}/api/actions/${actionId}/verify`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
        });

        if (res.ok) {
            const data = await res.json();
            renderVerificationMatrix(data, data.explanation);
            document.getElementById("section-security-matrix").scrollIntoView({ behavior: "smooth" });
        }
    } catch (e) {
        alert("Error inspecting action: " + e.message);
    }
};

// Render 9-Point Matrix UI Cards
function renderVerificationMatrix(result, executionMsg = "") {
    if (!result || !result.checks) return;

    if (result.is_valid) {
        matrixBadge.textContent = "PASSED (9 / 9 GATES)";
        matrixBadge.className = "verification-badge pass";
    } else {
        matrixBadge.textContent = "REFUSED (VIOLATION DETECTED)";
        matrixBadge.className = "verification-badge refused";
    }

    const checkMapping = [
        "CHK_PAYLOAD_INTEGRITY",
        "CHK_CHECKPOINT_HASH",
        "CHK_TOKEN_PAYLOAD_HASH",
        "CHK_APPROVAL_ID_BINDING",
        "CHK_EXPIRY_VALIDATION",
        "CHK_FOUR_EYES_POLICY",
        "CHK_APPROVAL_STATUS",
        "CHK_NOT_CONSUMED",
        "CHK_DYNAMIC_POLICY_BOUNDARIES",
    ];

    checkMapping.forEach((code, idx) => {
        const checkIndex = idx + 1;
        const chk = result.checks.find(c => c.code === code) || {
            status: "FAIL",
            expected: "N/A",
            actual: "N/A",
            details: "Check not reached",
        };

        const card = document.getElementById(`card-chk-${checkIndex}`);
        const pill = document.getElementById(`chk-pill-${checkIndex}`);
        const meta = document.getElementById(`chk-meta-${checkIndex}`);

        if (chk.status === "PASS") {
            card.className = "matrix-card pass";
            pill.textContent = "PASS";
            pill.className = "check-status-pill pass";
        } else {
            card.className = "matrix-card fail";
            pill.textContent = "FAIL";
            pill.className = "check-status-pill fail";
        }

        meta.innerHTML = `<div>Expected: <code>${escapeHtml(chk.expected)}</code></div><div>Actual: <code>${escapeHtml(chk.actual)}</code></div><div class="text-muted" style="margin-top:2px;">${escapeHtml(chk.details)}</div>`;
    });

    let terminalOutput = `>>> [DECISION: ${result.decision}]\n`;
    terminalOutput += `>>> [SUMMARY: ${result.summary}]\n\n`;
    terminalOutput += `>>> [EXPLANATION]:\n${result.explanation}\n\n`;
    if (executionMsg) {
        terminalOutput += `>>> [EXECUTION LOG]:\n${executionMsg}\n`;
    }

    explanationBox.textContent = terminalOutput;
}

// Attack Simulation Laboratory Handlers
async function triggerAttack(endpoint, btnId) {
    const btn = document.getElementById(btnId);
    const originalText = btn.textContent;
    btn.textContent = "Executing...";
    btn.disabled = true;

    try {
        const res = await fetch(`${API_BASE}/api/attacks/${endpoint}`, { method: "POST" });
        if (res.ok) {
            const data = await res.json();
            renderVerificationMatrix(data.security_verification, data.explanation);
            refreshAll();
            document.getElementById("section-security-matrix").scrollIntoView({ behavior: "smooth" });
        } else {
            const err = await res.json();
            alert("Simulation failed: " + (err.detail || "Error"));
        }
    } catch (e) {
        alert("Error executing attack simulation: " + e.message);
    } finally {
        btn.textContent = originalText;
        btn.disabled = false;
    }
}

document.getElementById("btn-run-normal").addEventListener("click", () => triggerAttack("normal", "btn-run-normal"));
document.getElementById("btn-attack-tamper").addEventListener("click", () => triggerAttack("tamper", "btn-attack-tamper"));
document.getElementById("btn-attack-replay").addEventListener("click", () => triggerAttack("replay", "btn-attack-replay"));
document.getElementById("btn-attack-expiry").addEventListener("click", () => triggerAttack("expiry", "btn-attack-expiry"));
document.getElementById("btn-attack-self").addEventListener("click", () => triggerAttack("self-approval", "btn-attack-self"));
document.getElementById("btn-attack-world").addEventListener("click", () => triggerAttack("world-changed", "btn-attack-world"));

document.getElementById("btn-refresh-data").addEventListener("click", refreshAll);
document.getElementById("btn-reset-env").addEventListener("click", resetEnvironmentState);
document.getElementById("btn-save-env").addEventListener("click", saveEnvironmentState);

function refreshAll() {
    fetchMetrics();
    fetchActions();
    fetchAuditTimeline();
    fetchEnvironmentState();
}

function escapeHtml(text) {
    if (!text) return "";
    return text.toString()
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// Initial boot
refreshAll();
updateNlPreview();
setInterval(fetchMetrics, 10000);
setInterval(fetchAuditTimeline, 10000);
