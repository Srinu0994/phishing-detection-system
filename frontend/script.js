// API Base Configuration
// If you host the backend API separately (e.g., on Render or Heroku), replace the URL below:
const REMOTE_API_URL = "https://your-deployed-backend-url.onrender.com/api"; 

const API_BASE = (window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1" || window.location.hostname === "")
    ? "http://127.0.0.1:5000/api"
    : (window.location.origin.includes("github.io") ? REMOTE_API_URL : `${window.location.origin}/api`);

// DOM Elements
const scanForm = document.getElementById("scan-form");
const urlInput = document.getElementById("url-input");
const scanBtn = document.getElementById("scan-btn");
const btnText = scanBtn.querySelector(".btn-text");
const btnLoader = scanBtn.querySelector(".btn-loader");
const errorMessage = document.getElementById("error-message");

const scanLoading = document.getElementById("scan-loading");
const scanResults = document.getElementById("scan-results");

// Results Showcase Elements
const riskScoreValue = document.getElementById("risk-score-value");
const gaugeFillRing = document.getElementById("gauge-fill-ring");
const verdictBadge = document.getElementById("verdict-badge");
const scannedUrlText = document.getElementById("scanned-url-text");
const riskFactorsList = document.getElementById("risk-factors-list");

// Features grid elements
const featUrlLength = document.getElementById("feat-url-length");
const featDots = document.getElementById("feat-dots");
const featSubdomains = document.getElementById("feat-subdomains");
const featHttps = document.getElementById("feat-https");
const featSsl = document.getElementById("feat-ssl");
const featAge = document.getElementById("feat-age");
const featRedirects = document.getElementById("feat-redirects");
const featIp = document.getElementById("feat-ip");
const featShortener = document.getElementById("feat-shortener");
const featKeywords = document.getElementById("feat-keywords");

// History elements
const historyCounter = document.getElementById("history-counter");
const historyTableBody = document.getElementById("history-table-body");

// Initial Setup
document.addEventListener("DOMContentLoaded", () => {
    fetchHistory();
});

// Scan Form Submit Handler
scanForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const url = urlInput.value.trim();
    if (!url) return;

    hideError();
    showLoadingState();

    try {
        const response = await fetch(`${API_BASE}/analyze`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ url })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "Failed to analyze URL.");
        }

        renderResults(data);
        fetchHistory(); // Refresh history log list
    } catch (err) {
        showError(err.message);
        scanResults.classList.add("hidden");
    } finally {
        hideLoadingState();
    }
});

// Render Scan Results
function renderResults(data) {
    const verdict = data.prediction;
    const score = data.risk_score;
    
    // Update simple texts
    scannedUrlText.textContent = data.url;
    riskScoreValue.textContent = `${score}%`;
    
    // Update SVG Circular Gauge
    // Circumference = 2 * PI * r = 2 * 3.14159 * 50 = 314.159
    const circumference = 314.159;
    const offset = circumference - (score / 100) * circumference;
    gaugeFillRing.style.strokeDashoffset = offset;
    
    // Customize gauge color gradient and glow shadow depending on severity
    if (verdict === "legitimate") {
        gaugeFillRing.style.stroke = "url(#gauge-grad-safe)";
        gaugeFillRing.style.setProperty('--glow-color', 'rgba(16, 185, 129, 0.4)');
        verdictBadge.textContent = "Safe Website";
        verdictBadge.className = "verdict-banner safe";
    } else if (verdict === "suspicious") {
        gaugeFillRing.style.stroke = "url(#gauge-grad-suspicious)";
        gaugeFillRing.style.setProperty('--glow-color', 'rgba(245, 158, 11, 0.4)');
        verdictBadge.textContent = "Suspicious Alert";
        verdictBadge.className = "verdict-banner suspicious";
    } else {
        gaugeFillRing.style.stroke = "url(#gauge-grad-danger)";
        gaugeFillRing.style.setProperty('--glow-color', 'rgba(239, 68, 68, 0.4)');
        verdictBadge.textContent = "Phishing Threat";
        verdictBadge.className = "verdict-banner phishing";
    }

    // Populate Risk Factors Checklist
    riskFactorsList.innerHTML = "";
    data.risk_factors.forEach(factor => {
        const li = document.createElement("li");
        li.textContent = factor;
        
        // Add styling indicator class depending on target risk class
        if (verdict === "legitimate") {
            li.className = "safe-info";
        } else if (verdict === "suspicious") {
            li.className = "warning";
        } else {
            li.className = "danger";
        }
        riskFactorsList.appendChild(li);
    });

    // Populate Extracted Feature Items Grid
    const f = data.features;
    featUrlLength.textContent = f.url_length;
    featDots.textContent = f.num_dots;
    featSubdomains.textContent = f.num_subdomains;
    
    featHttps.textContent = f.is_https === 1 ? "Yes (Secure)" : "No (Insecure)";
    featHttps.className = f.is_https === 1 ? "feature-value" : "feature-value warning-text";
    
    featSsl.textContent = f.ssl_valid === 1 ? "Verified Valid" : (f.is_https === 1 ? "Invalid / Untrusted" : "Not Applicable");
    if (f.ssl_valid === 1) {
        featSsl.className = "feature-value safe-text";
    } else if (f.is_https === 1) {
        featSsl.className = "feature-value danger-text";
    } else {
        featSsl.className = "feature-value";
    }

    featAge.textContent = f.domain_age_days === -1 ? "Unknown" : `${f.domain_age_days} Days`;
    featAge.className = (f.domain_age_days != -1 && f.domain_age_days < 90) ? "feature-value warning-text" : "feature-value";

    featRedirects.textContent = f.num_redirects;
    featRedirects.className = f.num_redirects > 2 ? "feature-value danger-text" : "feature-value";

    featIp.textContent = f.use_ip === 1 ? "Yes (Threat)" : "No";
    featIp.className = f.use_ip === 1 ? "feature-value danger-text" : "feature-value";

    featShortener.textContent = f.is_shortened === 1 ? "Yes (Warning)" : "No";
    featShortener.className = f.is_shortened === 1 ? "feature-value warning-text" : "feature-value";

    featKeywords.textContent = f.num_suspicious_keywords;
    featKeywords.className = f.num_suspicious_keywords > 0 ? "feature-value warning-text" : "feature-value";

    // Reveal Results Block
    scanResults.classList.remove("hidden");
}

// Fetch Scan Logs / History List
async function fetchHistory() {
    try {
        const response = await fetch(`${API_BASE}/history`);
        if (!response.ok) throw new Error("Could not fetch log history.");
        const historyData = await response.json();
        
        // Update total counter
        historyCounter.textContent = `${historyData.length} Scan${historyData.length !== 1 ? 's' : ''} Recorded`;
        
        renderHistoryTable(historyData);
    } catch (err) {
        console.error("History loading error:", err);
    }
}

// Render History Table List
function renderHistoryTable(list) {
    historyTableBody.innerHTML = "";

    if (list.length === 0) {
        historyTableBody.innerHTML = `
            <tr class="empty-state">
                <td colspan="5" style="text-align: center; color: var(--color-text-muted); padding: 2rem;">
                    No scan logs found. Paste a URL above to perform a scan.
                </td>
            </tr>
        `;
        return;
    }

    list.forEach(item => {
        const tr = document.createElement("tr");
        
        // Format Timestamp nicely
        const date = new Date(item.timestamp);
        const formattedDate = date.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });

        // Slice long URLs to fit table layout beautifully
        const displayUrl = item.url.length > 60 ? `${item.url.slice(0, 57)}...` : item.url;
        
        tr.innerHTML = `
            <td class="td-url" title="${item.url}">${escapeHtml(displayUrl)}</td>
            <td><span class="history-badge ${item.prediction}">${item.prediction}</span></td>
            <td><span class="history-risk ${item.prediction}">${item.risk_score}%</span></td>
            <td style="color: var(--color-text-muted); font-size: 0.85rem;">${formattedDate}</td>
            <td class="history-actions">
                <button class="btn-icon rescan-action" title="Scan again" data-url="${escapeHtml(item.url)}">🔄</button>
                <button class="btn-icon delete-action" title="Delete scan record" data-id="${item.id}">🗑️</button>
            </td>
        `;
        
        historyTableBody.appendChild(tr);
    });

    // Add Action Button Event Handlers in list
    document.querySelectorAll(".rescan-action").forEach(btn => {
        btn.addEventListener("click", () => {
            const url = btn.getAttribute("data-url");
            urlInput.value = url;
            scanForm.dispatchEvent(new Event("submit"));
            // Smooth scroll to top search bar
            window.scrollTo({ top: 0, behavior: 'smooth' });
        });
    });

    document.querySelectorAll(".delete-action").forEach(btn => {
        btn.addEventListener("click", async () => {
            const id = btn.getAttribute("data-id");
            if (confirm("Are you sure you want to delete this scan from history?")) {
                await deleteHistoryItem(id);
            }
        });
    });
}

// Delete Log Record
async function deleteHistoryItem(id) {
    try {
        const response = await fetch(`${API_BASE}/history/${id}`, {
            method: "DELETE"
        });
        if (!response.ok) throw new Error("Failed to delete record.");
        fetchHistory(); // Refresh history panel
    } catch (err) {
        alert(err.message);
    }
}

// Utility Loader toggles
function showLoadingState() {
    scanBtn.disabled = true;
    btnText.classList.add("hidden");
    btnLoader.classList.remove("hidden");
    scanLoading.classList.remove("hidden");
    scanResults.classList.add("hidden");
}

function hideLoadingState() {
    scanBtn.disabled = false;
    btnText.classList.remove("hidden");
    btnLoader.classList.add("hidden");
    scanLoading.classList.add("hidden");
}

function showError(msg) {
    errorMessage.textContent = msg;
    errorMessage.classList.remove("hidden");
}

function hideError() {
    errorMessage.textContent = "";
    errorMessage.classList.add("hidden");
}

// HTML Escaper to prevent injection
function escapeHtml(text) {
    return text
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}
