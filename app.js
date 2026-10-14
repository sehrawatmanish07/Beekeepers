// Paste the backend (Render) URL here, with no trailing slash
const BACKEND_URL = "https://honeypot-backend-766u.onrender.com";

/**
 * Honeypot Attack Console - Client Application
 * Static, framework-free dashboard for security operations telemetry.
 * All backend attacker data is safely rendered using textContent / DOM APIs (no innerHTML).
 */

(function () {
  "use strict";

  // Sanitize and normalize API URL
  const RAW_URL = typeof BACKEND_URL === "string" ? BACKEND_URL.trim() : "";
  const IS_PLACEHOLDER = !RAW_URL || RAW_URL === "PLACEHOLDER";
  const API_BASE = RAW_URL.replace(/\/+$/, "");

  // Storage Keys
  const TOKEN_KEY = "dashboard_token";
  const KIKO_HIDDEN_KEY = "kiko_mascot_hidden";

  // Global State
  let pollIntervalId = null;
  let countdownTimerId = null;
  let inFlightRequest = false;
  let secondsRemaining = 15;
  let lastDashboardData = null;
  let currentSortColumn = "risk_score";
  let currentSortAsc = false;
  let sessionsDisplayLimit = 100;
  let knownSessionIds = new Set();
  let expandedSessionIds = new Set();
  let animatedSessionIds = new Set();
  let isKikoSad = false;
  let kikoBubbleTimer = null;

  // Chart References
  let timelineChart = null;
  let riskChart = null;
  let topIpsChart = null;
  let topCommandsChart = null;

  // DOM Elements
  const el = {
    connectionBanner: document.getElementById("connection-banner"),
    loginView: document.getElementById("login-view"),
    dashboardView: document.getElementById("dashboard-view"),
    loginForm: document.getElementById("login-form"),
    usernameInput: document.getElementById("username"),
    passwordInput: document.getElementById("password"),
    loginBtn: document.getElementById("login-btn"),
    loginBtnSpinner: document.getElementById("login-btn-spinner"),
    loginBtnText: document.getElementById("login-btn-text"),
    loginError: document.getElementById("login-error"),
    loginInfo: document.getElementById("login-info"),
    backendWarning: document.getElementById("backend-warning"),
    logoutBtn: document.getElementById("logout-btn"),
    toggleMascotBtn: document.getElementById("toggle-mascot-btn"),
    toggleMascotLabel: document.getElementById("toggle-mascot-label"),
    countdownProgress: document.getElementById("countdown-progress"),
    countdownText: document.getElementById("countdown-text"),

    // Tabs
    tabLinks: {
      overview: document.getElementById("tab-link-overview"),
      live: document.getElementById("tab-link-live"),
      analysis: document.getElementById("tab-link-analysis")
    },
    tabPanes: {
      overview: document.getElementById("pane-overview"),
      live: document.getElementById("pane-live"),
      analysis: document.getElementById("pane-analysis")
    },

    // Overview Stats
    statSessions: document.getElementById("stat-total-sessions"),
    statAttacks: document.getElementById("stat-total-attacks"),
    statIps: document.getElementById("stat-unique-ips"),
    statCritical: document.getElementById("stat-critical-sessions"),

    // Overview Charts
    timelineCanvas: document.getElementById("timeline-chart"),
    timelineEmpty: document.getElementById("timeline-empty"),
    riskCanvas: document.getElementById("risk-chart"),
    riskEmpty: document.getElementById("risk-empty"),

    // Live Threats
    feedList: document.getElementById("live-feed-list"),
    feedEmpty: document.getElementById("feed-empty"),
    mapMarkersLayer: document.getElementById("map-markers-layer"),
    mapOverlay: document.getElementById("map-message-overlay"),
    mapTooltip: document.getElementById("map-tooltip"),
    tooltipIp: document.getElementById("tooltip-ip"),
    tooltipRisk: document.getElementById("tooltip-risk"),

    // Analysis
    topIpsCanvas: document.getElementById("top-ips-chart"),
    topIpsEmpty: document.getElementById("top-ips-empty"),
    topCommandsCanvas: document.getElementById("top-commands-chart"),
    topCommandsEmpty: document.getElementById("top-commands-empty"),
    sessionsTable: document.getElementById("sessions-table"),
    sessionsTbody: document.getElementById("sessions-tbody"),
    tableEmpty: document.getElementById("table-empty"),
    tableRecordCount: document.getElementById("table-record-count"),
    showMoreBtn: document.getElementById("show-more-btn"),

    // Mascot
    kikoLoginStage: document.getElementById("kiko-login-slot"),
    kikoLoginAvatar: document.getElementById("kiko-login-avatar"),
    kikoLoginBubble: document.getElementById("kiko-login-bubble"),
    kikoLoginBubbleText: document.getElementById("kiko-login-bubble-text"),
    kikoDashStage: document.getElementById("kiko-dashboard-slot"),
    kikoDashAvatar: document.getElementById("kiko-dash-avatar"),
    kikoDashBubble: document.getElementById("kiko-dash-bubble"),
    kikoDashBubbleText: document.getElementById("kiko-dash-bubble-text")
  };

  /* ==========================================================================
     KIKO MASCOT SVG DEFINITION & EYE TRACKING
     ========================================================================== */
  function createKikoSvg(idPrefix) {
    const ns = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(ns, "svg");
    svg.setAttribute("viewBox", "0 0 100 100");
    svg.setAttribute("width", "100%");
    svg.setAttribute("height", "100%");
    svg.setAttribute("class", "kiko-floating");
    svg.setAttribute("aria-hidden", "true");

    svg.innerHTML = `
      <defs>
        <linearGradient id="${idPrefix}-iris" x1="0%" y1="0%" x2="0%" y2="100%">
          <stop offset="0%" stop-color="#2dd4bf" />
          <stop offset="100%" stop-color="#0f766e" />
        </linearGradient>
        <radialGradient id="${idPrefix}-blush" cx="50%" cy="50%" r="50%">
          <stop offset="0%" stop-color="#fb7185" stop-opacity="0.5" />
          <stop offset="100%" stop-color="#fb7185" stop-opacity="0" />
        </radialGradient>
      </defs>

      <!-- Headset Back Band -->
      <path d="M 22 52 C 20 25, 80 25, 78 52" fill="none" stroke="#1f2d46" stroke-width="5" stroke-linecap="round"/>

      <!-- Body / Hoodie -->
      <path d="M 28 85 C 28 72, 72 72, 72 85 L 76 100 L 24 100 Z" fill="#141f36" />
      <path d="M 40 76 L 46 86 M 60 76 L 54 86" stroke="#2dd4bf" stroke-width="2" stroke-linecap="round" />
      <!-- Shield Emblem on Hoodie -->
      <path d="M 50 82 L 56 85 L 56 91 C 56 94, 50 97, 50 97 C 50 97, 44 94, 44 91 L 44 85 Z" fill="#0d9488" stroke="#2dd4bf" stroke-width="1.2" />

      <!-- Head & Skin -->
      <circle cx="50" cy="52" r="26" fill="#ffe2d6" />
      
      <!-- Cheeks Blush -->
      <circle cx="34" cy="58" r="5" fill="url(#${idPrefix}-blush)" />
      <circle cx="66" cy="58" r="5" fill="url(#${idPrefix}-blush)" />

      <!-- Mouth -->
      <path id="${idPrefix}-mouth" class="kiko-mouth-path" d="M 45 64 Q 50 69 55 64" fill="none" stroke="#be123c" stroke-width="2" stroke-linecap="round" />

      <!-- Eyes (Blinking group) -->
      <g id="${idPrefix}-eyes-group" class="kiko-eyes">
        <!-- Left Eye -->
        <g id="${idPrefix}-left-eye">
          <ellipse cx="38" cy="50" rx="7.5" ry="9" fill="#ffffff" stroke="#1a253b" stroke-width="1.2" />
          <ellipse cx="38" cy="50" rx="5.2" ry="7" fill="url(#${idPrefix}-iris)" />
          <!-- Pupil Left -->
          <circle id="${idPrefix}-pupil-l" cx="38" cy="50" r="3.2" fill="#042f2e" />
          <!-- Glint Highlights -->
          <circle cx="36" cy="47" r="2" fill="#ffffff" />
          <circle cx="40" cy="53" r="1.1" fill="#ffffff" />
        </g>

        <!-- Right Eye -->
        <g id="${idPrefix}-right-eye">
          <ellipse cx="62" cy="50" rx="7.5" ry="9" fill="#ffffff" stroke="#1a253b" stroke-width="1.2" />
          <ellipse cx="62" cy="50" rx="5.2" ry="7" fill="url(#${idPrefix}-iris)" />
          <!-- Pupil Right -->
          <circle id="${idPrefix}-pupil-r" cx="62" cy="50" r="3.2" fill="#042f2e" />
          <!-- Glint Highlights -->
          <circle cx="60" cy="47" r="2" fill="#ffffff" />
          <circle cx="64" cy="53" r="1.1" fill="#ffffff" />
        </g>
      </g>

      <!-- Hair Bob (Navy) -->
      <g class="kiko-hair">
        <!-- Hair Sides -->
        <path d="M 24 50 C 22 66, 32 72, 33 65 C 33 55, 30 42, 36 32 C 42 26, 58 26, 64 32 C 70 42, 67 55, 67 65 C 68 72, 78 66, 76 50 C 76 30, 24 30, 24 50 Z" fill="#121b2d" />
        <!-- Bangs -->
        <path d="M 28 40 Q 38 46 45 38 Q 52 46 62 38 Q 70 45 72 40 C 65 30, 35 30, 28 40 Z" fill="#16233a" />
      </g>

      <!-- Hair Antenna Strand (Wiggles) -->
      <g class="kiko-antenna">
        <path d="M 50 26 C 50 14, 58 12, 60 5" fill="none" stroke="#16233a" stroke-width="2.6" stroke-linecap="round" />
        <circle cx="60" cy="5" r="2.2" fill="#2dd4bf" />
      </g>

      <!-- Teal Headset Earcups and Boom Mic -->
      <g class="kiko-headset">
        <rect x="20" y="44" width="7" height="15" rx="3.5" fill="#2dd4bf" stroke="#0f766e" stroke-width="1.5" />
        <rect x="73" y="44" width="7" height="15" rx="3.5" fill="#2dd4bf" stroke="#0f766e" stroke-width="1.5" />
        <!-- Boom Mic -->
        <path d="M 24 57 C 24 68, 38 72, 44 71" fill="none" stroke="#1f2d46" stroke-width="2.2" stroke-linecap="round" />
        <circle cx="44" cy="71" r="2.6" fill="#2dd4bf" />
      </g>
    `;
    return svg;
  }

  function initMascot() {
    if (el.kikoLoginAvatar) {
      el.kikoLoginAvatar.appendChild(createKikoSvg("kiko-login"));
    }
    if (el.kikoDashAvatar) {
      el.kikoDashAvatar.appendChild(createKikoSvg("kiko-dash"));
    }

    // Load saved hide preference
    try {
      const isHidden = localStorage.getItem(KIKO_HIDDEN_KEY) === "true";
      setMascotHidden(isHidden);
    } catch (e) {
      // Storage unavailable or disabled
    }

    // Toggle button handler
    if (el.toggleMascotBtn) {
      el.toggleMascotBtn.addEventListener("click", () => {
        const currentlyHidden = el.kikoDashStage.classList.contains("hidden");
        const nextState = !currentlyHidden;
        setMascotHidden(nextState);
        try {
          localStorage.setItem(KIKO_HIDDEN_KEY, nextState ? "true" : "false");
        } catch (e) {}
      });
    }

    // Mouse tracking for pupils
    window.addEventListener("mousemove", (e) => {
      trackPupils(e.clientX, e.clientY);
    });

    // Hover on Mascot pops bubble immediately
    [el.kikoLoginAvatar, el.kikoDashAvatar].forEach((avatar) => {
      if (avatar) {
        avatar.addEventListener("mouseenter", () => {
          showKikoBubble(getCurrentMascotQuote());
        });
      }
    });

    // Routine speech bubble popping every ~14 seconds for ~4.5 seconds
    startKikoRoutine();
  }

  function setMascotHidden(hidden) {
    if (hidden) {
      el.kikoDashStage.classList.add("hidden");
      if (el.toggleMascotLabel) el.toggleMascotLabel.textContent = "Show Kiko";
    } else {
      el.kikoDashStage.classList.remove("hidden");
      if (el.toggleMascotLabel) el.toggleMascotLabel.textContent = "Hide Kiko";
    }
  }

  function trackPupils(mouseX, mouseY) {
    // Only track if motion is permitted
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;

    const pupils = document.querySelectorAll(
      "#kiko-login-pupil-l, #kiko-login-pupil-r, #kiko-dash-pupil-l, #kiko-dash-pupil-r"
    );

    pupils.forEach((pupil) => {
      const rect = pupil.getBoundingClientRect();
      if (!rect.width) return;
      const eyeX = rect.left + rect.width / 2;
      const eyeY = rect.top + rect.height / 2;
      const dx = mouseX - eyeX;
      const dy = mouseY - eyeY;
      const dist = Math.hypot(dx, dy) || 1;
      const maxDelta = 2.4;
      const factor = Math.min(maxDelta, dist / 80);
      const moveX = (dx / dist) * factor;
      const moveY = (dy / dist) * factor;
      pupil.setAttribute("transform", `translate(${moveX.toFixed(2)}, ${moveY.toFixed(2)})`);
    });
  }

  function setKikoMouth(sad) {
    isKikoSad = sad;
    const mouths = document.querySelectorAll(".kiko-mouth-path");
    mouths.forEach((m) => {
      if (sad) {
        // Sad inverted arc
        m.setAttribute("d", "M 45 68 Q 50 62 55 68");
      } else {
        // Happy smiling arc
        m.setAttribute("d", "M 45 64 Q 50 69 55 64");
      }
    });
  }

  function showKikoBubble(text, duration = 4500) {
    if (el.kikoLoginBubbleText) el.kikoLoginBubbleText.textContent = text;
    if (el.kikoDashBubbleText) el.kikoDashBubbleText.textContent = text;

    if (el.kikoLoginBubble) el.kikoLoginBubble.style.opacity = "1";
    if (el.kikoDashBubble) el.kikoDashBubble.style.opacity = "1";

    clearTimeout(kikoBubbleTimer);
    kikoBubbleTimer = setTimeout(() => {
      if (el.kikoLoginBubble) el.kikoLoginBubble.style.opacity = "0";
      if (el.kikoDashBubble) el.kikoDashBubble.style.opacity = "0";
    }, duration);
  }

  function getCurrentMascotQuote() {
    if (isLoginViewActive()) {
      return isKikoSad
        ? "Hmm, that did not work. Try again?"
        : "Hi there! Show me your credentials~";
    }

    const hash = window.location.hash || "#overview";
    if (hash === "#live") {
      return "Eyes on the feed. Attackers are heading for the honeypot!";
    } else if (hash === "#analysis") {
      return "Pick a session row to watch the replay.";
    }
    return "Welcome back, analyst! Here is your attack summary.";
  }

  function startKikoRoutine() {
    setInterval(() => {
      showKikoBubble(getCurrentMascotQuote());
    }, 14000);
  }

  function isLoginViewActive() {
    return !el.loginView.classList.contains("hidden");
  }

  /* ==========================================================================
     AUTHENTICATION & LOGIN VIEW
     ========================================================================== */
  function initAuth() {
    // Check if backend URL is configured
    if (IS_PLACEHOLDER) {
      el.backendWarning.classList.remove("hidden");
      el.loginBtn.disabled = true;
      el.usernameInput.disabled = true;
      el.passwordInput.disabled = true;
      return;
    }

    // Auto-login if token already in sessionStorage
    const existingToken = sessionStorage.getItem(TOKEN_KEY);
    if (existingToken) {
      showDashboardView();
      return;
    }

    // Setup form listener
    el.loginForm.addEventListener("submit", handleLoginSubmit);
  }

  async function handleLoginSubmit(e) {
    e.preventDefault();
    if (inFlightRequest || IS_PLACEHOLDER) return;

    hideLoginAlerts();
    setKikoMouth(false);

    const username = el.usernameInput.value.trim();
    const password = el.passwordInput.value;

    if (!username || !password) {
      showLoginError("Please enter both username and password.");
      return;
    }

    // Disable button and prevent double submit
    inFlightRequest = true;
    el.loginBtn.disabled = true;
    el.loginBtnSpinner.classList.remove("hidden");
    el.loginBtnText.textContent = "Connecting...";

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 60000);

    // After 5s, notify user about cold server wakeup
    const wakeupTimer = setTimeout(() => {
      if (inFlightRequest) {
        showLoginInfo("The server may be waking up, this can take up to a minute");
      }
    }, 5000);

    try {
      const response = await fetch(`${API_BASE}/api/login`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ username, password }),
        signal: controller.signal
      });

      clearTimeout(timeoutId);
      clearTimeout(wakeupTimer);

      if (response.status === 200) {
        const data = await response.json().catch(() => ({}));
        const token = data.token || data.access_token;
        if (token) {
          sessionStorage.setItem(TOKEN_KEY, token);
          el.passwordInput.value = "";
          showDashboardView();
        } else {
          showLoginError("Unexpected response from server");
        }
      } else if (response.status === 401) {
        showLoginError("Invalid credentials");
        el.passwordInput.value = "";
        setKikoMouth(true);
        showKikoBubble("Hmm, that did not work. Try again?");
      } else {
        showLoginError("Cannot reach the server. Please try again.");
      }
    } catch (err) {
      clearTimeout(timeoutId);
      clearTimeout(wakeupTimer);
      showLoginError("Cannot reach the server. Please try again.");
    } finally {
      inFlightRequest = false;
      el.loginBtn.disabled = false;
      el.loginBtnSpinner.classList.add("hidden");
      el.loginBtnText.textContent = "Log in";
    }
  }

  function showLoginError(msg) {
    el.loginError.textContent = msg;
    el.loginError.classList.remove("hidden");
  }

  function showLoginInfo(msg) {
    el.loginInfo.textContent = msg;
    el.loginInfo.classList.remove("hidden");
  }

  function hideLoginAlerts() {
    el.loginError.classList.add("hidden");
    el.loginError.textContent = "";
    el.loginInfo.classList.add("hidden");
    el.loginInfo.textContent = "";
  }

  function handleLogout(message) {
    sessionStorage.removeItem(TOKEN_KEY);
    stopPolling();
    lastDashboardData = null;

    el.dashboardView.classList.add("hidden");
    el.loginView.classList.remove("hidden");
    el.connectionBanner.classList.add("hidden");

    hideLoginAlerts();
    if (message) {
      showLoginError(message);
    }
    setKikoMouth(false);
    showKikoBubble("Hi there! Show me your credentials~");
  }

  /* ==========================================================================
     DASHBOARD VIEW & NAVIGATION
     ========================================================================== */
  function showDashboardView() {
    el.loginView.classList.add("hidden");
    el.dashboardView.classList.remove("hidden");
    hideLoginAlerts();

    // Reset mascot speech
    setKikoMouth(false);
    showKikoBubble(getCurrentMascotQuote());

    // Sync tab with URL hash
    handleHashRouting();

    // Trigger initial data load
    fetchDashboardData(true);

    // Start auto-refresh polling loop
    startPolling();
  }

  function initNavigation() {
    window.addEventListener("hashchange", handleHashRouting);

    if (el.logoutBtn) {
      el.logoutBtn.addEventListener("click", () => handleLogout());
    }

    // Sessions table sorting
    const sortHeaders = el.sessionsTable.querySelectorAll("th.sortable");
    sortHeaders.forEach((th) => {
      th.addEventListener("click", () => {
        const col = th.getAttribute("data-sort");
        if (currentSortColumn === col) {
          currentSortAsc = !currentSortAsc;
        } else {
          currentSortColumn = col;
          currentSortAsc = false; // Default desc
        }
        updateSortHeaderIndicators();
        if (lastDashboardData && Array.isArray(lastDashboardData.sessions)) {
          renderSessionsTable(lastDashboardData.sessions);
        }
      });
      // Keyboard accessible sorting
      th.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          th.click();
        }
      });
    });

    // Show more sessions button
    if (el.showMoreBtn) {
      el.showMoreBtn.addEventListener("click", () => {
        sessionsDisplayLimit += 100;
        if (lastDashboardData && Array.isArray(lastDashboardData.sessions)) {
          renderSessionsTable(lastDashboardData.sessions);
        }
      });
    }
  }

  function handleHashRouting() {
    let hash = (window.location.hash || "").toLowerCase();
    if (!hash || (hash !== "#overview" && hash !== "#live" && hash !== "#analysis")) {
      hash = "#overview";
      if (window.location.hash !== hash) {
        window.history.replaceState(null, "", hash);
      }
    }

    const activeTab = hash.substring(1);

    // Update active tab buttons
    Object.keys(el.tabLinks).forEach((key) => {
      const link = el.tabLinks[key];
      const isSelected = key === activeTab;
      link.classList.toggle("active", isSelected);
      link.setAttribute("aria-selected", isSelected ? "true" : "false");
    });

    // Update tab panes
    Object.keys(el.tabPanes).forEach((key) => {
      const pane = el.tabPanes[key];
      pane.classList.toggle("active", key === activeTab);
    });

    // Update Kiko quote for this tab
    showKikoBubble(getCurrentMascotQuote(), 3000);
  }

  /* ==========================================================================
     AUTO-REFRESH POLLING & COUNTDOWN RING
     ========================================================================== */
  function startPolling() {
    stopPolling();
    secondsRemaining = 15;
    updateCountdownUI(15);

    countdownTimerId = setInterval(() => {
      secondsRemaining -= 1;
      if (secondsRemaining <= 0) {
        secondsRemaining = 15;
        updateCountdownUI(15);
        fetchDashboardData(false);
      } else {
        updateCountdownUI(secondsRemaining);
      }
    }, 1000);
  }

  function stopPolling() {
    clearInterval(pollIntervalId);
    clearInterval(countdownTimerId);
    pollIntervalId = null;
    countdownTimerId = null;
  }

  function updateCountdownUI(sec) {
    if (el.countdownText) {
      el.countdownText.textContent = `${sec}s`;
    }
    if (el.countdownProgress) {
      // 100 is full circumference dashoffset
      const offset = (1 - sec / 15) * 100;
      el.countdownProgress.setAttribute("stroke-dashoffset", offset.toFixed(1));
    }
  }

  /* ==========================================================================
     DATA FETCHING & ERROR HANDLING
     ========================================================================== */
  async function fetchDashboardData(isFirstLoad = false) {
    if (inFlightRequest) return;

    const token = sessionStorage.getItem(TOKEN_KEY);
    if (!token) {
      handleLogout("Session expired, please log in again.");
      return;
    }

    inFlightRequest = true;

    try {
      const res = await fetch(`${API_BASE}/api/dashboard`, {
        method: "GET",
        headers: {
          "Authorization": `Bearer ${token}`
        }
      });

      if (res.status === 401) {
        handleLogout("Session expired, please log in again.");
        return;
      }

      if (!res.ok) {
        throw new Error(`Server returned ${res.status}`);
      }

      const data = await res.json();
      lastDashboardData = data;
      el.connectionBanner.classList.add("hidden");

      renderDashboard(data);
    } catch (err) {
      // Keep showing last data, show small banner "Connection lost, retrying..."
      el.connectionBanner.classList.remove("hidden");
    } finally {
      inFlightRequest = false;
    }
  }

  /* ==========================================================================
     DASHBOARD RENDERING (SAFE & ESCAPED)
     ========================================================================== */
  function renderDashboard(data) {
    if (!data || typeof data !== "object") return;

    renderStats(data.stats);
    renderTimelineChart(data.timeline);
    renderRiskDonutChart(data.risk_distribution);
    renderLiveFeed(data.sessions);
    renderAttackMap(data.sessions);
    renderTopIpsChart(data.top_ips);
    renderTopCommandsChart(data.top_commands);
    renderSessionsTable(data.sessions);
  }

  /* 1. Stat Cards Animated Counters */
  function renderStats(stats = {}) {
    const totalSessions = typeof stats.total_sessions === "number" ? stats.total_sessions : 0;
    const totalAttacks = typeof stats.total_attacks === "number" ? stats.total_attacks : 0;
    const uniqueIps = typeof stats.unique_ips === "number" ? stats.unique_ips : 0;
    const criticalSessions = typeof stats.critical_sessions === "number" ? stats.critical_sessions : 0;

    animateCounter(el.statSessions, totalSessions);
    animateCounter(el.statAttacks, totalAttacks);
    animateCounter(el.statIps, uniqueIps);
    animateCounter(el.statCritical, criticalSessions);
  }

  function animateCounter(domElement, targetValue) {
    if (!domElement) return;

    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      domElement.textContent = Number(targetValue).toLocaleString();
      return;
    }

    const currentText = domElement.textContent.replace(/[^0-9]/g, "");
    const startValue = currentText ? parseInt(currentText, 10) : 0;
    const endValue = Number(targetValue) || 0;

    if (startValue === endValue && domElement.textContent !== "—") return;

    const duration = 750;
    const startTime = performance.now();

    function updateCount(now) {
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      // easeOutExpo
      const ease = progress === 1 ? 1 : 1 - Math.pow(2, -10 * progress);
      const val = Math.round(startValue + (endValue - startValue) * ease);
      domElement.textContent = val.toLocaleString();

      if (progress < 1) {
        requestAnimationFrame(updateCount);
      } else {
        domElement.textContent = endValue.toLocaleString();
      }
    }

    requestAnimationFrame(updateCount);
  }

  /* 2. Timeline Line/Area Chart */
  function renderTimelineChart(timeline) {
    const hasData = Array.isArray(timeline) && timeline.length > 0;

    if (!hasData) {
      el.timelineEmpty.classList.remove("hidden");
      if (timelineChart) {
        timelineChart.destroy();
        timelineChart = null;
      }
      return;
    }

    el.timelineEmpty.classList.add("hidden");

    const labels = timeline.map((item) => String(item.date || ""));
    const counts = timeline.map((item) => Number(item.count || 0));

    if (timelineChart) {
      timelineChart.data.labels = labels;
      timelineChart.data.datasets[0].data = counts;
      timelineChart.update();
      return;
    }

    const ctx = el.timelineCanvas.getContext("2d");
    const gradient = ctx.createLinearGradient(0, 0, 0, 260);
    gradient.addColorStop(0, "rgba(45, 212, 191, 0.4)");
    gradient.addColorStop(1, "rgba(45, 212, 191, 0.0)");

    timelineChart = new Chart(ctx, {
      type: "line",
      data: {
        labels: labels,
        datasets: [
          {
            label: "Attacks",
            data: counts,
            borderColor: "#2dd4bf",
            backgroundColor: gradient,
            borderWidth: 2.5,
            pointBackgroundColor: "#2dd4bf",
            pointBorderColor: "#0b1220",
            pointBorderWidth: 2,
            pointRadius: 4,
            pointHoverRadius: 6,
            tension: 0.35,
            fill: true
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: {
          duration: 800
        },
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: "#0d1424",
            titleColor: "#e6edf7",
            bodyColor: "#2dd4bf",
            borderColor: "#1f2d46",
            borderWidth: 1,
            padding: 10,
            displayColors: false,
            callbacks: {
              label: (ctx) => `Attacks: ${ctx.parsed.y}`
            }
          }
        },
        scales: {
          x: {
            grid: { color: "#172338" },
            ticks: { color: "#8fa3c0", font: { family: "IBM Plex Sans", size: 11 } }
          },
          y: {
            beginAtZero: true,
            grid: { color: "#172338" },
            ticks: { color: "#8fa3c0", font: { family: "JetBrains Mono", size: 11 }, precision: 0 }
          }
        }
      }
    });
  }

  /* 3. Risk Distribution Donut Chart with Total in Center */
  function renderRiskDonutChart(riskDist = {}) {
    const low = Number(riskDist.low || 0);
    const medium = Number(riskDist.medium || 0);
    const high = Number(riskDist.high || 0);
    const critical = Number(riskDist.critical || 0);
    const total = low + medium + high + critical;

    if (total === 0) {
      el.riskEmpty.classList.remove("hidden");
      if (riskChart) {
        riskChart.destroy();
        riskChart = null;
      }
      return;
    }

    el.riskEmpty.classList.add("hidden");

    const labels = ["Low", "Medium", "High", "Critical"];
    const counts = [low, medium, high, critical];
    const colors = ["#34d399", "#fbbf24", "#fb923c", "#f87171"];

    // Custom center text plugin
    const centerTextPlugin = {
      id: "centerTextPlugin",
      afterDraw(chart) {
        const { ctx, chartArea: { left, right, top, bottom } } = chart;
        const centerX = (left + right) / 2;
        const centerY = (top + bottom) / 2;

        ctx.save();
        ctx.textAlign = "center";
        ctx.textBaseline = "middle";

        ctx.font = "bold 24px 'JetBrains Mono', monospace";
        ctx.fillStyle = "#e6edf7";
        ctx.fillText(total.toLocaleString(), centerX, centerY - 6);

        ctx.font = "600 11px 'IBM Plex Sans', sans-serif";
        ctx.fillStyle = "#8fa3c0";
        ctx.fillText("TOTAL RISKS", centerX, centerY + 14);

        ctx.restore();
      }
    };

    if (riskChart) {
      riskChart.data.datasets[0].data = counts;
      riskChart.update();
      return;
    }

    const ctx = el.riskCanvas.getContext("2d");
    riskChart = new Chart(ctx, {
      type: "doughnut",
      data: {
        labels: labels,
        datasets: [
          {
            data: counts,
            backgroundColor: colors,
            borderColor: "#111a2b",
            borderWidth: 3,
            hoverOffset: 4
          }
        ]
      },
      plugins: [centerTextPlugin],
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: "72%",
        animation: { duration: 800 },
        plugins: {
          legend: {
            position: "bottom",
            labels: {
              color: "#ffffff",
              font: { family: "IBM Plex Sans", size: 12 },
              padding: 16,
              usePointStyle: true,
              pointStyle: "circle",
              generateLabels: (chart) => {
                const data = chart.data;
                return data.labels.map((label, i) => ({
                  text: `${label} (${data.datasets[0].data[i]})`,
                  fillStyle: colors[i],
                  strokeStyle: colors[i],
                  hidden: false,
                  index: i
                }));
              }
            }
          },
          tooltip: {
            backgroundColor: "#0d1424",
            titleColor: "#e6edf7",
            bodyColor: "#2dd4bf",
            borderColor: "#1f2d46",
            borderWidth: 1,
            padding: 10
          }
        }
      }
    });
  }

  /* 4. Live Attack Feed (12 Latest Sessions) */
  function renderLiveFeed(sessions) {
    if (!Array.isArray(sessions) || sessions.length === 0) {
      el.feedEmpty.classList.remove("hidden");
      el.feedList.textContent = "";
      return;
    }

    el.feedEmpty.classList.add("hidden");

    // Copy and sort newest first by start_time
    const sorted = [...sessions].sort((a, b) => {
      const tA = a.start_time ? new Date(a.start_time).getTime() : 0;
      const tB = b.start_time ? new Date(b.start_time).getTime() : 0;
      return tB - tA;
    });

    const latest12 = sorted.slice(0, 12);
    const fragment = document.createDocumentFragment();

    latest12.forEach((session) => {
      const sid = String(session.session_id || "");
      const isNew = sid && !knownSessionIds.has(sid);

      const li = document.createElement("li");
      li.className = "feed-item";
      if (isNew) {
        li.classList.add("new-session-highlight");
      }

      // Main content wrap
      const mainDiv = document.createElement("div");
      mainDiv.className = "feed-item-main";

      const headerDiv = document.createElement("div");
      headerDiv.className = "feed-item-header";

      const ipSpan = document.createElement("span");
      ipSpan.className = "feed-ip";
      ipSpan.textContent = String(session.src_ip || "Unknown IP");

      const timeSpan = document.createElement("span");
      timeSpan.className = "feed-time";
      timeSpan.textContent = formatLocalTime(session.start_time);

      headerDiv.appendChild(ipSpan);
      headerDiv.appendChild(timeSpan);

      // Description text (plain text)
      const descDiv = document.createElement("div");
      descDiv.className = "feed-desc";
      descDiv.textContent = buildSessionDescription(session);

      mainDiv.appendChild(headerDiv);
      mainDiv.appendChild(descDiv);

      // Risk badge
      const badge = createRiskBadge(session.risk_level);

      li.appendChild(mainDiv);
      li.appendChild(badge);

      fragment.appendChild(li);
    });

    // Update list cleanly
    el.feedList.textContent = "";
    el.feedList.appendChild(fragment);

    // Update known session IDs
    sessions.forEach((s) => {
      if (s.session_id) knownSessionIds.add(String(s.session_id));
    });
  }

  function buildSessionDescription(session) {
    if (Array.isArray(session.commands) && session.commands.length > 0) {
      const lastCmd = session.commands[session.commands.length - 1];
      return `Ran ${lastCmd}`;
    }

    if (Array.isArray(session.login_attempts) && session.login_attempts.length > 0) {
      const successfulAttempt = session.login_attempts.find((a) => a && a.success === true);
      if (successfulAttempt) {
        return `Login succeeded as ${successfulAttempt.username || "unknown"}`;
      }
      const firstAttempt = session.login_attempts[0];
      return `Failed login as ${firstAttempt.username || "unknown"}`;
    }

    return "Connected, no activity";
  }

  function createRiskBadge(level) {
    const span = document.createElement("span");
    const lvl = (level || "low").toLowerCase();
    span.className = `badge badge-${lvl}`;
    span.textContent = lvl.toUpperCase();
    return span;
  }

  /* 5. Attack Origins Map */
  function renderAttackMap(sessions) {
    el.mapMarkersLayer.textContent = "";

    const validMarkers = [];

    if (Array.isArray(sessions)) {
      sessions.forEach((s) => {
        const lat = Number(s.latitude);
        const lng = Number(s.longitude);
        if (!isNaN(lat) && !isNaN(lng) && typeof s.latitude === "number" && typeof s.longitude === "number") {
          validMarkers.push({
            ip: String(s.src_ip || "Unknown IP"),
            risk: String(s.risk_level || "low"),
            lat: lat,
            lng: lng
          });
        }
      });
    }

    if (validMarkers.length === 0) {
      el.mapOverlay.classList.remove("hidden");
      return;
    }

    el.mapOverlay.classList.add("hidden");

    const ns = "http://www.w3.org/2000/svg";

    validMarkers.forEach((m) => {
      // Equirectangular projection into 1000x500
      const x = ((m.lng + 180) / 360) * 1000;
      const y = ((90 - m.lat) / 180) * 500;

      const group = document.createElementNS(ns, "g");
      group.setAttribute("class", "map-marker");
      group.setAttribute("transform", `translate(${x.toFixed(1)}, ${y.toFixed(1)})`);

      // Outer pulsing ripple
      const pulseCircle = document.createElementNS(ns, "circle");
      pulseCircle.setAttribute("cx", "0");
      pulseCircle.setAttribute("cy", "0");
      pulseCircle.setAttribute("r", "8");
      pulseCircle.setAttribute("class", "map-marker-pulse");
      pulseCircle.setAttribute("fill", getRiskColor(m.risk));
      pulseCircle.setAttribute("opacity", "0.4");

      // Inner pin circle
      const coreCircle = document.createElementNS(ns, "circle");
      coreCircle.setAttribute("cx", "0");
      coreCircle.setAttribute("cy", "0");
      coreCircle.setAttribute("r", "4");
      coreCircle.setAttribute("fill", getRiskColor(m.risk));
      coreCircle.setAttribute("stroke", "#ffffff");
      coreCircle.setAttribute("stroke-width", "1.2");

      group.appendChild(pulseCircle);
      group.appendChild(coreCircle);

      // Tooltip interaction
      group.addEventListener("mouseenter", (e) => {
        el.tooltipIp.textContent = m.ip;
        el.tooltipRisk.textContent = `Risk Level: ${m.risk}`;
        el.mapTooltip.classList.remove("hidden");

        const rect = el.mapMarkersLayer.getBoundingClientRect();
        const clientX = e.clientX;
        const clientY = e.clientY;
        el.mapTooltip.style.left = `${clientX}px`;
        el.mapTooltip.style.top = `${clientY}px`;
      });

      group.addEventListener("mouseleave", () => {
        el.mapTooltip.classList.add("hidden");
      });

      el.mapMarkersLayer.appendChild(group);
    });
  }

  function getRiskColor(level) {
    const l = (level || "").toLowerCase();
    switch (l) {
      case "critical": return "#f87171";
      case "high": return "#fb923c";
      case "medium": return "#fbbf24";
      default: return "#34d399";
    }
  }

  /* 6. Top IPs Bar Chart */
  function renderTopIpsChart(topIps) {
    const hasData = Array.isArray(topIps) && topIps.length > 0;

    if (!hasData) {
      el.topIpsEmpty.classList.remove("hidden");
      if (topIpsChart) {
        topIpsChart.destroy();
        topIpsChart = null;
      }
      return;
    }

    el.topIpsEmpty.classList.add("hidden");

    const labels = topIps.map((i) => String(i.ip || ""));
    const counts = topIps.map((i) => Number(i.count || 0));

    if (topIpsChart) {
      topIpsChart.data.labels = labels;
      topIpsChart.data.datasets[0].data = counts;
      topIpsChart.update();
      return;
    }

    const ctx = el.topIpsCanvas.getContext("2d");
    topIpsChart = new Chart(ctx, {
      type: "bar",
      data: {
        labels: labels,
        datasets: [
          {
            label: "Attacks",
            data: counts,
            backgroundColor: "#2dd4bf",
            borderRadius: 4,
            barThickness: 16
          }
        ]
      },
      options: {
        indexAxis: "y",
        responsive: true,
        maintainAspectRatio: false,
        animation: { duration: 800 },
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: "#0d1424",
            titleColor: "#e6edf7",
            bodyColor: "#2dd4bf",
            borderColor: "#1f2d46",
            borderWidth: 1,
            padding: 10
          }
        },
        scales: {
          x: {
            beginAtZero: true,
            grid: { color: "#172338" },
            ticks: { color: "#8fa3c0", font: { family: "JetBrains Mono", size: 11 }, precision: 0 }
          },
          y: {
            grid: { display: false },
            ticks: { color: "#8fa3c0", font: { family: "JetBrains Mono", size: 11 } }
          }
        }
      }
    });
  }

  /* 7. Top Commands Bar Chart (with Axis Truncation & Full Tooltip) */
  function renderTopCommandsChart(topCommands) {
    const hasData = Array.isArray(topCommands) && topCommands.length > 0;

    if (!hasData) {
      el.topCommandsEmpty.classList.remove("hidden");
      if (topCommandsChart) {
        topCommandsChart.destroy();
        topCommandsChart = null;
      }
      return;
    }

    el.topCommandsEmpty.classList.add("hidden");

    const fullCommands = topCommands.map((c) => String(c.command || ""));
    const counts = topCommands.map((c) => Number(c.count || 0));

    // Truncate labels on Y-axis
    const displayLabels = fullCommands.map((cmd) => {
      return cmd.length > 22 ? cmd.substring(0, 20) + "..." : cmd;
    });

    if (topCommandsChart) {
      topCommandsChart.data.labels = displayLabels;
      topCommandsChart.data.datasets[0].data = counts;
      topCommandsChart.data.datasets[0].fullCommands = fullCommands;
      topCommandsChart.update();
      return;
    }

    const ctx = el.topCommandsCanvas.getContext("2d");
    topCommandsChart = new Chart(ctx, {
      type: "bar",
      data: {
        labels: displayLabels,
        datasets: [
          {
            label: "Executions",
            data: counts,
            fullCommands: fullCommands,
            backgroundColor: "#38bdf8",
            borderRadius: 4,
            barThickness: 16
          }
        ]
      },
      options: {
        indexAxis: "y",
        responsive: true,
        maintainAspectRatio: false,
        animation: { duration: 800 },
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: "#0d1424",
            titleColor: "#e6edf7",
            bodyColor: "#38bdf8",
            borderColor: "#1f2d46",
            borderWidth: 1,
            padding: 10,
            callbacks: {
              title: function (items) {
                const index = items[0].dataIndex;
                return fullCommands[index] || "";
              },
              label: function (item) {
                return `Executions: ${item.parsed.x}`;
              }
            }
          }
        },
        scales: {
          x: {
            beginAtZero: true,
            grid: { color: "#172338" },
            ticks: { color: "#8fa3c0", font: { family: "JetBrains Mono", size: 11 }, precision: 0 }
          },
          y: {
            grid: { display: false },
            ticks: {
              color: "#8fa3c0",
              font: { family: "JetBrains Mono", size: 11 }
            }
          }
        }
      }
    });
  }

  /* 8. Sessions Table with Sorting, Expanding Rows, Typewriter Replay & Attempts */
  function renderSessionsTable(sessions) {
    if (!Array.isArray(sessions) || sessions.length === 0) {
      el.tableEmpty.classList.remove("hidden");
      el.sessionsTbody.textContent = "";
      el.tableRecordCount.textContent = "0 sessions";
      el.showMoreBtn.classList.add("hidden");
      return;
    }

    el.tableEmpty.classList.add("hidden");

    // Sort sessions
    const sorted = sortSessionsList([...sessions], currentSortColumn, currentSortAsc);
    const totalCount = sorted.length;
    const visibleSessions = sorted.slice(0, sessionsDisplayLimit);

    el.tableRecordCount.textContent = `Showing ${visibleSessions.length} of ${totalCount}`;

    if (totalCount > sessionsDisplayLimit) {
      el.showMoreBtn.classList.remove("hidden");
    } else {
      el.showMoreBtn.classList.add("hidden");
    }

    el.sessionsTbody.textContent = "";
    const fragment = document.createDocumentFragment();

    visibleSessions.forEach((session) => {
      const sid = String(session.session_id || "");
      const isExpanded = expandedSessionIds.has(sid);
      const riskLevel = (session.risk_level || "low").toLowerCase();

      // Main session row
      const tr = document.createElement("tr");
      tr.className = `session-row risk-tint-${riskLevel}`;
      if (isExpanded) tr.classList.add("expanded");
      tr.tabIndex = 0;
      tr.setAttribute("role", "button");
      tr.setAttribute("aria-expanded", isExpanded ? "true" : "false");

      // Column 1: Session ID
      const tdId = document.createElement("td");
      tdId.className = "cell-session-id";
      tdId.textContent = sid.length > 14 ? sid.substring(0, 12) + "..." : sid;
      tdId.title = sid;
      tr.appendChild(tdId);

      // Column 2: Source IP
      const tdIp = document.createElement("td");
      tdIp.className = "cell-ip";
      tdIp.textContent = String(session.src_ip || "—");
      tr.appendChild(tdIp);

      // Column 3: Risk Score
      const tdScore = document.createElement("td");
      tdScore.className = "cell-score";
      const score = Number(session.risk_score || 0);
      tdScore.textContent = score.toString();
      if (score >= 75) tdScore.classList.add("text-critical");
      tr.appendChild(tdScore);

      // Column 4: Level badge
      const tdLevel = document.createElement("td");
      tdLevel.appendChild(createRiskBadge(session.risk_level));
      tr.appendChild(tdLevel);

      // Column 5: Started Time
      const tdTime = document.createElement("td");
      tdTime.className = "cell-time";
      tdTime.textContent = formatLocalTime(session.start_time);
      tr.appendChild(tdTime);

      // Column 6: Commands count
      const tdCmds = document.createElement("td");
      const cmdCount = Array.isArray(session.commands) ? session.commands.length : 0;
      tdCmds.textContent = `${cmdCount} cmds`;
      tr.appendChild(tdCmds);

      // Click / Enter listener to toggle details
      const toggleRow = () => {
        if (expandedSessionIds.has(sid)) {
          expandedSessionIds.delete(sid);
        } else {
          expandedSessionIds.add(sid);
        }
        renderSessionsTable(lastDashboardData.sessions);
      };

      tr.addEventListener("click", toggleRow);
      tr.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          toggleRow();
        }
      });

      fragment.appendChild(tr);

      // Detail row if expanded
      if (isExpanded) {
        const detailTr = createSessionDetailRow(session);
        fragment.appendChild(detailTr);
      }
    });

    el.sessionsTbody.appendChild(fragment);
  }

  function sortSessionsList(sessions, column, asc) {
    return sessions.sort((a, b) => {
      let valA, valB;

      switch (column) {
        case "session_id":
          valA = String(a.session_id || "");
          valB = String(b.session_id || "");
          return asc ? valA.localeCompare(valB) : valB.localeCompare(valA);

        case "src_ip":
          valA = String(a.src_ip || "");
          valB = String(b.src_ip || "");
          return asc ? valA.localeCompare(valB) : valB.localeCompare(valA);

        case "risk_score":
          valA = Number(a.risk_score || 0);
          valB = Number(b.risk_score || 0);
          return asc ? valA - valB : valB - valA;

        case "risk_level":
          const weight = { critical: 4, high: 3, medium: 2, low: 1 };
          valA = weight[(a.risk_level || "").toLowerCase()] || 0;
          valB = weight[(b.risk_level || "").toLowerCase()] || 0;
          return asc ? valA - valB : valB - valA;

        case "start_time":
          valA = a.start_time ? new Date(a.start_time).getTime() : 0;
          valB = b.start_time ? new Date(b.start_time).getTime() : 0;
          return asc ? valA - valB : valB - valA;

        case "command_count":
          valA = Array.isArray(a.commands) ? a.commands.length : 0;
          valB = Array.isArray(b.commands) ? b.commands.length : 0;
          return asc ? valA - valB : valB - valA;

        default:
          return 0;
      }
    });
  }

  function updateSortHeaderIndicators() {
    const headers = el.sessionsTable.querySelectorAll("th.sortable");
    headers.forEach((th) => {
      const col = th.getAttribute("data-sort");
      const indicator = th.querySelector(".sort-indicator");

      if (col === currentSortColumn) {
        th.setAttribute("aria-sort", currentSortAsc ? "ascending" : "descending");
        if (indicator) indicator.textContent = currentSortAsc ? "▲" : "▼";
      } else {
        th.setAttribute("aria-sort", "none");
        if (indicator) indicator.textContent = "↕";
      }
    });
  }

  function createSessionDetailRow(session) {
    const sid = String(session.session_id || "");
    const detailTr = document.createElement("tr");
    detailTr.className = "session-detail-row";

    const td = document.createElement("td");
    td.colSpan = 6;

    const wrapper = document.createElement("div");
    wrapper.className = "session-detail-wrapper";

    // 1. Session Replay Section
    const replaySection = document.createElement("div");
    replaySection.className = "detail-section";

    const replayTitle = document.createElement("div");
    replayTitle.className = "detail-section-title";
    replayTitle.textContent = "Session Replay (Commands Execution)";
    replaySection.appendChild(replayTitle);

    const terminalBox = document.createElement("div");
    terminalBox.className = "terminal-box";

    const commands = Array.isArray(session.commands) ? session.commands : [];

    if (commands.length === 0) {
      const emptyLine = document.createElement("div");
      emptyLine.className = "terminal-line";
      emptyLine.textContent = "No commands were run";
      terminalBox.appendChild(emptyLine);
    } else {
      const shouldAnimate = !animatedSessionIds.has(sid) && !window.matchMedia("(prefers-reduced-motion: reduce)").matches;

      if (shouldAnimate) {
        animatedSessionIds.add(sid);
        startTypewriterReplay(terminalBox, commands);
      } else {
        // Render instantly without animation
        commands.forEach((cmd) => {
          const line = document.createElement("div");
          line.className = "terminal-line";

          const prompt = document.createElement("span");
          prompt.className = "terminal-prompt";
          prompt.textContent = "$";

          const text = document.createElement("span");
          text.textContent = ` ${cmd}`;

          line.appendChild(prompt);
          line.appendChild(text);
          terminalBox.appendChild(line);
        });

        const cursorLine = document.createElement("div");
        cursorLine.className = "terminal-line";
        const cursor = document.createElement("span");
        cursor.className = "terminal-cursor";
        cursor.textContent = "▌";
        cursorLine.appendChild(cursor);
        terminalBox.appendChild(cursorLine);
      }
    }

    replaySection.appendChild(terminalBox);

    // 2. Login Attempts Section
    const loginSection = document.createElement("div");
    loginSection.className = "detail-section";

    const loginTitle = document.createElement("div");
    loginTitle.className = "detail-section-title";
    loginTitle.textContent = "Credential Login Attempts";
    loginSection.appendChild(loginTitle);

    const attempts = Array.isArray(session.login_attempts) ? session.login_attempts : [];

    if (attempts.length === 0) {
      const emptyAttempts = document.createElement("div");
      emptyAttempts.className = "empty-state";
      const p = document.createElement("p");
      p.textContent = "No login attempts recorded";
      emptyAttempts.appendChild(p);
      loginSection.appendChild(emptyAttempts);
    } else {
      const table = document.createElement("table");
      table.className = "attempts-table";

      const thead = document.createElement("thead");
      const trh = document.createElement("tr");

      ["Username", "Password", "Result", "Time"].forEach((h) => {
        const th = document.createElement("th");
        th.textContent = h;
        trh.appendChild(th);
      });
      thead.appendChild(trh);
      table.appendChild(thead);

      const tbody = document.createElement("tbody");

      attempts.forEach((att) => {
        const tr = document.createElement("tr");

        // Username
        const tdU = document.createElement("td");
        tdU.textContent = String(att.username || "—");
        tr.appendChild(tdU);

        // Password (treated strictly as plain text!)
        const tdP = document.createElement("td");
        tdP.textContent = String(att.password || "—");
        tr.appendChild(tdP);

        // Result badge
        const tdR = document.createElement("td");
        const badge = document.createElement("span");
        const isSuccess = att.success === true;
        badge.className = `result-badge ${isSuccess ? "result-success" : "result-failed"}`;
        badge.textContent = isSuccess ? "Success" : "Failed";
        tdR.appendChild(badge);
        tr.appendChild(tdR);

        // Timestamp
        const tdT = document.createElement("td");
        tdT.textContent = formatLocalTime(att.timestamp);
        tr.appendChild(tdT);

        tbody.appendChild(tr);
      });

      table.appendChild(tbody);
      loginSection.appendChild(table);
    }

    wrapper.appendChild(replaySection);
    wrapper.appendChild(loginSection);
    td.appendChild(wrapper);
    detailTr.appendChild(td);

    return detailTr;
  }

  /* Typewriter Animation for Replay */
  function startTypewriterReplay(container, commands) {
    let cmdIdx = 0;
    let charIdx = 0;

    const cursor = document.createElement("span");
    cursor.className = "terminal-cursor";
    cursor.textContent = "▌";

    let currentLine = null;
    let currentTextSpan = null;

    function nextChar() {
      if (cmdIdx >= commands.length) {
        if (currentLine && !currentLine.contains(cursor)) {
          currentLine.appendChild(cursor);
        }
        return;
      }

      const cmd = commands[cmdIdx];

      if (charIdx === 0) {
        currentLine = document.createElement("div");
        currentLine.className = "terminal-line";

        const prompt = document.createElement("span");
        prompt.className = "terminal-prompt";
        prompt.textContent = "$ ";

        currentTextSpan = document.createElement("span");

        currentLine.appendChild(prompt);
        currentLine.appendChild(currentTextSpan);
        currentLine.appendChild(cursor);

        container.appendChild(currentLine);
      }

      if (charIdx < cmd.length) {
        currentTextSpan.textContent += cmd[charIdx];
        charIdx += 1;
        container.scrollTop = container.scrollHeight;
        setTimeout(nextChar, 25);
      } else {
        // Line finished, move to next command after pause
        cmdIdx += 1;
        charIdx = 0;
        setTimeout(nextChar, 200);
      }
    }

    nextChar();
  }

  /* Helper: Format Timestamp to Local Time */
  function formatLocalTime(isoString) {
    if (!isoString) return "—";
    try {
      const d = new Date(isoString);
      if (isNaN(d.getTime())) return "—";
      return d.toLocaleString(undefined, {
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit"
      });
    } catch (e) {
      return "—";
    }
  }

  /* ==========================================================================
     INITIALIZATION ON DOMContentLoaded
     ========================================================================== */
  document.addEventListener("DOMContentLoaded", () => {
    initMascot();
    initNavigation();
    initAuth();
  });
})();
