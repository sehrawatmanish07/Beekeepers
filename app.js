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
  const DEMO_MAP_MARKERS = [
    { ip: "203.0.113.10", risk: "high", lat: 37.7749, lng: -122.4194 },
    { ip: "198.51.100.24", risk: "medium", lat: 52.52, lng: 13.405 },
    { ip: "192.0.2.45", risk: "critical", lat: 1.3521, lng: 103.8198 },
    { ip: "203.0.113.87", risk: "low", lat: -31.9505, lng: 115.8605 }
  ];

  // Global State
  let countdownTimerId = null;
  let loginRequestInFlight = false;
  let dashboardRequestInFlight = false;
  let secondsRemaining = 15;
  let lastDashboardData = null;
  let pdfStatusTimerId = null;
  let currentSortColumn = "risk_score";
  let currentSortAsc = false;
  let sessionsDisplayLimit = 100;
  let sessionsSearchDebounceId = null;
  let knownSessionIds = new Set();
  let expandedSessionIds = new Set();
  let animatedSessionIds = new Set();
  let isKikoSad = false;
  let kikoBubbleTimer = null;
  let pupilTrackingFrameId = null;
  let latestMousePosition = null;
  let scoringRules = [];
  let scoringRulesStatus = "idle";
  let scoringRulesOpen = false;
  let scoringRulesRequestInFlight = false;
  let topToolsChart = null;
  let activeIncidentReport = null;
  let previousReportTitle = "";
  let previousReportScrollY = 0;

  // Chart References
  let timelineChart = null;
  let riskChart = null;
  let topIpsChart = null;
  let topCommandsChart = null;

  // DOM Elements
  const el = {
    connectionBanner: document.getElementById("connection-banner"),
    connectionBannerText: document.getElementById("connection-banner-text"),
    mapOverlayText: document.getElementById("map-overlay-text"),
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
    exportPdfBtn: document.getElementById("export-pdf-btn"),
    pdfExportStatus: document.getElementById("pdf-export-status"),
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
    topToolsCanvas: document.getElementById("top-tools-chart"),
    topToolsEmpty: document.getElementById("top-tools-empty"),
    scoringRulesToggle: document.getElementById("scoring-rules-toggle"),
    scoringRulesPanel: document.getElementById("scoring-rules-panel"),
    sessionsTable: document.getElementById("sessions-table"),
    sessionsTbody: document.getElementById("sessions-tbody"),
    tableEmpty: document.getElementById("table-empty"),
    tableRecordCount: document.getElementById("table-record-count"),
    showMoreBtn: document.getElementById("show-more-btn"),
    sessionSearchInput: document.getElementById("session-search-input"),
    sessionSearchClear: document.getElementById("session-search-clear"),

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
      latestMousePosition = { x: e.clientX, y: e.clientY };
      if (pupilTrackingFrameId === null) {
        pupilTrackingFrameId = window.requestAnimationFrame(() => {
          pupilTrackingFrameId = null;
          if (latestMousePosition) {
            trackPupils(latestMousePosition.x, latestMousePosition.y);
          }
        });
      }
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

    el.loginForm.addEventListener("submit", handleLoginSubmit);

    // Auto-login if token already in sessionStorage
    const existingToken = sessionStorage.getItem(TOKEN_KEY);
    if (existingToken) {
      showDashboardView();
    }
  }

  async function handleLoginSubmit(e) {
    e.preventDefault();
    if (loginRequestInFlight || IS_PLACEHOLDER) return;

    hideLoginAlerts();
    setKikoMouth(false);

    const username = el.usernameInput.value.trim();
    const password = el.passwordInput.value;

    if (!username || !password) {
      showLoginError("Please enter both username and password.");
      return;
    }

    // Disable button and prevent double submit
    loginRequestInFlight = true;
    el.loginBtn.disabled = true;
    el.loginBtnSpinner.classList.remove("hidden");
    el.loginBtnText.textContent = "Connecting...";

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 60000);

    // After 5s, notify user about cold server wakeup
    const wakeupTimer = setTimeout(() => {
      if (loginRequestInFlight) {
        showLoginInfo("The server may be waking up, this can take up to a minute");
      }
    }, 5000);
    let authenticated = false;

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
          authenticated = true;
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
      loginRequestInFlight = false;
      el.loginBtn.disabled = false;
      el.loginBtnSpinner.classList.add("hidden");
      el.loginBtnText.textContent = "Log in";
      if (authenticated) {
        showDashboardView();
      }
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
    clearTimeout(sessionsSearchDebounceId);
    sessionsSearchDebounceId = null;
    el.sessionSearchInput.value = "";
    el.sessionSearchClear.classList.add("hidden");
    lastDashboardData = null;
    el.exportPdfBtn.disabled = true;

    el.dashboardView.classList.add("hidden");
    el.loginView.classList.remove("hidden");
    hideConnectionBanner();

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
    fetchScoringRules();

    // Start auto-refresh polling loop
    startPolling();
  }

  function initNavigation() {
    window.addEventListener("hashchange", handleHashRouting);
    window.addEventListener("resize", positionConnectionBanner);
    document.addEventListener("visibilitychange", handleVisibilityChange);

    el.sessionSearchInput.addEventListener("input", () => {
      el.sessionSearchClear.classList.toggle("hidden", el.sessionSearchInput.value.length === 0);
      clearTimeout(sessionsSearchDebounceId);
      sessionsSearchDebounceId = setTimeout(() => {
        sessionsSearchDebounceId = null;
        if (lastDashboardData && Array.isArray(lastDashboardData.sessions)) {
          renderSessionsTable(lastDashboardData.sessions);
        }
      }, 150);
    });

    el.sessionSearchInput.addEventListener("keydown", (event) => {
      if (event.key === "Escape" && el.sessionSearchInput.value.length > 0) {
        event.preventDefault();
        clearSessionsSearch();
      }
    });

    el.sessionSearchClear.addEventListener("click", () => clearSessionsSearch());

    if (el.logoutBtn) {
      el.logoutBtn.addEventListener("click", () => handleLogout());
    }

    if (el.scoringRulesToggle) {
      el.scoringRulesToggle.addEventListener("click", toggleScoringRulesPanel);
      el.scoringRulesToggle.setAttribute("aria-expanded", String(scoringRulesOpen));
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

  function clearSessionsSearch() {
    clearTimeout(sessionsSearchDebounceId);
    sessionsSearchDebounceId = null;
    el.sessionSearchInput.value = "";
    el.sessionSearchClear.classList.add("hidden");
    if (lastDashboardData && Array.isArray(lastDashboardData.sessions)) {
      renderSessionsTable(lastDashboardData.sessions);
    }
    el.sessionSearchInput.focus();
  }

  /* ==========================================================================
     AUTO-REFRESH POLLING & COUNTDOWN RING
     ========================================================================== */
  function startPolling() {
    stopPolling();
    if (document.hidden) return;
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
    clearInterval(countdownTimerId);
    countdownTimerId = null;
  }

  function handleVisibilityChange() {
    if (el.dashboardView.classList.contains("hidden")) return;
    if (document.hidden) {
      stopPolling();
      return;
    }

    fetchDashboardData(false);
    startPolling();
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
    if (dashboardRequestInFlight) return;

    const token = sessionStorage.getItem(TOKEN_KEY);
    if (!token) {
      handleLogout("Session expired, please log in again.");
      return;
    }

    dashboardRequestInFlight = true;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 60000);
    let data;

    try {
      const res = await fetch(`${API_BASE}/api/dashboard`, {
        method: "GET",
        signal: controller.signal,
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

      data = await res.json();
    } catch (err) {
      el.connectionBannerText.textContent = controller.signal.aborted
        ? "Dashboard request timed out, retrying..."
        : "Connection lost, retrying...";
      showConnectionBanner();
      return;
    } finally {
      clearTimeout(timeoutId);
      dashboardRequestInFlight = false;
    }

    lastDashboardData = data;
    el.exportPdfBtn.disabled = !data || !Array.isArray(data.sessions);
    hideConnectionBanner();

    try {
      renderDashboard(data);
    } catch (err) {
      console.error("Dashboard rendering failed.", err);
      el.connectionBannerText.textContent = "Dashboard data loaded, but some panels could not be displayed.";
      showConnectionBanner();
    }
  }

  function positionConnectionBanner() {
    if (el.connectionBanner.classList.contains("hidden")) return;
    const header = el.dashboardView.querySelector(".console-header");
    const top = el.dashboardView.classList.contains("hidden")
      ? 0
      : header.getBoundingClientRect().bottom;
    el.connectionBanner.style.top = `${Math.max(0, top)}px`;
  }

  function showConnectionBanner() {
    el.connectionBanner.classList.remove("hidden");
    positionConnectionBanner();
  }

  function hideConnectionBanner() {
    el.connectionBanner.classList.add("hidden");
    el.connectionBanner.style.top = "";
    el.connectionBannerText.textContent = "Connection lost, retrying...";
  }

  async function fetchScoringRules(forceRefresh = false) {
    if (scoringRulesRequestInFlight) return;
    if (!forceRefresh && scoringRulesStatus === "ready" && scoringRules.length > 0) {
      renderScoringRulesPanel();
      return;
    }

    scoringRulesRequestInFlight = true;

    try {
      const res = await fetch(`${API_BASE}/api/rules`, {
        method: "GET",
        headers: {
          Accept: "application/json"
        }
      });

      if (!res.ok) {
        throw new Error(`Rules API returned ${res.status}`);
      }

      const data = await res.json();
      scoringRules = Array.isArray(data) ? data : [];
      scoringRulesStatus = "ready";
      renderScoringRulesPanel();
    } catch (err) {
      scoringRules = [];
      scoringRulesStatus = "error";
      renderScoringRulesPanel();
    } finally {
      scoringRulesRequestInFlight = false;
    }
  }

  function toggleScoringRulesPanel() {
    scoringRulesOpen = !scoringRulesOpen;
    if (el.scoringRulesToggle) {
      el.scoringRulesToggle.setAttribute("aria-expanded", String(scoringRulesOpen));
      el.scoringRulesToggle.classList.toggle("is-open", scoringRulesOpen);
    }
    renderScoringRulesPanel();
  }

  function renderScoringRulesPanel() {
    if (!el.scoringRulesPanel) return;

    el.scoringRulesPanel.classList.toggle("hidden", !scoringRulesOpen);
    if (!scoringRulesOpen) {
      el.scoringRulesPanel.textContent = "";
      return;
    }

    el.scoringRulesPanel.textContent = "";

    const note = document.createElement("div");
    note.className = "rules-panel-note";
    note.textContent = "Each session's risk score is the sum of the rules that matched.";
    el.scoringRulesPanel.appendChild(note);

    if (scoringRulesStatus === "error") {
      const errorWrap = document.createElement("div");
      errorWrap.className = "rules-panel-error";

      const message = document.createElement("span");
      message.textContent = "Could not load scoring rules";
      errorWrap.appendChild(message);

      const retryBtn = document.createElement("button");
      retryBtn.type = "button";
      retryBtn.className = "btn btn-secondary btn-sm rules-retry-btn";
      retryBtn.textContent = "Retry";
      retryBtn.addEventListener("click", () => fetchScoringRules(true));
      errorWrap.appendChild(retryBtn);

      el.scoringRulesPanel.appendChild(errorWrap);
      return;
    }

    const sortedRules = Array.isArray(scoringRules)
      ? [...scoringRules].sort((a, b) => (Number(a.order) || 0) - (Number(b.order) || 0))
      : [];

    if (sortedRules.length === 0) {
      const empty = document.createElement("div");
      empty.className = "rules-empty-message";
      empty.textContent = "No scoring rules available.";
      el.scoringRulesPanel.appendChild(empty);
      return;
    }

    const tableWrap = document.createElement("div");
    tableWrap.className = "rules-table-wrap";

    const table = document.createElement("table");
    table.className = "rules-table";

    const thead = document.createElement("thead");
    const headRow = document.createElement("tr");
    ["Order", "Rule", "Description", "Points"].forEach((label) => {
      const th = document.createElement("th");
      th.scope = "col";
      th.textContent = label;
      headRow.appendChild(th);
    });
    thead.appendChild(headRow);
    table.appendChild(thead);

    const tbody = document.createElement("tbody");
    sortedRules.forEach((rule) => {
      const row = document.createElement("tr");

      const orderCell = document.createElement("td");
      orderCell.textContent = String(rule.order ?? "");
      row.appendChild(orderCell);

      const labelCell = document.createElement("td");
      labelCell.textContent = String(rule.label || rule.name || "Unknown");
      row.appendChild(labelCell);

      const descCell = document.createElement("td");
      descCell.textContent = String(rule.description || "");
      row.appendChild(descCell);

      const pointsCell = document.createElement("td");
      pointsCell.className = "rules-points";
      const points = Number(rule.points || 0);
      pointsCell.textContent = `+${points}`;
      row.appendChild(pointsCell);

      tbody.appendChild(row);
    });
    table.appendChild(tbody);
    tableWrap.appendChild(table);
    el.scoringRulesPanel.appendChild(tableWrap);
  }

  /* ==========================================================================
     DASHBOARD RENDERING (SAFE & ESCAPED)
     ========================================================================== */
  function renderDashboard(data) {
    if (!data || typeof data !== "object") return;

    const renderers = [
      ["statistics", () => renderStats(data.stats)],
      ["attack timeline", () => renderTimelineChart(data.timeline)],
      ["risk chart", () => renderRiskDonutChart(data.risk_distribution)],
      ["live feed", () => renderLiveFeed(data.sessions)],
      ["attack map", () => renderAttackMap(data.sessions)],
      ["top IPs chart", () => renderTopIpsChart(data.top_ips)],
      ["top tools chart", () => renderTopToolsChart(data.top_tools)],
      ["top commands chart", () => renderTopCommandsChart(data.top_commands)],
      ["sessions table", () => renderSessionsTable(data.sessions)]
    ];
    let firstRenderError = null;

    renderers.forEach(([name, render]) => {
      try {
        render();
      } catch (err) {
        console.error(`Failed to render ${name}.`, err);
        if (!firstRenderError) firstRenderError = err;
      }
    });

    if (firstRenderError) {
      throw new Error("One or more dashboard panels failed to render.");
    }
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
        const currentTotal = chart.data.datasets[0].data.reduce((sum, count) => sum + Number(count || 0), 0);
        ctx.fillText(currentTotal.toLocaleString(), centerX, centerY - 6);

        ctx.font = "600 11px 'IBM Plex Sans', sans-serif";
        ctx.fillStyle = "#8fa3c0";
        ctx.fillText("TOTAL RISKS", centerX, centerY + 14);

        ctx.restore();
      }
    };

    if (riskChart) {
      riskChart.data.datasets[0].data = counts;
      riskChart.options.plugins.legend.labels.color = "#ffffff";
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
                  fontColor: "#ffffff",
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

    const markersByIp = new Map();
    const riskRank = { low: 1, medium: 2, high: 3, critical: 4 };

    if (Array.isArray(sessions)) {
      sessions.forEach((s) => {
        const lat = Number(s.latitude);
        const lng = Number(s.longitude);
        if (Number.isFinite(lat) && Number.isFinite(lng) &&
            lat >= -90 && lat <= 90 && lng >= -180 && lng <= 180 &&
            typeof s.latitude === "number" && typeof s.longitude === "number") {
          const ip = String(s.src_ip || "Unknown IP");
          const risk = String(s.risk_level || "low").toLowerCase();
          const marker = markersByIp.get(ip);
          if (!marker) {
            markersByIp.set(ip, { ip, risk, lat, lng, isDemo: false });
          } else if ((riskRank[risk] || 0) > (riskRank[marker.risk] || 0)) {
            marker.risk = risk;
          }
        }
      });
    }

    if (markersByIp.size === 0) {
      DEMO_MAP_MARKERS.forEach((marker) => {
        markersByIp.set(marker.ip, { ...marker, isDemo: true });
      });
      el.mapOverlayText.textContent = "Sample locations shown for demonstration. Live location data is unavailable.";
      el.mapOverlay.classList.remove("hidden");
    } else {
      el.mapOverlay.classList.add("hidden");
    }

    const ns = "http://www.w3.org/2000/svg";

    markersByIp.forEach((m) => {
      // Equirectangular projection into 1000x500
      const x = ((m.lng + 180) / 360) * 1000;
      const y = ((90 - m.lat) / 180) * 500;

      const group = document.createElementNS(ns, "g");
      group.setAttribute("class", "map-marker");
      group.setAttribute("transform", `translate(${x.toFixed(1)}, ${y.toFixed(1)})`);
      const markerScale = document.createElementNS(ns, "g");
      markerScale.setAttribute("class", "map-marker-scale");

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

      markerScale.appendChild(pulseCircle);
      markerScale.appendChild(coreCircle);
      group.appendChild(markerScale);

      // Tooltip interaction
      group.addEventListener("mouseenter", (e) => {
        el.tooltipIp.textContent = m.ip;
        el.tooltipRisk.textContent = `Risk Level: ${m.risk}${m.isDemo ? " (sample)" : ""}`;
        el.mapTooltip.classList.remove("hidden");

        const rect = el.mapTooltip.parentElement.getBoundingClientRect();
        el.mapTooltip.style.left = `${e.clientX - rect.left}px`;
        el.mapTooltip.style.top = `${e.clientY - rect.top}px`;
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
        onHover: (event, activeElements) => {
          el.topIpsCanvas.style.cursor = activeElements.length ? "pointer" : "default";
        },
        onClick: (event, activeElements) => {
          if (!activeElements.length || !topIpsChart) return;
          const ip = topIpsChart.data.labels[activeElements[0].index];
          try {
            exportIpPdf(ip);
          } catch (error) {
            showPdfExportStatus("Could not generate the PDF. Please try again.", true);
          }
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
            callbacks: {
              afterBody: () => ["Click to download PDF"]
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
                const item = items[0];
                const commands = item.chart.data.datasets[0].fullCommands;
                return commands[item.dataIndex] || "";
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

  /* 8. Tools Seen Bar Chart */
  function renderTopToolsChart(topTools) {
    const hasData = Array.isArray(topTools) && topTools.length > 0;

    if (!hasData) {
      el.topToolsEmpty.classList.remove("hidden");
      if (topToolsChart) {
        topToolsChart.destroy();
        topToolsChart = null;
      }
      return;
    }

    el.topToolsEmpty.classList.add("hidden");

    const fullTools = topTools.map((tool) => String(tool.tool || "Unknown"));
    const counts = topTools.map((tool) => Number(tool.count || 0));
    const displayLabels = fullTools.map((tool) => {
      return tool.length > 22 ? tool.substring(0, 20) + "..." : tool;
    });

    if (topToolsChart) {
      topToolsChart.data.labels = displayLabels;
      topToolsChart.data.datasets[0].data = counts;
      topToolsChart.data.datasets[0].fullTools = fullTools;
      topToolsChart.update();
      return;
    }

    const ctx = el.topToolsCanvas.getContext("2d");
    topToolsChart = new Chart(ctx, {
      type: "bar",
      data: {
        labels: displayLabels,
        datasets: [{
          label: "Occurrences",
          data: counts,
          fullTools: fullTools,
          backgroundColor: "#a78bfa",
          borderRadius: 4,
          barThickness: 16
        }]
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
            bodyColor: "#a78bfa",
            borderColor: "#1f2d46",
            borderWidth: 1,
            padding: 10,
            callbacks: {
              title: function (items) {
                const item = items[0];
                const tools = item.chart.data.datasets[0].fullTools;
                return tools[item.dataIndex] || "";
              },
              label: function (item) {
                return `Occurrences: ${item.parsed.x}`;
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

  /* 9. Sessions Table with Sorting, Expanding Rows, Typewriter Replay & Attempts */
  function renderSessionsTable(sessions) {
    const focusedRow = el.sessionsTbody.contains(document.activeElement)
      ? document.activeElement.closest(".session-row")
      : null;
    const focusedSessionId = focusedRow ? focusedRow.dataset.sessionId : null;

    if (!Array.isArray(sessions)) {
      el.tableEmpty.classList.remove("hidden");
      el.sessionsTbody.textContent = "";
      el.tableRecordCount.textContent = "0 sessions";
      el.showMoreBtn.classList.add("hidden");
      return;
    }

    el.tableEmpty.classList.add("hidden");

    const searchQuery = el.sessionSearchInput.value.trim().toLowerCase();
    const filteredSessions = searchQuery
      ? sessions.filter((session) => String(session.src_ip || "").toLowerCase().includes(searchQuery))
      : sessions;

    if (sessions.length === 0 && !searchQuery) {
      el.tableEmpty.classList.remove("hidden");
      el.sessionsTbody.textContent = "";
      el.tableRecordCount.textContent = "0 sessions";
      el.showMoreBtn.classList.add("hidden");
      return;
    }

    const sorted = sortSessionsList([...filteredSessions], currentSortColumn, currentSortAsc);
    const visibleSessions = sorted.slice(0, sessionsDisplayLimit);

    el.tableRecordCount.textContent = `Showing ${visibleSessions.length} of ${sessions.length}`;
    el.sessionsTbody.textContent = "";

    if (filteredSessions.length > sessionsDisplayLimit) {
      el.showMoreBtn.classList.remove("hidden");
    } else {
      el.showMoreBtn.classList.add("hidden");
    }

    if (searchQuery && filteredSessions.length === 0) {
      const emptyRow = document.createElement("tr");
      const emptyCell = document.createElement("td");
      emptyCell.colSpan = 6;

      const emptyMessage = document.createElement("div");
      emptyMessage.className = "session-search-empty";

      const message = document.createElement("span");
      message.textContent = "No sessions found for this IP.";
      emptyMessage.appendChild(message);

      const clearButton = document.createElement("button");
      clearButton.type = "button";
      clearButton.textContent = "Clear search";
      clearButton.addEventListener("click", clearSessionsSearch);
      emptyMessage.appendChild(clearButton);

      emptyCell.appendChild(emptyMessage);
      emptyRow.appendChild(emptyCell);
      el.sessionsTbody.appendChild(emptyRow);
      return;
    }

    const fragment = document.createDocumentFragment();

    visibleSessions.forEach((session) => {
      const sid = String(session.session_id || "");
      const isExpanded = expandedSessionIds.has(sid);
      const riskLevel = (session.risk_level || "low").toLowerCase();

      // Main session row
      const tr = document.createElement("tr");
      tr.className = `session-row risk-tint-${riskLevel}`;
      tr.dataset.sessionId = sid;
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
    if (focusedSessionId !== null) {
      const restoredRow = Array.from(el.sessionsTbody.querySelectorAll(".session-row"))
        .find((row) => row.dataset.sessionId === focusedSessionId);
      if (restoredRow) restoredRow.focus();
    }
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
          return asc
            ? valA.localeCompare(valB, undefined, { numeric: true })
            : valB.localeCompare(valA, undefined, { numeric: true });

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

    const summaryRow = document.createElement("div");
    summaryRow.className = "session-detail-header-strip";

    const leftMeta = document.createElement("div");
    leftMeta.className = "session-detail-header-left";
    leftMeta.appendChild(createRiskBadge(session.risk_level));

    const toolBadge = document.createElement("span");
    toolBadge.className = "tool-badge";

    const toolLabel = document.createElement("span");
    toolLabel.className = "tool-badge-label";
    toolLabel.textContent = "Tool";

    const toolValue = document.createElement("span");
    toolValue.className = "tool-badge-value";
    toolValue.textContent = String(session.tool || "Unknown");

    toolBadge.appendChild(toolLabel);
    toolBadge.appendChild(toolValue);
    leftMeta.appendChild(toolBadge);
    summaryRow.appendChild(leftMeta);

    const metaGroup = document.createElement("div");
    metaGroup.className = "session-detail-meta";

    const clientVersion = session.client_version || null;
    if (clientVersion) {
      const clientMeta = document.createElement("span");
      clientMeta.className = "session-meta-line";
      clientMeta.textContent = `client_version: ${clientVersion}`;
      metaGroup.appendChild(clientMeta);
    }

    const hassh = session.hassh || null;
    if (hassh) {
      const hasshMeta = document.createElement("span");
      hasshMeta.className = "session-meta-line session-meta-mono";
      hasshMeta.textContent = `hassh: ${hassh}`;
      metaGroup.appendChild(hasshMeta);
    }

    summaryRow.appendChild(metaGroup);

    const printButton = document.createElement("button");
    printButton.type = "button";
    printButton.className = "btn btn-secondary btn-sm print-report-btn";
    printButton.textContent = "Print Report";
    printButton.addEventListener("click", (event) => {
      event.preventDefault();
      event.stopPropagation();
      openIncidentReport(session);
    });
    summaryRow.appendChild(printButton);

    wrapper.appendChild(summaryRow);

    const scoreBreakdownSection = document.createElement("div");
    scoreBreakdownSection.className = "detail-section score-breakdown-section";

    const scoreTitle = document.createElement("div");
    scoreTitle.className = "detail-section-title";
    scoreTitle.textContent = "Score Breakdown";
    scoreBreakdownSection.appendChild(scoreTitle);

    const scoreEntries = Array.isArray(session.score_breakdown) ? session.score_breakdown : [];
    if (scoreEntries.length === 0) {
      const emptyScore = document.createElement("div");
      emptyScore.className = "empty-state compact-empty";
      const emptyText = document.createElement("p");
      emptyText.textContent = "No scoring rules matched";
      emptyScore.appendChild(emptyText);
      scoreBreakdownSection.appendChild(emptyScore);
    } else {
      const scoreList = document.createElement("div");
      scoreList.className = "score-breakdown-list";

      let totalPoints = 0;
      scoreEntries.forEach((item) => {
        const row = document.createElement("div");
        row.className = "score-breakdown-row";

        const description = document.createElement("span");
        description.className = "score-breakdown-label";
        description.textContent = String(item.label || item.rule || "Unknown");

        const points = document.createElement("span");
        points.className = "score-breakdown-points";
        const value = Number(item.points || 0);
        totalPoints += value;
        points.textContent = `+${value}`;

        row.appendChild(description);
        row.appendChild(points);
        scoreList.appendChild(row);
      });

      const totalRow = document.createElement("div");
      totalRow.className = "score-breakdown-total";

      const totalLabel = document.createElement("span");
      totalLabel.textContent = "Total";

      const totalValue = document.createElement("span");
      totalValue.className = "score-breakdown-points";
      totalValue.textContent = String(Number(session.risk_score || 0));

      totalRow.appendChild(totalLabel);
      totalRow.appendChild(totalValue);
      scoreList.appendChild(totalRow);
      scoreBreakdownSection.appendChild(scoreList);

      const riskScore = Number(session.risk_score || 0);
      if (riskScore !== totalPoints) {
        const note = document.createElement("div");
        note.className = "score-breakdown-note";
        note.textContent = "Score was adjusted or capped by the backend";
        scoreBreakdownSection.appendChild(note);
      }
    }

    wrapper.appendChild(scoreBreakdownSection);

    const stages = Array.isArray(session.stages)
      ? [...session.stages].sort((a, b) => (Number(a.order) || 0) - (Number(b.order) || 0))
      : [];

    if (stages.length > 0) {
      const killChainSection = document.createElement("div");
      killChainSection.className = "detail-section kill-chain-section";

      const killChainTitle = document.createElement("div");
      killChainTitle.className = "detail-section-title";
      killChainTitle.textContent = "Attack Progress (Kill Chain)";
      killChainSection.appendChild(killChainTitle);

      const reachedCount = stages.filter((stage) => stage.reached === true).length;
      const furthestStage = [...stages].reverse().find((stage) => stage.reached === true);
      const summary = document.createElement("div");
      summary.className = "kill-chain-summary";
      const furthestText = furthestStage && (furthestStage.label || furthestStage.stage)
        ? ` (furthest: ${furthestStage.label || furthestStage.stage})`
        : "";
      summary.textContent = `Reached ${reachedCount} of ${stages.length} stages${furthestText}`;
      killChainSection.appendChild(summary);

      const list = document.createElement("ol");
      list.className = "kill-chain-list";
      list.setAttribute("aria-label", "Attack progress kill chain");

      stages.forEach((stage) => {
        const item = document.createElement("li");
        item.className = "kill-chain-step";
        const reached = stage.reached === true;
        if (reached) item.classList.add("reached");
        if (furthestStage && (stage.order || stage.stage) === (furthestStage.order || furthestStage.stage) && reached) {
          item.classList.add("furthest");
        }

        const number = document.createElement("span");
        number.className = "kill-chain-number";
        number.textContent = String(stage.order || "");

        const label = document.createElement("span");
        label.className = "kill-chain-label";
        label.textContent = String(stage.label || stage.stage || "Unknown");

        const sr = document.createElement("span");
        sr.className = "sr-only";
        sr.textContent = reached ? "reached" : "not reached";

        item.appendChild(number);
        item.appendChild(label);
        item.appendChild(sr);
        item.setAttribute("aria-label", `${label.textContent} ${reached ? "reached" : "not reached"}`);
        list.appendChild(item);
      });

      killChainSection.appendChild(list);
      wrapper.appendChild(killChainSection);
    }

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

      const sortedAttempts = [...attempts].sort((a, b) => {
        const timeA = a && a.timestamp ? new Date(a.timestamp).getTime() : 0;
        const timeB = b && b.timestamp ? new Date(b.timestamp).getTime() : 0;
        return timeA - timeB;
      });

      sortedAttempts.forEach((att) => {
        const tr = document.createElement("tr");

        const tdU = document.createElement("td");
        tdU.textContent = String(att.username || "—");
        tr.appendChild(tdU);

        const tdP = document.createElement("td");
        tdP.textContent = String(att.password || "—");
        tr.appendChild(tdP);

        const tdR = document.createElement("td");
        const badge = document.createElement("span");
        const isSuccess = att.success === true;
        badge.className = `result-badge ${isSuccess ? "result-success" : "result-failed"}`;
        badge.textContent = isSuccess ? "Success" : "Failed";
        tdR.appendChild(badge);
        tr.appendChild(tdR);

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
      if (!container.isConnected) return;
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

    window.requestAnimationFrame(nextChar);
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

  function handleReportKeydown(event) {
    if (event.key === "Escape" && activeIncidentReport) {
      closeIncidentReport();
    }
  }

  function openIncidentReport(session) {
    if (!session) return;

    const existingReport = document.getElementById("report-view");
    if (existingReport) {
      existingReport.remove();
    }

    previousReportTitle = document.title;
    previousReportScrollY = window.scrollY || window.pageYOffset || 0;

    const snapshot = JSON.parse(JSON.stringify(session));
    activeIncidentReport = snapshot;

    const reportView = document.createElement("div");
    reportView.id = "report-view";
    reportView.className = "report-view";

    const toolbar = document.createElement("div");
    toolbar.className = "report-view-toolbar no-print";

    const backButton = document.createElement("button");
    backButton.type = "button";
    backButton.className = "btn btn-secondary btn-sm";
    backButton.textContent = "Back to dashboard";
    backButton.addEventListener("click", closeIncidentReport);

    const printButton = document.createElement("button");
    printButton.type = "button";
    printButton.className = "btn btn-primary btn-sm";
    printButton.textContent = "Print / Save as PDF";
    printButton.addEventListener("click", () => window.print());

    const toolbarRight = document.createElement("div");
    toolbarRight.className = "report-toolbar-actions";
    toolbarRight.appendChild(printButton);
    toolbar.appendChild(backButton);
    toolbar.appendChild(toolbarRight);

    reportView.appendChild(toolbar);

    const content = document.createElement("div");
    content.className = "report-view-content";

    const reportHeader = document.createElement("header");
    reportHeader.className = "report-header";

    const title = document.createElement("h1");
    title.textContent = "Honeypot Incident Report";
    reportHeader.appendChild(title);

    const generated = document.createElement("div");
    generated.className = "report-generated";
    generated.textContent = `Generated: ${formatLocalTime(new Date().toISOString())}`;
    reportHeader.appendChild(generated);

    const warning = document.createElement("div");
    warning.className = "report-warning";
    warning.textContent = "Contains sensitive data. Handle with care.";
    reportHeader.appendChild(warning);

    content.appendChild(reportHeader);

    const summarySection = document.createElement("section");
    summarySection.className = "report-section";

    const summaryTitle = document.createElement("h2");
    summaryTitle.textContent = "Summary";
    summarySection.appendChild(summaryTitle);

    const summaryTable = document.createElement("table");
    summaryTable.className = "report-table";

    const summaryRows = [
      ["Session ID", String(snapshot.session_id || "Unknown")],
      ["Source IP", String(snapshot.src_ip || "Unknown")],
      ["Start time", formatLocalTime(snapshot.start_time)],
      ["Risk score", String(Number(snapshot.risk_score || 0))],
      ["Risk level", String(snapshot.risk_level || "low")],
      ["Identified tool", `${String(snapshot.tool || "Unknown")}${snapshot.client_version ? ` (${snapshot.client_version})` : ""}${snapshot.hassh ? ` | hassh: ${snapshot.hassh}` : ""}`]
    ];

    summaryRows.forEach(([label, value]) => {
      const row = document.createElement("tr");
      const labelCell = document.createElement("th");
      labelCell.scope = "row";
      labelCell.textContent = label;
      const valueCell = document.createElement("td");
      valueCell.textContent = value;
      row.appendChild(labelCell);
      row.appendChild(valueCell);
      summaryTable.appendChild(row);
    });
    summarySection.appendChild(summaryTable);
    content.appendChild(summarySection);

    const breakdownSection = document.createElement("section");
    breakdownSection.className = "report-section";

    const breakdownTitle = document.createElement("h2");
    breakdownTitle.textContent = "Risk Score Breakdown";
    breakdownSection.appendChild(breakdownTitle);

    const breakdownList = document.createElement("div");
    breakdownList.className = "report-breakdown-list";

    const scoreEntries = Array.isArray(snapshot.score_breakdown) ? snapshot.score_breakdown : [];
    let totalPoints = 0;
    if (scoreEntries.length === 0) {
      const noData = document.createElement("p");
      noData.className = "report-empty";
      noData.textContent = "No scoring rules matched";
      breakdownList.appendChild(noData);
    } else {
      scoreEntries.forEach((entry) => {
        const line = document.createElement("div");
        line.className = "report-breakdown-row";

        const label = document.createElement("span");
        label.textContent = String(entry.label || entry.rule || "Unknown");

        const points = document.createElement("span");
        points.className = "report-breakdown-points";
        const value = Number(entry.points || 0);
        totalPoints += value;
        points.textContent = `+${value}`;

        line.appendChild(label);
        line.appendChild(points);
        breakdownList.appendChild(line);
      });

      const totalLine = document.createElement("div");
      totalLine.className = "report-breakdown-row report-breakdown-total";
      const totalLabel = document.createElement("span");
      totalLabel.textContent = "Total";
      const totalValue = document.createElement("span");
      totalValue.className = "report-breakdown-points";
      totalValue.textContent = String(Number(snapshot.risk_score || 0));
      totalLine.appendChild(totalLabel);
      totalLine.appendChild(totalValue);
      breakdownList.appendChild(totalLine);

      if (Number(snapshot.risk_score || 0) !== totalPoints) {
        const note = document.createElement("p");
        note.className = "report-note";
        note.textContent = "Score was adjusted or capped by the backend";
        breakdownList.appendChild(note);
      }
    }

    breakdownSection.appendChild(breakdownList);
    content.appendChild(breakdownSection);

    const killChainSection = document.createElement("section");
    killChainSection.className = "report-section";

    const killTitle = document.createElement("h2");
    killTitle.textContent = "Kill Chain";
    killChainSection.appendChild(killTitle);

    const stages = Array.isArray(snapshot.stages)
      ? [...snapshot.stages].sort((a, b) => (Number(a.order) || 0) - (Number(b.order) || 0))
      : [];

    if (stages.length > 0) {
      const reachedCount = stages.filter((stage) => stage.reached === true).length;
      const furthest = [...stages].reverse().find((stage) => stage.reached === true);
      const summaryText = document.createElement("p");
      summaryText.className = "report-summary-text";
      const furthestText = furthest && (furthest.label || furthest.stage)
        ? ` (furthest: ${furthest.label || furthest.stage})`
        : "";
      summaryText.textContent = `Reached ${reachedCount} of ${stages.length} stages${furthestText}`;
      killChainSection.appendChild(summaryText);

      const killTable = document.createElement("table");
      killTable.className = "report-table report-killchain-table";
      stages.forEach((stage) => {
        const row = document.createElement("tr");
        const stageName = document.createElement("th");
        stageName.scope = "row";
        stageName.textContent = `${stage.order || ""}. ${stage.label || stage.stage || "Unknown"}`;
        const status = document.createElement("td");
        status.textContent = stage.reached === true ? "Reached" : "Not reached";
        status.className = stage.reached === true ? "status-reached" : "status-not-reached";
        row.appendChild(stageName);
        row.appendChild(status);
        killTable.appendChild(row);
      });
      killChainSection.appendChild(killTable);
    }
    content.appendChild(killChainSection);

    const timelineSection = document.createElement("section");
    timelineSection.className = "report-section";

    const timelineTitle = document.createElement("h2");
    timelineTitle.textContent = "Activity Timeline";
    timelineSection.appendChild(timelineTitle);

    const attempts = Array.isArray(snapshot.login_attempts) ? [...snapshot.login_attempts] : [];
    if (attempts.length > 0) {
      const attemptsTable = document.createElement("table");
      attemptsTable.className = "report-table";
      const attemptsHead = document.createElement("thead");
      const attemptsHeadRow = document.createElement("tr");
      ["Time", "Username", "Password", "Result"].forEach((headerLabel) => {
        const cell = document.createElement("th");
        cell.textContent = headerLabel;
        attemptsHeadRow.appendChild(cell);
      });
      attemptsHead.appendChild(attemptsHeadRow);
      attemptsTable.appendChild(attemptsHead);

      const attemptsBody = document.createElement("tbody");
      attempts
        .sort((a, b) => {
          const aTime = a && a.timestamp ? new Date(a.timestamp).getTime() : 0;
          const bTime = b && b.timestamp ? new Date(b.timestamp).getTime() : 0;
          return aTime - bTime;
        })
        .forEach((attempt) => {
          const row = document.createElement("tr");
          const timeCell = document.createElement("td");
          timeCell.textContent = formatLocalTime(attempt.timestamp);
          const userCell = document.createElement("td");
          userCell.textContent = String(attempt.username || "—");
          const passCell = document.createElement("td");
          passCell.textContent = String(attempt.password || "—");
          const resultCell = document.createElement("td");
          resultCell.textContent = attempt.success === true ? "Success" : "Failed";
          row.appendChild(timeCell);
          row.appendChild(userCell);
          row.appendChild(passCell);
          row.appendChild(resultCell);
          attemptsBody.appendChild(row);
        });
      attemptsTable.appendChild(attemptsBody);
      timelineSection.appendChild(attemptsTable);
    } else {
      const noAttempts = document.createElement("p");
      noAttempts.className = "report-empty";
      noAttempts.textContent = "No login attempts recorded";
      timelineSection.appendChild(noAttempts);
    }

    const commands = Array.isArray(snapshot.commands) ? snapshot.commands : [];
    const commandList = document.createElement("ol");
    commandList.className = "report-command-list";
    commands.forEach((command, index) => {
      const item = document.createElement("li");
      item.textContent = `${index + 1}. ${command}`;
      commandList.appendChild(item);
    });
    if (commands.length === 0) {
      const noCommands = document.createElement("p");
      noCommands.className = "report-empty";
      noCommands.textContent = "No commands were run";
      commandList.appendChild(noCommands);
    }
    timelineSection.appendChild(commandList);

    content.appendChild(timelineSection);
    reportView.appendChild(content);
    document.body.appendChild(reportView);
    document.body.style.overflow = "hidden";
    document.title = `Incident Report - ${String(snapshot.session_id || "Unknown")}`;
    document.addEventListener("keydown", handleReportKeydown);
  }

  function closeIncidentReport() {
    const reportView = document.getElementById("report-view");
    if (reportView) {
      reportView.remove();
    }
    activeIncidentReport = null;
    document.body.style.overflow = "";
    document.title = previousReportTitle || "Honeypot Attack Console";
    window.scrollTo({ top: previousReportScrollY, behavior: "auto" });
    document.removeEventListener("keydown", handleReportKeydown);
  }

  /* ==========================================================================
     PDF EXPORT
     ========================================================================== */
  function showPdfExportStatus(message, persistent = false) {
    if (!el.pdfExportStatus) return;
    clearTimeout(pdfStatusTimerId);
    el.pdfExportStatus.textContent = message;
    if (!persistent) {
      pdfStatusTimerId = setTimeout(() => {
        el.pdfExportStatus.textContent = "";
      }, 4500);
    }
  }

  function hasPdfLibrary() {
    return typeof window.jspdf !== "undefined" &&
      Boolean(window.jspdf.jsPDF) &&
      Boolean(window.jspdf.jsPDF.API) &&
      typeof window.jspdf.jsPDF.API.autoTable === "function";
  }

  function getPdfLibrary() {
    if (!hasPdfLibrary()) return null;
    return new window.jspdf.jsPDF({ format: "a4", unit: "mm", orientation: "portrait" });
  }

  function pdfString(value, fallback = "—") {
    return value === null || value === undefined || value === "" ? fallback : String(value);
  }

  function pdfLocalTime(value) {
    if (!value) return "—";
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString();
  }

  function pdfDateStamp(date = new Date()) {
    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, "0");
    const day = String(date.getDate()).padStart(2, "0");
    return `${year}-${month}-${day}`;
  }

  function pdfRiskLevel(value) {
    const level = String(value || "low").toLowerCase();
    if (level === "medium") return "Medium";
    if (level === "high") return "High";
    if (level === "critical") return "Critical";
    return "Low";
  }

  function pdfRiskColor(value) {
    switch (pdfRiskLevel(value)) {
      case "Medium": return [202, 138, 4];
      case "High": return [234, 88, 12];
      case "Critical": return [220, 38, 38];
      default: return [22, 163, 74];
    }
  }

  function sessionsForPdf() {
    return lastDashboardData && Array.isArray(lastDashboardData.sessions)
      ? lastDashboardData.sessions
      : [];
  }

  function summarizePdfSessions(sessions) {
    const risks = ["Low", "Medium", "High", "Critical"];
    let highestRisk = "Low";
    let firstSeen = null;
    let lastSeen = null;

    sessions.forEach((session) => {
      const risk = pdfRiskLevel(session.risk_level);
      if (risks.indexOf(risk) > risks.indexOf(highestRisk)) highestRisk = risk;
      const date = new Date(session.start_time);
      if (!Number.isNaN(date.getTime())) {
        if (!firstSeen || date < firstSeen) firstSeen = date;
        if (!lastSeen || date > lastSeen) lastSeen = date;
      }
    });

    return {
      highestRisk,
      firstSeen: firstSeen ? firstSeen.toLocaleString() : "—",
      lastSeen: lastSeen ? lastSeen.toLocaleString() : "—"
    };
  }

  function sortPdfSessions(sessions) {
    return [...sessions].sort((a, b) => {
      const timeA = new Date(a.start_time).getTime();
      const timeB = new Date(b.start_time).getTime();
      const validA = Number.isNaN(timeA) ? -Infinity : timeA;
      const validB = Number.isNaN(timeB) ? -Infinity : timeB;
      return validB - validA;
    });
  }

  function addPdfHeader(doc, title, generatedAt) {
    const pageWidth = doc.internal.pageSize.getWidth();
    const margin = 14;
    doc.setTextColor(25, 35, 48);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(16);
    const titleLines = doc.splitTextToSize(title, pageWidth - margin * 2);
    doc.text(titleLines, margin, 18);

    let y = 18 + titleLines.length * 7;
    doc.setFont("helvetica", "normal");
    doc.setFontSize(9);
    doc.text(`Generated: ${generatedAt.toLocaleString()}`, margin, y);
    y += 5;
    doc.text("Contains sensitive data. Handle with care.", margin, y);
    return y + 8;
  }

  function addPdfSummaryTable(doc, title, rows, startY) {
    doc.setFont("helvetica", "bold");
    doc.setFontSize(11);
    doc.setTextColor(25, 35, 48);
    doc.text(title, 14, startY);
    doc.autoTable({
      startY: startY + 3,
      head: [["Field", "Value"]],
      body: rows,
      theme: "grid",
      margin: { left: 14, right: 14, bottom: 18 },
      styles: { font: "helvetica", fontSize: 9, textColor: [35, 42, 52], overflow: "linebreak", cellPadding: 2 },
      headStyles: { fillColor: [230, 235, 242], textColor: [25, 35, 48] },
      rowPageBreak: "auto"
    });
    return doc.lastAutoTable.finalY + 9;
  }

  function writePdfParagraph(doc, text, y, color = [35, 42, 52], fontSize = 9) {
    const margin = 14;
    const width = doc.internal.pageSize.getWidth() - margin * 2;
    doc.setFont("helvetica", "normal");
    doc.setFontSize(fontSize);
    doc.setTextColor(...color);
    const lines = doc.splitTextToSize(String(text), width);
    const lineHeight = 4.5;
    if (y + lines.length * lineHeight > doc.internal.pageSize.getHeight() - 18) {
      doc.addPage();
      y = 16;
    }
    doc.text(lines, margin, y);
    return y + lines.length * lineHeight + 2;
  }

  function addPdfSessions(doc, sessions, startY) {
    let y = startY;
    const sortedSessions = sortPdfSessions(sessions);

    sortedSessions.forEach((session) => {
      const risk = pdfRiskLevel(session.risk_level);
      const heading = `Session ${pdfString(session.session_id)} | ${pdfLocalTime(session.start_time)}`;
      const headingLines = doc.splitTextToSize(heading, doc.internal.pageSize.getWidth() - 28);
      if (y + headingLines.length * 5 + 13 > doc.internal.pageSize.getHeight() - 18) {
        doc.addPage();
        y = 16;
      }
      doc.setDrawColor(...pdfRiskColor(risk));
      doc.setLineWidth(0.8);
      doc.line(14, y - 2, 20, y - 2);
      doc.setFont("helvetica", "bold");
      doc.setFontSize(10);
      doc.setTextColor(25, 35, 48);
      doc.text(headingLines, 22, y);
      y += headingLines.length * 5 + 1;
      y = writePdfParagraph(
        doc,
        `Risk score: ${pdfString(session.risk_score, "0")} | Risk level: ${risk}`,
        y,
        [35, 42, 52]
      );

      const commands = Array.isArray(session.commands) ? session.commands : [];
      doc.autoTable({
        startY: y,
        head: [["Commands (in order)"]],
        body: commands.length ? commands.map((command) => [pdfString(command, "")]) : [["No commands were run"]],
        theme: "grid",
        margin: { left: 14, right: 14, bottom: 18 },
        styles: { font: "helvetica", fontSize: 9, textColor: [35, 42, 52], overflow: "linebreak", cellPadding: 2 },
        headStyles: { fillColor: [230, 235, 242], textColor: [25, 35, 48] },
        rowPageBreak: "auto"
      });
      y = doc.lastAutoTable.finalY + 3;

      const attempts = Array.isArray(session.login_attempts) ? session.login_attempts : [];
      doc.autoTable({
        startY: y,
        head: [["Username", "Password", "Result", "Time"]],
        body: attempts.length
          ? attempts.map((attempt) => [
            pdfString(attempt.username),
            pdfString(attempt.password),
            attempt.success === true ? "Success" : "Failed",
            pdfLocalTime(attempt.timestamp)
          ])
          : [["No login attempts recorded", "", "", ""]],
        theme: "grid",
        margin: { left: 14, right: 14, bottom: 18 },
        styles: { font: "helvetica", fontSize: 9, textColor: [35, 42, 52], overflow: "linebreak", cellPadding: 2 },
        headStyles: { fillColor: [230, 235, 242], textColor: [25, 35, 48] },
        rowPageBreak: "auto"
      });
      y = doc.lastAutoTable.finalY + 9;
    });

    return y;
  }

  function finishPdf(doc, filename) {
    const pageCount = doc.internal.getNumberOfPages();
    for (let page = 1; page <= pageCount; page += 1) {
      doc.setPage(page);
      doc.setFont("helvetica", "normal");
      doc.setFontSize(9);
      doc.setTextColor(90, 98, 108);
      doc.text(
        `Report generated from the sessions available in the dashboard at export time.  |  Page ${page} of ${pageCount}`,
        14,
        doc.internal.pageSize.getHeight() - 8
      );
    }
    doc.save(filename);
  }

  function createAllIpsPdf(sessions) {
    const doc = getPdfLibrary();
    if (!doc) {
      showPdfExportStatus("Could not load the PDF tool. Please check your connection.", true);
      return;
    }

    const generatedAt = new Date();
    const groups = new Map();
    sessions.forEach((session) => {
      const ip = typeof session.src_ip === "string" ? session.src_ip : "";
      if (!groups.has(ip)) groups.set(ip, []);
      groups.get(ip).push(session);
    });

    const ipGroups = Array.from(groups.entries())
      .map(([ip, ipSessions]) => ({ ip, sessions: ipSessions, summary: summarizePdfSessions(ipSessions) }))
      .sort((a, b) => b.sessions.length - a.sessions.length || a.ip.localeCompare(b.ip));

    let y = addPdfHeader(doc, "Honeypot Attack Report: All IPs", generatedAt);
    y = addPdfSummaryTable(doc, "Summary", [
      ["Total IPs", String(ipGroups.length)],
      ["Total sessions", String(sessions.length)]
    ], y);

    doc.autoTable({
      startY: y,
      head: [["IP", "Sessions", "Highest risk", "First seen", "Last seen"]],
      body: ipGroups.map((group) => [
        group.ip || "Unknown IP",
        String(group.sessions.length),
        group.summary.highestRisk,
        group.summary.firstSeen,
        group.summary.lastSeen
      ]),
      theme: "grid",
      margin: { left: 14, right: 14, bottom: 18 },
      styles: { font: "helvetica", fontSize: 9, textColor: [35, 42, 52], overflow: "linebreak", cellPadding: 2 },
      headStyles: { fillColor: [230, 235, 242], textColor: [25, 35, 48] },
      rowPageBreak: "auto"
    });

    ipGroups.forEach((group) => {
      doc.addPage();
      const sectionY = addPdfHeader(doc, `IP: ${group.ip || "Unknown IP"}`, generatedAt);
      doc.setDrawColor(...pdfRiskColor(group.summary.highestRisk));
      doc.setLineWidth(1);
      doc.line(14, sectionY - 3, 22, sectionY - 3);
      addPdfSessions(doc, group.sessions, sectionY + 3);
    });

    finishPdf(doc, `honeypot-report-all-ips-${pdfDateStamp(generatedAt)}.pdf`);
  }

  function exportIpPdf(ip) {
    if (!lastDashboardData || !Array.isArray(lastDashboardData.sessions)) {
      showPdfExportStatus("No attack data to export yet.");
      return;
    }
    const sessions = sessionsForPdf().filter((session) => session.src_ip === ip);
    if (!sessions.length) {
      showPdfExportStatus("No attack data to export yet.");
      return;
    }

    const doc = getPdfLibrary();
    if (!doc) {
      showPdfExportStatus("Could not load the PDF tool. Please check your connection.", true);
      return;
    }

    const generatedAt = new Date();
    const summary = summarizePdfSessions(sessions);
    let y = addPdfHeader(doc, `Honeypot Attack Report: ${ip}`, generatedAt);
    y = addPdfSummaryTable(doc, "Summary", [
      ["IP", ip],
      ["Number of sessions", String(sessions.length)],
      ["Highest risk level", summary.highestRisk],
      ["First seen", summary.firstSeen],
      ["Last seen", summary.lastSeen]
    ], y);
    addPdfSessions(doc, sessions, y);

    const safeIp = String(ip).replace(/[^A-Za-z0-9.-]/g, "_");
    finishPdf(doc, `honeypot-report-${safeIp}-${pdfDateStamp(generatedAt)}.pdf`);
  }

  function initPdfExport() {
    if (document.documentElement.dataset.pdfToolUnavailable === "true" || !hasPdfLibrary()) {
      showPdfExportStatus("Could not load the PDF tool. Please check your connection.", true);
    }
    el.exportPdfBtn.addEventListener("click", () => {
      const sessions = sessionsForPdf();
      if (!sessions.length) {
        showPdfExportStatus("No attack data to export yet.");
        return;
      }
      try {
        createAllIpsPdf(sessions);
      } catch (error) {
        showPdfExportStatus("Could not generate the PDF. Please try again.", true);
      }
    });
  }

  /* ==========================================================================
     INITIALIZATION ON DOMContentLoaded
     ========================================================================== */
  document.addEventListener("DOMContentLoaded", () => {
    initMascot();
    initNavigation();
    initPdfExport();
    initAuth();
  });
})();
