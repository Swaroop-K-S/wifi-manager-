/**
 * AETHER SHIELD // NETGOD
 * Core JavaScript Controller: WebSockets, Chart.js, Realtime Telemetry, Guest Network, Connection Diagnostics & God Mode
 */

// Application State
let appState = {
  gatewayIp: '192.168.1.1',
  localIp: '192.168.1.39',
  devices: [],
  primaryDevices: [],
  guestDevices: [],
  activities: [],
  guestActivities: [],
  guestStats: {},
  guestConfig: {},
  blacklistRules: [],
  selectedDeviceMac: null,
  activeFilter: 'all',
  searchQuery: '',
  killswitchActive: false,
  godSchedules: []
};

// DOM Cache
const DOM = {
  headerGatewayIp: document.getElementById('header-gateway-ip'),
  headerLocalIp: document.getElementById('header-local-ip'),
  wsStatusText: document.getElementById('ws-status-text'),
  btnRescan: document.getElementById('btn-rescan'),
  btnPhoneQr: document.getElementById('btn-phone-qr'),
  btnKillswitch: document.getElementById('btn-killswitch'),
  killswitchText: document.getElementById('killswitch-text'),

  kpiDlSpeed: document.getElementById('kpi-dl-speed'),
  kpiUlSpeed: document.getElementById('kpi-ul-speed'),
  kpiDlTotal: document.getElementById('kpi-dl-total'),
  kpiUlTotal: document.getElementById('kpi-ul-total'),
  kpiDevicesCount: document.getElementById('kpi-devices-count'),
  kpiBlockedCount: document.getElementById('kpi-blocked-count'),
  kpiGuestCountPill: document.getElementById('kpi-guest-count-pill'),
  kpiRulesCount: document.getElementById('kpi-rules-count'),
  kpiDeviceAvatars: document.getElementById('kpi-device-avatars'),
  barDlFill: document.getElementById('bar-dl-fill'),
  barUlFill: document.getElementById('bar-ul-fill'),

  tabButtons: document.querySelectorAll('.tab-btn, .mobile-nav-btn'),
  tabContents: document.querySelectorAll('.tab-content'),
  tabBadgeDevices: document.getElementById('tab-badge-devices'),
  tabBadgeGuests: document.getElementById('tab-badge-guests'),

  devicesContainer: document.getElementById('devices-container'),
  deviceSearch: document.getElementById('device-search'),
  filterChips: document.querySelectorAll('.filter-chip'),
  btnAddCustomDev: document.getElementById('btn-add-custom-dev'),

  btnToggleGuestNet: document.getElementById('btn-toggle-guest-net'),
  btnIsolateGuest: document.getElementById('btn-isolate-guest'),
  btnKickAllGuests: document.getElementById('btn-kick-all-guests'),
  guestStatClients: document.getElementById('guest-stat-clients'),
  guestStatSpeed: document.getElementById('guest-stat-speed'),
  guestStatBytes: document.getElementById('guest-stat-bytes'),
  guestStatCap: document.getElementById('guest-stat-cap'),
  guestDevicesContainer: document.getElementById('guest-devices-container'),
  guestActivityTbody: document.getElementById('guest-activity-tbody'),

  activityTableBody: document.getElementById('activity-stream-tbody'),
  activitySearch: document.getElementById('activity-search'),
  activityDeviceFilter: document.getElementById('activity-device-filter'),
  activityCategoryFilter: document.getElementById('activity-category-filter'),
  btnClearStream: document.getElementById('btn-clear-stream'),

  formAddRule: document.getElementById('form-add-rule'),
  ruleTarget: document.getElementById('rule-target'),
  ruleReason: document.getElementById('rule-reason'),
  rulesTbody: document.getElementById('rules-tbody'),
  presetButtons: document.querySelectorAll('.preset-btn'),

  leaderboardContainer: document.getElementById('leaderboard-container'),

  deviceModal: document.getElementById('device-modal'),
  modalClose: document.getElementById('modal-close'),
  modalAvatar: document.getElementById('modal-avatar'),
  modalDeviceName: document.getElementById('modal-device-name'),
  modalDeviceIp: document.getElementById('modal-device-ip'),
  modalDeviceMac: document.getElementById('modal-device-mac'),
  modalSelectDevType: document.getElementById('modal-select-devtype'),
  modalConnType: document.getElementById('modal-conn-type'),
  modalBandChannel: document.getElementById('modal-band-channel'),
  modalLinkRate: document.getElementById('modal-link-rate'),
  modalSignal: document.getElementById('modal-signal'),
  modalTotalBytes: document.getElementById('modal-total-bytes'),
  modalBtnPause: document.getElementById('modal-btn-pause'),
  modalBtnBlock: document.getElementById('modal-btn-block'),
  modalBtnSwitchNet: document.getElementById('modal-btn-switch-net'),
  modalHistoryContainer: document.getElementById('modal-history-container'),

  // Super God Mode DOM elements
  hudBand: document.getElementById('hud-band'),
  hudNodesCount: document.getElementById('hud-nodes-count'),
  sentinelDeviceList: document.getElementById('sentinel-device-list'),
  godSchedulesList: document.getElementById('god-schedules-list'),
  modalLagSlider: document.getElementById('modal-lag-slider'),
  modalLagValue: document.getElementById('modal-lag-value'),
  modalSentinelApp: document.getElementById('modal-sentinel-app'),
  modalSentinelConfidence: document.getElementById('modal-sentinel-confidence'),
  presetLagButtons: document.querySelectorAll('.preset-lag-btn'),

  // Hardware Brand & Model Identifier elements
  modalBrandBadge: document.getElementById('modal-brand-badge'),
  modalInputBrand: document.getElementById('modal-input-brand'),
  modalInputModel: document.getElementById('modal-input-model'),
  modalBtnSaveIdentify: document.getElementById('modal-btn-save-identify'),
  presetModelButtons: document.querySelectorAll('.preset-model-btn'),

  addDeviceModal: document.getElementById('add-device-modal'),
  addDeviceClose: document.getElementById('add-device-close'),
  formAddDevice: document.getElementById('form-add-device'),

  qrModal: document.getElementById('qr-modal'),
  qrModalClose: document.getElementById('qr-modal-close'),
  popupMobileUrl: document.getElementById('popup-mobile-url'),
  popupQrcodeBox: document.getElementById('popup-qrcode-box'),
  qrcodeBox: document.getElementById('qrcode-box'),
  mobileUrlText: document.getElementById('mobile-url-text'),
  mobileGuideUrl: document.getElementById('mobile-guide-url'),
  btnCopyUrl: document.getElementById('btn-copy-url'),

  toastContainer: document.getElementById('toast-container')
};

// Charts
let bandwidthChart = null;
let categoryChart = null;
const MAX_CHART_POINTS = 20;

document.addEventListener('DOMContentLoaded', () => {
  initTabs();
  initModals();
  initCharts();
  initFirewallPresets();
  initGuestControls();
  initQrCode();
  initTopologyRadar();
  initLagSwitch();
  initDeviceIdentifier();
  connectWebSocket();

  // Self-identify browser / mobile phone client
  if (navigator.userAgent) {
    fetch('/api/identify-me', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user_agent: navigator.userAgent })
    }).catch(() => {});
  }

  if (DOM.deviceSearch) {
    DOM.deviceSearch.addEventListener('input', (e) => {
      appState.searchQuery = e.target.value.toLowerCase();
      renderPrimaryDevices();
      renderGuestDevices();
    });
  }

  DOM.filterChips.forEach(chip => {
    chip.addEventListener('click', () => {
      DOM.filterChips.forEach(c => c.classList.remove('active'));
      chip.classList.add('active');
      appState.activeFilter = chip.dataset.filter;
      renderPrimaryDevices();
    });
  });

  if (DOM.btnRescan) {
    DOM.btnRescan.addEventListener('click', async () => {
      showToast('⚡ Running physical subnet sweep...', 'cyan');
      try {
        await fetch('/api/scan', { method: 'POST' });
        showToast('✓ Subnet scan finished. Active hosts updated.', 'emerald');
      } catch (err) {
        showToast('Error during scan: ' + err.message, 'crimson');
      }
    });
  }

  if (DOM.btnKillswitch) {
    DOM.btnKillswitch.addEventListener('click', async () => {
      try {
        const res = await fetch('/api/godmode/killswitch', { method: 'POST' });
        const data = await res.json();
        appState.killswitchActive = data.killswitch_active;
        if (appState.killswitchActive) {
          DOM.btnKillswitch.classList.add('killswitch-active');
          DOM.killswitchText.textContent = 'RESTORE NETWORK';
          showToast('⚠️ GOD MODE ACTIVATED: Non-admin devices frozen!', 'crimson');
        } else {
          DOM.btnKillswitch.classList.remove('killswitch-active');
          DOM.killswitchText.textContent = 'FREEZE NETWORK';
          showToast('✓ Network access restored to all devices', 'emerald');
        }
      } catch (err) {
        showToast('Killswitch error: ' + err.message, 'crimson');
      }
    });
  }

  if (DOM.formAddRule) {
    DOM.formAddRule.addEventListener('submit', async (e) => {
      e.preventDefault();
      const ruleType = document.querySelector('input[name="rule_type"]:checked').value;
      const target = DOM.ruleTarget.value.trim();
      const reason = DOM.ruleReason.value.trim() || 'Admin God Mode Policy';

      if (!target) return;
      try {
        const res = await fetch('/api/firewall/rule', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ rule_type: ruleType, target, reason })
        });
        if (res.ok) {
          showToast(`🛡️ Block rule enforced for: ${target}`, 'emerald');
          DOM.ruleTarget.value = '';
          DOM.ruleReason.value = '';
        } else {
          const err = await res.json();
          showToast(err.detail || 'Failed to add rule', 'crimson');
        }
      } catch (err) {
        showToast('Network error adding rule', 'crimson');
      }
    });
  }

  if (DOM.btnCopyUrl) {
    DOM.btnCopyUrl.addEventListener('click', () => {
      const url = DOM.mobileUrlText.textContent;
      navigator.clipboard.writeText(url);
      showToast('Copied URL to clipboard: ' + url, 'cyan');
    });
  }
});

function initGuestControls() {
  if (DOM.btnToggleGuestNet) {
    DOM.btnToggleGuestNet.addEventListener('click', async () => {
      try {
        const res = await fetch('/api/guest/toggle', { method: 'POST' });
        const data = await res.json();
        showToast(data.message, data.is_enabled ? 'emerald' : 'amber');
      } catch (err) {
        showToast('Failed to toggle Guest Wi-Fi', 'crimson');
      }
    });
  }

  if (DOM.btnIsolateGuest) {
    DOM.btnIsolateGuest.addEventListener('click', async () => {
      try {
        const res = await fetch('/api/guest/isolate', { method: 'POST' });
        const data = await res.json();
        showToast(data.message, data.is_isolated ? 'emerald' : 'amber');
      } catch (err) {
        showToast('Failed to toggle Guest LAN Isolation', 'crimson');
      }
    });
  }

  if (DOM.btnKickAllGuests) {
    DOM.btnKickAllGuests.addEventListener('click', async () => {
      if (!confirm('Kick and disconnect ALL guest devices from the Wi-Fi?')) return;
      try {
        const res = await fetch('/api/guest/kickall', { method: 'POST' });
        const data = await res.json();
        showToast(data.message, 'crimson');
      } catch (err) {
        showToast('Failed to kick guest devices', 'crimson');
      }
    });
  }
}

function initTabs() {
  DOM.tabButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const targetTabId = btn.dataset.tab;
      DOM.tabButtons.forEach(b => b.classList.toggle('active', b.dataset.tab === targetTabId));
      DOM.tabContents.forEach(tab => tab.classList.toggle('active', tab.id === targetTabId));

      if (targetTabId === 'tab-analytics') {
        setTimeout(() => {
          if (bandwidthChart) bandwidthChart.resize();
          if (categoryChart) categoryChart.resize();
        }, 50);
      } else if (targetTabId === 'tab-godmode') {
        setTimeout(() => {
          if (window.topologyRadar) {
            window.topologyRadar.resize();
            window.topologyRadar.updateNodes(appState.devices, appState.gatewayIp);
          }
        }, 60);
      }
    });
  });
}

function initModals() {
  if (DOM.modalClose) {
    DOM.modalClose.addEventListener('click', () => DOM.deviceModal.classList.remove('open'));
  }
  DOM.deviceModal.querySelector('.modal-backdrop').addEventListener('click', () => DOM.deviceModal.classList.remove('open'));

  if (DOM.btnAddCustomDev) {
    DOM.btnAddCustomDev.addEventListener('click', () => DOM.addDeviceModal.classList.add('open'));
  }
  if (DOM.addDeviceClose) {
    DOM.addDeviceClose.addEventListener('click', () => DOM.addDeviceModal.classList.remove('open'));
  }
  DOM.addDeviceModal.querySelector('.modal-backdrop').addEventListener('click', () => DOM.addDeviceModal.classList.remove('open'));

  DOM.formAddDevice.addEventListener('submit', async (e) => {
    e.preventDefault();
    const payload = {
      ip: document.getElementById('cust-ip').value.trim(),
      mac: document.getElementById('cust-mac').value.trim(),
      name: document.getElementById('cust-name').value.trim(),
      device_type: document.getElementById('cust-type').value,
      network_type: document.getElementById('cust-network').value
    };
    try {
      const res = await fetch('/api/devices/custom', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      if (res.ok) {
        showToast(`Device ${payload.name} registered`, 'emerald');
        DOM.addDeviceModal.classList.remove('open');
        DOM.formAddDevice.reset();
      }
    } catch (err) {
      showToast('Error registering device', 'crimson');
    }
  });

  if (DOM.btnPhoneQr) {
    DOM.btnPhoneQr.addEventListener('click', () => DOM.qrModal.classList.add('open'));
  }
  if (DOM.qrModalClose) {
    DOM.qrModalClose.addEventListener('click', () => DOM.qrModal.classList.remove('open'));
  }
  DOM.qrModal.querySelector('.modal-backdrop').addEventListener('click', () => DOM.qrModal.classList.remove('open'));

  DOM.modalBtnBlock.addEventListener('click', async () => {
    if (!appState.selectedDeviceMac) return;
    await toggleDeviceBlock(appState.selectedDeviceMac);
    refreshModalDetails(appState.selectedDeviceMac);
  });

  DOM.modalBtnPause.addEventListener('click', async () => {
    if (!appState.selectedDeviceMac) return;
    await toggleDevicePause(appState.selectedDeviceMac);
    refreshModalDetails(appState.selectedDeviceMac);
  });

  DOM.modalBtnSwitchNet.addEventListener('click', async () => {
    if (!appState.selectedDeviceMac) return;
    const dev = appState.devices.find(d => d.mac === appState.selectedDeviceMac);
    if (!dev) return;
    const newNet = dev.network_type === 'guest' ? 'primary' : 'guest';
    await switchDeviceNetwork(dev.mac, newNet);
    refreshModalDetails(dev.mac);
  });

  // Device Classification dropdown change listener
  if (DOM.modalSelectDevType) {
    DOM.modalSelectDevType.addEventListener('change', async (e) => {
      if (!appState.selectedDeviceMac) return;
      const newType = e.target.value;
      try {
        await fetch(`/api/devices/${appState.selectedDeviceMac}/type`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ device_type: newType })
        });
        showToast(`Device type updated to ${newType.toUpperCase()}`, 'cyan');
        const d = appState.devices.find(x => x.mac === appState.selectedDeviceMac);
        if (d) d.device_type = newType;
        DOM.modalAvatar.textContent = getDeviceIcon(newType);
        renderPrimaryDevices();
        renderGuestDevices();
      } catch (err) {
        showToast('Error updating device type', 'crimson');
      }
    });
  }
}

function connectWebSocket() {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${protocol}//${window.location.host}/ws`;
  const ws = new WebSocket(wsUrl);

  ws.onopen = () => {
    DOM.wsStatusText.textContent = 'REALTIME SYNC';
    DOM.wsStatusText.parentElement.classList.add('status-live');
  };

  ws.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      updateTelemetry(data);
    } catch (err) {
      console.error('WS parse error:', err);
    }
  };

  ws.onclose = () => {
    DOM.wsStatusText.textContent = 'RECONNECTING...';
    DOM.wsStatusText.parentElement.classList.remove('status-live');
    setTimeout(connectWebSocket, 2000);
  };
}

function updateTelemetry(data) {
  appState.gatewayIp = data.gateway_ip;
  appState.localIp = data.local_ip;
  appState.devices = data.devices || [];
  appState.primaryDevices = data.primary_devices || [];
  appState.guestDevices = data.guest_devices || [];
  appState.activities = data.recent_activity || [];
  appState.guestActivities = data.guest_activity || [];
  appState.guestStats = data.guest_stats || {};
  appState.guestConfig = data.guest_config || {};
  appState.blacklistRules = data.blacklist_rules || [];
  appState.godSchedules = data.god_schedules || [];

  if (DOM.headerGatewayIp) DOM.headerGatewayIp.textContent = data.gateway_ip;
  if (DOM.headerLocalIp) DOM.headerLocalIp.textContent = data.local_ip;

  if (DOM.kpiDlSpeed) DOM.kpiDlSpeed.textContent = data.total_download_mbps.toFixed(1);
  if (DOM.kpiUlSpeed) DOM.kpiUlSpeed.textContent = data.total_upload_mbps.toFixed(1);
  if (DOM.kpiDlTotal) DOM.kpiDlTotal.textContent = `${data.total_download_gb.toFixed(3)} GB`;
  if (DOM.kpiUlTotal) DOM.kpiUlTotal.textContent = `${data.total_upload_gb.toFixed(3)} GB`;
  if (DOM.kpiDevicesCount) DOM.kpiDevicesCount.textContent = data.active_devices_count;
  if (DOM.kpiBlockedCount) DOM.kpiBlockedCount.textContent = `${data.blocked_devices_count} Blocked`;
  if (DOM.kpiGuestCountPill) DOM.kpiGuestCountPill.textContent = `${appState.guestDevices.length} Guests`;
  if (DOM.kpiRulesCount) DOM.kpiRulesCount.textContent = appState.blacklistRules.length;

  if (DOM.hudNodesCount) DOM.hudNodesCount.textContent = `${appState.devices.length} Tracked`;
  if (window.topologyRadar) {
    window.topologyRadar.updateNodes(appState.devices, appState.gatewayIp);
  }

  if (DOM.tabBadgeDevices) DOM.tabBadgeDevices.textContent = appState.primaryDevices.length;
  if (DOM.tabBadgeGuests) DOM.tabBadgeGuests.textContent = appState.guestDevices.length;

  if (DOM.guestStatClients) DOM.guestStatClients.textContent = `${appState.guestDevices.length} Devices`;
  if (DOM.guestStatSpeed) DOM.guestStatSpeed.textContent = `${(appState.guestStats.download_mbps || 0).toFixed(1)} Mbps`;
  const guestTotalGb = ((appState.guestStats.total_download_gb || 0) + (appState.guestStats.total_upload_gb || 0)).toFixed(2);
  if (DOM.guestStatBytes) DOM.guestStatBytes.textContent = `${guestTotalGb} GB Total`;
  if (DOM.guestStatCap) DOM.guestStatCap.textContent = `${appState.guestConfig.bandwidth_cap_mbps || 10} Mbps Cap`;

  if (DOM.btnIsolateGuest) {
    const isIso = !!appState.guestConfig.is_isolated;
    DOM.btnIsolateGuest.textContent = isIso ? 'LAN ISOLATION: ACTIVE' : 'LAN ISOLATION: OFF';
    DOM.btnIsolateGuest.className = isIso ? 'cyber-btn btn-phone' : 'cyber-btn btn-secondary';
  }

  const dlPct = Math.min(100, Math.max(8, (data.total_download_mbps / 120) * 100));
  const ulPct = Math.min(100, Math.max(8, (data.total_upload_mbps / 40) * 100));
  if (DOM.barDlFill) DOM.barDlFill.style.width = `${dlPct}%`;
  if (DOM.barUlFill) DOM.barUlFill.style.width = `${ulPct}%`;

  renderMiniAvatars();
  renderPrimaryDevices();
  renderGuestDevices();
  renderActivityStream();
  renderGuestActivityStream();
  renderLeaderboard();
  renderFirewallRules();
  renderSentinelFeed();
  renderGodSchedules();
  updateChartData(data.total_download_mbps, data.total_upload_mbps, data.timestamp);
}

function renderMiniAvatars() {
  if (!DOM.kpiDeviceAvatars) return;
  DOM.kpiDeviceAvatars.innerHTML = appState.devices.slice(0, 6).map(d => {
    const icon = getDeviceIcon(d.device_type);
    return `<div class="mini-avatar" title="${d.custom_name || d.hostname}">${icon}</div>`;
  }).join('');
}

function renderPrimaryDevices() {
  if (!DOM.devicesContainer) return;
  renderDeviceCards(DOM.devicesContainer, appState.primaryDevices, 'primary');
}

function renderGuestDevices() {
  if (!DOM.guestDevicesContainer) return;
  if (appState.guestDevices.length === 0) {
    DOM.guestDevicesContainer.innerHTML = `
      <div style="grid-column: 1 / -1; padding: 35px; text-align: center; color: #94a3b8; background: rgba(0,0,0,0.2); border-radius: var(--radius-md); border: 1px dashed var(--border-subtle);">
        <p style="font-size: 1rem; font-weight: 600; color: #fff; margin-bottom: 6px;">No Guest Devices Currently Connected</p>
        <p style="font-size: 0.8rem;">When visitors connect to your guest Wi-Fi hotspot, they will automatically appear here with connection frequency band and live speed.</p>
      </div>
    `;
    return;
  }
  renderDeviceCards(DOM.guestDevicesContainer, appState.guestDevices, 'guest');
}

function renderDeviceCards(container, list, networkType) {
  let filtered = list.filter(d => {
    if (d.ip === '127.0.0.1' || d.mac === 'dev:1' || (d.ip && d.ip.startsWith('169.254'))) return false;

    if (appState.activeFilter === 'blocked') {
      if (!d.is_blocked) return false;
    } else if (appState.activeFilter !== 'all') {
      if (d.device_type !== appState.activeFilter) return false;
    }

    if (appState.searchQuery) {
      const q = appState.searchQuery;
      const name = (d.custom_name || d.hostname || '').toLowerCase();
      const ip = (d.ip || '').toLowerCase();
      const mac = (d.mac || '').toLowerCase();
      const vendor = (d.vendor || '').toLowerCase();
      if (!name.includes(q) && !ip.includes(q) && !mac.includes(q) && !vendor.includes(q)) return false;
    }
    return true;
  });

  if (filtered.length === 0) {
    container.innerHTML = `<div style="grid-column: 1 / -1; padding: 30px; text-align: center; color: #64748b;">No devices matching filter.</div>`;
    return;
  }

  container.innerHTML = filtered.map(d => {
    const isLocal = d.ip === appState.localIp;
    const isGateway = d.ip === appState.gatewayIp;
    const isBlocked = !!d.is_blocked;
    const isPaused = !!d.is_paused;
    const icon = getDeviceIcon(d.device_type);
    const typeLabel = getDeviceTypeLabel(d.device_type);

    let statusPill = `<span class="dev-status-pill status-online">ONLINE</span>`;
    let cardClass = 'device-card';
    if (isBlocked) {
      statusPill = `<span class="dev-status-pill status-blocked">BLOCKED</span>`;
      cardClass += ' card-blocked';
    } else if (isPaused) {
      statusPill = `<span class="dev-status-pill status-paused">PAUSED</span>`;
      cardClass += ' card-paused';
    } else if (networkType === 'guest') {
      statusPill = `<span class="dev-status-pill" style="background: rgba(139,92,246,0.25); color: #c4b5fd;">GUEST</span>`;
      cardClass += ' card-guest';
    } else if (isLocal) {
      statusPill = `<span class="dev-status-pill" style="background: rgba(6,182,212,0.2); color: #38bdf8;">ADMIN HOST</span>`;
      cardClass += ' card-local';
    }

    const dlKbps = (d.current_dl_kbps || 0).toFixed(0);
    const ulKbps = (d.current_ul_kbps || 0).toFixed(0);
    const totalGB = ((d.total_download_bytes + d.total_upload_bytes) / (1024**3)).toFixed(2);
    const targetNet = d.network_type === 'guest' ? 'primary' : 'guest';
    const switchLabel = d.network_type === 'guest' ? 'TO PRIMARY' : 'TO GUEST';

    // Hardware Company / Brand & Exact Model Identification
    const brand = d.brand || (d.vendor && d.vendor.toLowerCase().includes('samsung') ? 'Samsung' : (d.vendor && d.vendor.toLowerCase().includes('apple') ? 'Apple' : ''));
    const modelName = d.model_name || '';
    let displayName = d.custom_name || d.hostname;
    if (!displayName || displayName.includes('Client (') || displayName.includes('Mobile Phone (')) {
      if (modelName) {
        displayName = (brand && !modelName.toLowerCase().includes(brand.toLowerCase())) ? `${brand} ${modelName}` : modelName;
      } else {
        displayName = d.hostname || d.ip;
      }
    }

    // Connection Band & PHY Link Speed
    const connType = d.connection_type || 'Wi-Fi 5 (802.11ac)';
    const wifiBand = d.wifi_band || '5 GHz';
    const linkRate = d.link_rate_mbps || 866.7;
    const channel = d.channel || 'Ch 153';
    const signalPct = d.signal_percent || 92;
    const signalDbm = d.signal_dbm || -45;

    return `
      <div class="${cardClass}" data-mac="${d.mac}">
        <div>
          <div class="dev-top">
            <div class="dev-identity">
              <div class="dev-avatar">${icon}</div>
              <div class="dev-titles">
                <div style="display: flex; align-items: center; gap: 6px; flex-wrap: wrap;">
                  <span class="dev-name">${escapeHtml(displayName)}</span>
                  ${brand ? `<span class="brand-pill ${brand.toLowerCase().replace(/[^a-z0-9]/g, '')}">${brand.toUpperCase()}</span>` : ''}
                </div>
                <div style="display: flex; align-items: center; gap: 6px; flex-wrap: wrap; margin-top: 2px;">
                  <span class="dev-vendor">${escapeHtml(d.vendor || 'Physical Client')}</span>
                  ${modelName ? `<span class="model-badge">📱 ${escapeHtml(modelName)}</span>` : ''}
                </div>
              </div>
            </div>
            ${statusPill}
          </div>

          <!-- Connection Diagnostic Bar -->
          <div style="display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 10px;">
            <span class="shield-tag" style="background: rgba(6,182,212,0.12); color: #38bdf8; border-color: rgba(6,182,212,0.3); font-weight: 700;">
              ${icon} ${typeLabel}
            </span>
            <span class="shield-tag" style="background: rgba(139,92,246,0.12); color: #c4b5fd; border-color: rgba(139,92,246,0.3);">
              ⚡ ${wifiBand} (${channel})
            </span>
            <span class="shield-tag" style="background: rgba(16,185,129,0.12); color: #6ee7b7; border-color: rgba(16,185,129,0.3);">
              📶 ${signalPct}% (${linkRate} Mbps) • ⏱️ ${d.latency_ms || 2}ms
            </span>
          </div>

          <div class="dev-meta-row">
            <span class="ip-val mono">${d.ip}</span>
            <span class="mac-val mono">${d.mac}</span>
          </div>

          <!-- Sentinel AI Behavioral Prediction Badge -->
          <div class="sentinel-badge-strip" style="display: flex; align-items: center; justify-content: space-between; background: rgba(15, 23, 42, 0.65); border: 1px solid rgba(6, 182, 212, 0.25); border-radius: 8px; padding: 5px 10px; margin-bottom: 8px;">
            <span style="font-size: 0.72rem; color: #94a3b8; display: flex; align-items: center; gap: 5px;">
              <span>${(d.sentinel && d.sentinel.icon) || '📱'}</span>
              <span style="color: #38bdf8; font-weight: 700;">${(d.sentinel && d.sentinel.predicted_app) || 'Background Sync'}</span>
            </span>
            <span class="shield-tag" style="background: rgba(6, 182, 212, 0.15); color: #38bdf8; font-size: 0.62rem; font-weight: 700; padding: 1px 6px;">
              ${(d.sentinel && d.sentinel.confidence_percent) || 95}% AI
            </span>
          </div>

          ${(d.artificial_latency_ms || 0) > 0 ? `
            <div style="display: flex; align-items: center; gap: 6px; background: rgba(245, 158, 11, 0.15); border: 1px solid rgba(245, 158, 11, 0.4); border-radius: 6px; padding: 3px 8px; margin-bottom: 8px; font-size: 0.7rem; color: #fbbf24; font-weight: 700;" class="mono">
              <span>⏱️ LAG SWITCH: +${d.artificial_latency_ms}ms</span>
            </div>
          ` : ''}

          <div class="dev-speed-row">
            <div class="speed-box ${parseFloat(dlKbps) > 0 ? 'active-io' : ''}">
              <span class="speed-lbl">LIVE DOWNLOAD</span>
              <span class="speed-val dl mono ${parseFloat(dlKbps) > 0 ? 'active-traffic' : ''}">${dlKbps} <small style="font-size:0.65rem">KB/s</small></span>
            </div>
            <div class="speed-box ${parseFloat(ulKbps) > 0 ? 'active-io' : ''}">
              <span class="speed-lbl">LIVE UPLOAD</span>
              <span class="speed-val ul mono ${parseFloat(ulKbps) > 0 ? 'active-traffic' : ''}">${ulKbps} <small style="font-size:0.65rem">KB/s</small></span>
            </div>
          </div>

          <div class="dev-total-usage">
            <span>Physical I/O Volume:</span>
            <strong class="mono">${totalGB} GB</strong>
          </div>
        </div>

        <div class="dev-controls">
          <button class="btn-card-action btn-inspect" onclick="openDeviceModal('${d.mac}')">INSPECT</button>
          ${!isLocal && !isGateway ? `
            <button class="btn-card-action btn-switch" onclick="switchDeviceNetwork('${d.mac}', '${targetNet}')">${switchLabel}</button>
            <button class="btn-card-action btn-pause" onclick="toggleDevicePause('${d.mac}')">${isPaused ? 'RESUME' : 'PAUSE'}</button>
            <button class="btn-card-action btn-kick" onclick="toggleDeviceBlock('${d.mac}')">${isBlocked ? 'UNBLOCK' : 'KICK'}</button>
          ` : `
            <button class="btn-card-action" style="cursor: not-allowed; opacity: 0.5;" disabled>PROTECTED</button>
          `}
        </div>
      </div>
    `;
  }).join('');
}

function renderActivityStream() {
  if (!DOM.activityTableBody) return;

  if (DOM.activityDeviceFilter && DOM.activityDeviceFilter.children.length <= 1) {
    appState.devices.forEach(d => {
      const opt = document.createElement('option');
      opt.value = d.ip;
      opt.textContent = `${d.custom_name || d.hostname} (${d.ip})`;
      DOM.activityDeviceFilter.appendChild(opt);
    });
  }

  const searchQ = (DOM.activitySearch ? DOM.activitySearch.value : '').toLowerCase();
  const devFilter = DOM.activityDeviceFilter ? DOM.activityDeviceFilter.value : 'all';
  const catFilter = DOM.activityCategoryFilter ? DOM.activityCategoryFilter.value : 'all';

  const filtered = appState.activities.filter(a => {
    if (devFilter !== 'all' && a.device_ip !== devFilter) return false;
    if (catFilter !== 'all' && a.category !== catFilter) return false;
    if (searchQ) {
      const d = (a.domain || '').toLowerCase();
      const u = (a.url_path || '').toLowerCase();
      const dev = (a.device_name || '').toLowerCase();
      if (!d.includes(searchQ) && !u.includes(searchQ) && !dev.includes(searchQ)) return false;
    }
    return true;
  });

  if (filtered.length === 0) {
    DOM.activityTableBody.innerHTML = `<tr><td colspan="9" style="text-align: center; padding: 25px; color: #64748b;">Monitoring active sockets and live UDP/53 DNS queries...</td></tr>`;
    return;
  }

  DOM.activityTableBody.innerHTML = filtered.map(a => {
    const catClass = getCategoryBadgeClass(a.category);
    const netBadge = a.network_type === 'guest' ? '<span class="net-badge-guest">GUEST</span>' : '<span class="net-badge-primary">PRIMARY</span>';

    return `
      <tr>
        <td class="mono" style="color: #64748b;">${a.timestamp}</td>
        <td style="font-weight: 600; color: #fff;">${escapeHtml(a.device_name)}</td>
        <td>${netBadge}</td>
        <td class="mono" style="font-size: 0.72rem; color: #38bdf8;">${a.device_ip}:${a.port || 443}</td>
        <td>
          <div class="domain-pill"><span>${escapeHtml(a.domain)}</span></div>
          <span class="url-subpath mono">${escapeHtml(a.url_path || '')}</span>
        </td>
        <td><span class="cat-badge ${catClass}">${a.category}</span></td>
        <td class="mono" style="font-size: 0.72rem; color: #94a3b8;">${a.protocol}</td>
        <td><span class="action-badge ${a.action_taken === 'BLOCKED' ? 'action-blocked' : 'action-allowed'}">${a.action_taken}</span></td>
        <td>
          <button class="cyber-btn btn-sm btn-ghost" style="padding: 2px 8px; font-size: 0.68rem;" onclick="quickBlockDomain('${a.domain}')">BLOCK</button>
        </td>
      </tr>
    `;
  }).join('');
}

function renderGuestActivityStream() {
  if (!DOM.guestActivityTbody) return;
  if (appState.guestActivities.length === 0) {
    DOM.guestActivityTbody.innerHTML = `<tr><td colspan="8" style="text-align: center; padding: 25px; color: #64748b;">No active web traffic from guest visitors yet.</td></tr>`;
    return;
  }

  DOM.guestActivityTbody.innerHTML = appState.guestActivities.map(a => `
    <tr>
      <td class="mono" style="color: #64748b;">${a.timestamp}</td>
      <td style="font-weight: 600; color: #c4b5fd;">${escapeHtml(a.device_name)}</td>
      <td class="mono" style="font-size: 0.72rem; color: #38bdf8;">${a.device_ip}</td>
      <td>
        <div class="domain-pill"><span>${escapeHtml(a.domain)}</span></div>
        <span class="url-subpath mono">${escapeHtml(a.url_path || '')}</span>
      </td>
      <td><span class="cat-badge ${getCategoryBadgeClass(a.category)}">${a.category}</span></td>
      <td class="mono" style="font-size: 0.72rem;">${a.protocol}</td>
      <td><span class="action-badge ${a.action_taken === 'BLOCKED' ? 'action-blocked' : 'action-allowed'}">${a.action_taken}</span></td>
      <td>
        <button class="cyber-btn btn-sm btn-ghost" style="padding: 2px 8px; font-size: 0.68rem;" onclick="quickBlockDomain('${a.domain}')">BLOCK</button>
      </td>
    </tr>
  `).join('');
}

function renderLeaderboard() {
  if (!DOM.leaderboardContainer) return;
  const sorted = [...appState.devices].sort((a, b) => b.total_download_bytes - a.total_download_bytes);
  const maxBytes = sorted[0] ? sorted[0].total_download_bytes : 1;

  DOM.leaderboardContainer.innerHTML = sorted.map((d, idx) => {
    const rankClass = idx === 0 ? 'top-1' : idx === 1 ? 'top-2' : idx === 2 ? 'top-3' : '';
    const gb = (d.total_download_bytes / (1024**3)).toFixed(2);
    const pct = Math.max(5, (d.total_download_bytes / maxBytes) * 100);

    return `
      <div class="leaderboard-row">
        <span class="rank-badge ${rankClass}">#${idx + 1}</span>
        <div class="leader-info">
          <div class="leader-name">${escapeHtml(d.custom_name || d.hostname)}</div>
          <div class="leader-meta mono">${d.ip} • ${d.wifi_band || '5 GHz'} • ${d.link_rate_mbps || 866.7} Mbps • <span style="text-transform:uppercase">${d.device_type || 'phone'}</span></div>
        </div>
        <div class="leader-usage-bar-wrap">
          <div class="kpi-graph-bar">
            <div class="bar-fill cyan-gradient" style="width: ${pct}%;"></div>
          </div>
        </div>
        <div class="leader-bytes mono">${gb} GB</div>
      </div>
    `;
  }).join('');
}

function renderFirewallRules() {
  if (!DOM.rulesTbody) return;
  if (appState.blacklistRules.length === 0) {
    DOM.rulesTbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: #64748b; padding: 20px;">No custom rules set. All traffic permitted.</td></tr>`;
    return;
  }

  DOM.rulesTbody.innerHTML = appState.blacklistRules.map(r => `
    <tr>
      <td style="text-transform: uppercase; font-weight: 700; color: #94a3b8;">${r.rule_type}</td>
      <td class="mono" style="font-weight: 600; color: #f87171;">${escapeHtml(r.target)}</td>
      <td style="color: #cbd5e1;">${escapeHtml(r.reason || 'Admin God Mode Policy')}</td>
      <td><span class="action-badge action-blocked">ENFORCED</span></td>
      <td>
        <button class="cyber-btn btn-sm btn-ghost" style="color: #ef4444;" onclick="deleteRule(${r.id})">REMOVE</button>
      </td>
    </tr>
  `).join('');
}

function initCharts() {
  const ctxBandwidth = document.getElementById('bandwidthChart');
  const ctxCategory = document.getElementById('categoryChart');

  if (ctxBandwidth) {
    bandwidthChart = new Chart(ctxBandwidth, {
      type: 'line',
      data: {
        labels: [],
        datasets: [
          {
            label: 'Download (Mbps)',
            borderColor: '#06b6d4',
            backgroundColor: 'rgba(6, 182, 212, 0.08)',
            borderWidth: 2.5,
            tension: 0.4,
            fill: true,
            data: []
          },
          {
            label: 'Upload (Mbps)',
            borderColor: '#8b5cf6',
            backgroundColor: 'rgba(139, 92, 246, 0.05)',
            borderWidth: 2,
            tension: 0.4,
            fill: true,
            data: []
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: { duration: 300 },
        scales: {
          x: {
            grid: { color: 'rgba(255, 255, 255, 0.04)' },
            ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10 } }
          },
          y: {
            beginAtZero: true,
            grid: { color: 'rgba(255, 255, 255, 0.04)' },
            ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10 } }
          }
        },
        plugins: { legend: { display: false } }
      }
    });
  }

  if (ctxCategory) {
    categoryChart = new Chart(ctxCategory, {
      type: 'doughnut',
      data: {
        labels: ['Streaming', 'Social Media', 'Gaming', 'Dev & AI', 'Cloud', 'System'],
        datasets: [{
          data: [35, 30, 15, 12, 5, 3],
          backgroundColor: ['#ef4444', '#3b82f6', '#8b5cf6', '#10b981', '#06b6d4', '#64748b'],
          borderColor: '#070b14',
          borderWidth: 3
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'right',
            labels: { color: '#94a3b8', font: { family: 'Inter', size: 11 }, boxWidth: 12 }
          }
        }
      }
    });
  }
}

function updateChartData(dlMbps, ulMbps, timestamp) {
  if (!bandwidthChart) return;
  const labels = bandwidthChart.data.labels;
  const dlData = bandwidthChart.data.datasets[0].data;
  const ulData = bandwidthChart.data.datasets[1].data;

  labels.push(timestamp || new Date().toLocaleTimeString());
  dlData.push(dlMbps);
  ulData.push(ulMbps);

  if (labels.length > MAX_CHART_POINTS) {
    labels.shift();
    dlData.shift();
    ulData.shift();
  }

  bandwidthChart.update('none');
}

window.openDeviceModal = async function(mac) {
  appState.selectedDeviceMac = mac;
  const dev = appState.devices.find(d => d.mac === mac);
  if (!dev) return;

  DOM.modalDeviceName.textContent = dev.custom_name || dev.hostname;
  DOM.modalDeviceIp.textContent = dev.ip;
  DOM.modalDeviceMac.textContent = dev.mac;
  DOM.modalAvatar.textContent = getDeviceIcon(dev.device_type);

  if (DOM.modalSelectDevType) {
    DOM.modalSelectDevType.value = dev.device_type || 'phone';
  }

  if (DOM.modalConnType) {
    DOM.modalConnType.textContent = dev.connection_type || 'Wi-Fi 5 (802.11ac)';
  }
  if (DOM.modalBandChannel) {
    DOM.modalBandChannel.textContent = `${dev.wifi_band || '5 GHz'} • ${dev.channel || 'Ch 153'}`;
  }
  if (DOM.modalLinkRate) {
    DOM.modalLinkRate.textContent = `${dev.link_rate_mbps || 866.7} Mbps (Negotiated)`;
  }
  if (DOM.modalSignal) {
    DOM.modalSignal.textContent = `${dev.signal_percent || 92}% (${dev.signal_dbm || -45} dBm)`;
  }

  const totalGb = ((dev.total_download_bytes + dev.total_upload_bytes) / (1024**3)).toFixed(2);
  DOM.modalTotalBytes.textContent = `${totalGb} GB`;

  // Super God Mode: Artificial Latency / Lag Switch Shaper
  const currentLag = dev.artificial_latency_ms || 0;
  if (DOM.modalLagSlider) DOM.modalLagSlider.value = currentLag;
  if (DOM.modalLagValue) {
    DOM.modalLagValue.textContent = currentLag === 0 ? '0 ms (Normal)' : `+${currentLag} ms Latency`;
  }

  // Super God Mode: Sentinel AI Behavioral Profile
  const s = dev.sentinel || { behavior_state: 'Passive Idle', predicted_app: 'Background Sync', icon: '💤', confidence_percent: 95 };
  if (DOM.modalSentinelApp) {
    DOM.modalSentinelApp.innerHTML = `${s.icon || '📱'} ${s.predicted_app} <span style="font-size:0.75rem; color:#94a3b8">(${s.behavior_state})</span>`;
  }
  if (DOM.modalSentinelConfidence) {
    DOM.modalSentinelConfidence.textContent = `${s.confidence_percent}% CONFIDENCE`;
  }

  // Hardware Brand & Model Identification
  const brand = dev.brand || (dev.vendor && dev.vendor.toLowerCase().includes('samsung') ? 'Samsung' : (dev.vendor && dev.vendor.toLowerCase().includes('apple') ? 'Apple' : ''));
  const model = dev.model_name || '';
  if (DOM.modalInputBrand) DOM.modalInputBrand.value = brand;
  if (DOM.modalInputModel) DOM.modalInputModel.value = model;
  if (DOM.modalBrandBadge) {
    DOM.modalBrandBadge.textContent = (brand || 'GENERIC').toUpperCase();
    DOM.modalBrandBadge.className = `shield-tag brand-pill ${brand ? brand.toLowerCase().replace(/[^a-z0-9]/g, '') : ''}`;
  }

  DOM.modalBtnBlock.textContent = dev.is_blocked ? 'UNBLOCK DEVICE' : 'KICK & BLOCK';
  DOM.modalBtnPause.textContent = dev.is_paused ? 'RESUME INTERNET' : 'PAUSE INTERNET';
  DOM.modalBtnSwitchNet.textContent = dev.network_type === 'guest' ? 'MOVE TO PRIMARY' : 'MOVE TO GUEST';

  DOM.deviceModal.classList.add('open');

  DOM.modalHistoryContainer.innerHTML = '<div style="padding: 16px; text-align: center; color: #64748b;">Loading logs...</div>';
  try {
    const res = await fetch(`/api/devices/${mac}/history`);
    const data = await res.json();
    renderModalHistory(data.logs || []);
  } catch (err) {
    DOM.modalHistoryContainer.innerHTML = '<div style="padding: 16px; text-align: center; color: #ef4444;">Failed to load logs.</div>';
  }
};

function renderModalHistory(logs) {
  if (logs.length === 0) {
    DOM.modalHistoryContainer.innerHTML = '<div style="padding: 16px; text-align: center; color: #64748b;">No recent web activity recorded yet.</div>';
    return;
  }
  DOM.modalHistoryContainer.innerHTML = logs.map(l => `
    <div class="history-item">
      <div>
        <strong style="color: #fff;">${escapeHtml(l.domain)}</strong>
        <span class="url-subpath mono">${escapeHtml(l.url_path || '')}</span>
      </div>
      <div style="display: flex; align-items: center; gap: 8px;">
        <span class="cat-badge ${getCategoryBadgeClass(l.category)}">${l.category}</span>
        <span class="mono" style="font-size: 0.72rem; color: #64748b;">${l.timestamp}</span>
      </div>
    </div>
  `).join('');
}

function refreshModalDetails(mac) {
  const dev = appState.devices.find(d => d.mac === mac);
  if (dev && DOM.deviceModal.classList.contains('open')) {
    DOM.modalBtnBlock.textContent = dev.is_blocked ? 'UNBLOCK DEVICE' : 'KICK & BLOCK';
    DOM.modalBtnPause.textContent = dev.is_paused ? 'RESUME INTERNET' : 'PAUSE INTERNET';
    DOM.modalBtnSwitchNet.textContent = dev.network_type === 'guest' ? 'MOVE TO PRIMARY' : 'MOVE TO GUEST';

    const brand = dev.brand || (dev.vendor && dev.vendor.toLowerCase().includes('samsung') ? 'Samsung' : '');
    const model = dev.model_name || '';
    if (DOM.modalInputBrand) DOM.modalInputBrand.value = brand;
    if (DOM.modalInputModel) DOM.modalInputModel.value = model;
    if (DOM.modalBrandBadge) {
      DOM.modalBrandBadge.textContent = (brand || 'GENERIC').toUpperCase();
      DOM.modalBrandBadge.className = `shield-tag brand-pill ${brand ? brand.toLowerCase().replace(/[^a-z0-9]/g, '') : ''}`;
    }
  }
}

window.toggleDeviceBlock = async function(mac) {
  try {
    const res = await fetch(`/api/devices/${mac}/block`, { method: 'POST' });
    const data = await res.json();
    showToast(data.message, data.is_blocked ? 'crimson' : 'emerald');
  } catch (err) {
    showToast('Block toggle failed', 'crimson');
  }
};

window.toggleDevicePause = async function(mac) {
  try {
    const res = await fetch(`/api/devices/${mac}/pause`, { method: 'POST' });
    const data = await res.json();
    showToast(data.message, data.is_paused ? 'amber' : 'emerald');
  } catch (err) {
    showToast('Pause toggle failed', 'crimson');
  }
};

window.switchDeviceNetwork = async function(mac, networkType) {
  try {
    const res = await fetch(`/api/devices/${mac}/network`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ network_type: networkType })
    });
    if (res.ok) {
      showToast(`Device moved to ${networkType.toUpperCase()} network`, 'purple');
    }
  } catch (err) {
    showToast('Failed to switch network', 'crimson');
  }
};

window.quickBlockDomain = async function(domain) {
  try {
    const res = await fetch('/api/firewall/rule', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ rule_type: 'domain', target: domain, reason: 'Quick Action' })
    });
    if (res.ok) {
      showToast(`🛡️ Instantly blocked domain: ${domain}`, 'emerald');
    }
  } catch (err) {
    showToast('Failed to quick-block domain', 'crimson');
  }
};

window.deleteRule = async function(ruleId) {
  try {
    const res = await fetch(`/api/firewall/rule/${ruleId}`, { method: 'DELETE' });
    if (res.ok) showToast('Firewall rule removed', 'cyan');
  } catch (err) {
    showToast('Failed to delete rule', 'crimson');
  }
};

function initFirewallPresets() {
  DOM.presetButtons.forEach(btn => {
    btn.addEventListener('click', async () => {
      const target = btn.dataset.target;
      const ruleType = btn.dataset.type;
      try {
        const res = await fetch('/api/firewall/rule', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ rule_type: ruleType, target, reason: `Quick Preset: ${btn.textContent}` })
        });
        if (res.ok) {
          showToast(`🛡️ Shield active: ${target}`, 'emerald');
        } else {
          showToast(`Rule for ${target} already active`, 'amber');
        }
      } catch (err) {
        showToast('Error applying preset', 'crimson');
      }
    });
  });
}

function initQrCode() {
  const host = window.location.hostname || '192.168.1.39';
  const port = window.location.port || '8000';
  const mobileUrl = `http://${host}:${port}`;

  if (DOM.mobileUrlText) DOM.mobileUrlText.textContent = mobileUrl;
  if (DOM.mobileGuideUrl) DOM.mobileGuideUrl.textContent = mobileUrl;
  if (DOM.popupMobileUrl) DOM.popupMobileUrl.textContent = mobileUrl;

  if (typeof QRCode !== 'undefined') {
    if (DOM.qrcodeBox) {
      DOM.qrcodeBox.innerHTML = '';
      new QRCode(DOM.qrcodeBox, {
        text: mobileUrl,
        width: 170,
        height: 170,
        colorDark: '#070b14',
        colorLight: '#ffffff',
        correctLevel: QRCode.CorrectLevel.M
      });
    }

    if (DOM.popupQrcodeBox) {
      DOM.popupQrcodeBox.innerHTML = '';
      new QRCode(DOM.popupQrcodeBox, {
        text: mobileUrl,
        width: 180,
        height: 180,
        colorDark: '#070b14',
        colorLight: '#ffffff',
        correctLevel: QRCode.CorrectLevel.M
      });
    }
  }
}

// Helpers
function getDeviceIcon(type) {
  switch (type) {
    case 'phone': return '📱';
    case 'laptop':
    case 'pc': return '💻';
    case 'tablet': return '📟';
    case 'smart_tv': return '📺';
    case 'console': return '🎮';
    case 'router': return '🌐';
    case 'iot': return '💡';
    default: return '📱';
  }
}

function getDeviceTypeLabel(type) {
  switch (type) {
    case 'phone': return 'SMARTPHONE';
    case 'laptop':
    case 'pc': return 'LAPTOP / PC';
    case 'tablet': return 'TABLET';
    case 'smart_tv': return 'SMART TV';
    case 'console': return 'CONSOLE';
    case 'router': return 'GATEWAY AP';
    case 'iot': return 'SMART HOME';
    default: return 'CLIENT';
  }
}

function getCategoryBadgeClass(category) {
  switch (category) {
    case 'Streaming': return 'cat-streaming';
    case 'Social Media': return 'cat-social';
    case 'Gaming': return 'cat-gaming';
    case 'Dev & AI': return 'cat-dev';
    case 'Cloud & Storage': return 'cat-cloud';
    case 'Threat & P2P': return 'cat-threat';
    default: return 'cat-dev';
  }
}

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function showToast(message, color = 'cyan') {
  if (!DOM.toastContainer) return;
  const toast = document.createElement('div');
  toast.className = 'cyber-toast';
  
  let borderColor = 'var(--cyan-primary)';
  if (color === 'emerald') borderColor = 'var(--emerald-success)';
  if (color === 'crimson') borderColor = 'var(--crimson-danger)';
  if (color === 'amber') borderColor = 'var(--amber-warning)';
  if (color === 'purple') borderColor = 'var(--purple-accent)';
  
  toast.style.borderColor = borderColor;
  toast.innerHTML = `<span>${escapeHtml(message)}</span>`;
  
  DOM.toastContainer.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(-10px)';
    toast.style.transition = 'all 0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}

/* ==========================================================================
   SUPER GOD MODE // TOPOLOGY RADAR, LAG SWITCH, SENTINEL AI & CHRONOS
   ========================================================================== */

function initTopologyRadar() {
  if (typeof NetworkTopologyRadar !== 'undefined') {
    window.topologyRadar = new NetworkTopologyRadar('topologyCanvas');
    if (appState.devices.length > 0) {
      window.topologyRadar.updateNodes(appState.devices, appState.gatewayIp);
    }
  }
}

function initLagSwitch() {
  if (DOM.modalLagSlider) {
    DOM.modalLagSlider.addEventListener('input', (e) => {
      const val = parseInt(e.target.value);
      if (DOM.modalLagValue) {
        DOM.modalLagValue.textContent = val === 0 ? '0 ms (Normal)' : `+${val} ms Latency`;
      }
    });

    DOM.modalLagSlider.addEventListener('change', async (e) => {
      if (!appState.selectedDeviceMac) return;
      const val = parseInt(e.target.value);
      await window.setDeviceLag(appState.selectedDeviceMac, val);
    });
  }

  DOM.presetLagButtons.forEach(btn => {
    btn.addEventListener('click', async () => {
      if (!appState.selectedDeviceMac) return;
      const lag = parseInt(btn.dataset.lag);
      if (DOM.modalLagSlider) DOM.modalLagSlider.value = lag;
      if (DOM.modalLagValue) {
        DOM.modalLagValue.textContent = lag === 0 ? '0 ms (Normal)' : `+${lag} ms Latency`;
      }
      await window.setDeviceLag(appState.selectedDeviceMac, lag);
    });
  });
}

window.setDeviceLag = async function(mac, lagMs) {
  try {
    const res = await fetch(`/api/devices/${mac}/lag`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ latency_ms: lagMs })
    });
    if (res.ok) {
      showToast(`⏱️ Lag Switch: ${lagMs}ms applied to target`, lagMs > 0 ? 'amber' : 'emerald');
      const dev = appState.devices.find(d => d.mac === mac);
      if (dev) dev.artificial_latency_ms = lagMs;
      renderPrimaryDevices();
      renderGuestDevices();
    }
  } catch (err) {
    showToast('Failed to apply artificial latency', 'crimson');
  }
};

window.toggleScheduleRule = async function(ruleId) {
  try {
    const res = await fetch(`/api/schedules/${ruleId}/toggle`, { method: 'POST' });
    const data = await res.json();
    showToast(`⏰ Policy "${data.rule_name}": ${data.is_active ? 'ACTIVE' : 'DEACTIVATED'}`, data.is_active ? 'emerald' : 'amber');
    const btn = document.getElementById(`sched-btn-${ruleId}`);
    if (btn) {
      btn.textContent = data.is_active ? 'ACTIVE (ENFORCED)' : 'ENABLE RULE';
      btn.classList.toggle('active', data.is_active);
    }
  } catch (err) {
    showToast('Failed to toggle schedule rule', 'crimson');
  }
};

function renderSentinelFeed() {
  if (!DOM.sentinelDeviceList) return;
  if (!appState.devices || appState.devices.length === 0) {
    DOM.sentinelDeviceList.innerHTML = '<div style="color: #64748b; padding: 12px; font-size: 0.8rem;">Awaiting subnet telemetry...</div>';
    return;
  }

  DOM.sentinelDeviceList.innerHTML = appState.devices.map(d => {
    const s = d.sentinel || { behavior_state: 'Passive Idle', predicted_app: 'Background Sync', icon: '💤', confidence_percent: 95 };
    const dlKbps = (d.current_dl_kbps || 0).toFixed(0);
    const ulKbps = (d.current_ul_kbps || 0).toFixed(0);
    const isLocal = d.ip === appState.localIp;

    return `
      <div class="sentinel-card">
        <div class="sentinel-device-identity">
          <div class="sentinel-avatar">${s.icon || '📱'}</div>
          <div>
            <div class="sentinel-dev-name">${escapeHtml(d.custom_name || d.hostname)} ${isLocal ? '<span class="shield-tag" style="font-size:0.6rem; color:#38bdf8">YOU</span>' : ''}</div>
            <div class="sentinel-prediction">${s.predicted_app}</div>
          </div>
        </div>
        <div style="text-align: right;">
          <span class="shield-tag" style="background: rgba(6,182,212,0.15); color: #38bdf8; font-weight: 700; font-size: 0.7rem;">
            ${s.confidence_percent}% AI CONFIDENCE
          </span>
          <div class="mono" style="font-size: 0.72rem; color: #64748b; margin-top: 4px;">
            ↓ ${dlKbps} KB/s • ↑ ${ulKbps} KB/s
          </div>
        </div>
      </div>
    `;
  }).join('');
}

function renderGodSchedules() {
  if (!appState.godSchedules) return;
  appState.godSchedules.forEach(s => {
    const btn = document.getElementById(`sched-btn-${s.id}`);
    if (btn) {
      btn.textContent = s.is_active ? 'ACTIVE (ENFORCED)' : 'ENABLE RULE';
      btn.classList.toggle('active', !!s.is_active);
    }
  });
}

function initDeviceIdentifier() {
  if (DOM.modalBtnSaveIdentify) {
    DOM.modalBtnSaveIdentify.addEventListener('click', async () => {
      if (!appState.selectedDeviceMac) return;
      const brand = DOM.modalInputBrand ? DOM.modalInputBrand.value.trim() : '';
      const model = DOM.modalInputModel ? DOM.modalInputModel.value.trim() : '';
      const devType = DOM.modalSelectDevType ? DOM.modalSelectDevType.value : 'phone';
      const customName = model ? (brand && !model.toLowerCase().includes(brand.toLowerCase()) ? `${brand} ${model}` : model) : undefined;

      try {
        const res = await fetch(`/api/devices/${appState.selectedDeviceMac}/identify`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            brand: brand || 'Generic',
            model_name: model,
            device_type: devType,
            custom_name: customName
          })
        });
        if (res.ok) {
          const dev = appState.devices.find(d => d.mac === appState.selectedDeviceMac);
          if (dev) {
            dev.brand = brand || 'Generic';
            dev.model_name = model;
            if (customName) dev.custom_name = customName;
            if (devType) dev.device_type = devType;
          }
          if (DOM.modalBrandBadge) {
            DOM.modalBrandBadge.textContent = (brand || 'GENERIC').toUpperCase();
            DOM.modalBrandBadge.className = `shield-tag brand-pill ${brand ? brand.toLowerCase().replace(/[^a-z0-9]/g, '') : ''}`;
          }
          if (DOM.modalDeviceName && customName) {
            DOM.modalDeviceName.textContent = customName;
          }
          showToast(`✓ Identified as: ${brand} ${model}`, 'emerald');
          renderPrimaryDevices();
          renderGuestDevices();
          if (window.topologyRadar) {
            window.topologyRadar.updateNodes(appState.devices, appState.gatewayIp);
          }
        } else {
          showToast('Failed to save hardware identity', 'crimson');
        }
      } catch (err) {
        showToast('Network error saving device identity', 'crimson');
      }
    });
  }

  DOM.presetModelButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const brand = btn.dataset.brand;
      const model = btn.dataset.model;
      const devType = btn.dataset.type;
      const devName = btn.dataset.name;

      if (DOM.modalInputBrand) DOM.modalInputBrand.value = brand;
      if (DOM.modalInputModel) DOM.modalInputModel.value = model;
      if (DOM.modalSelectDevType && devType) DOM.modalSelectDevType.value = devType;
      if (DOM.modalBrandBadge) {
        DOM.modalBrandBadge.textContent = brand.toUpperCase();
        DOM.modalBrandBadge.className = `shield-tag brand-pill ${brand.toLowerCase().replace(/[^a-z0-9]/g, '')}`;
      }

      // Automatically trigger save for quick preset action
      if (DOM.modalBtnSaveIdentify) {
        DOM.modalBtnSaveIdentify.click();
      }
    });
  });
}


