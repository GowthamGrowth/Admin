(() => {
  const tokenInput = document.getElementById("admin-token");
  const notice = document.getElementById("notice");
  const shopsBody = document.getElementById("shops-body");
  const releasesBody = document.getElementById("releases-body");
  const pushButton = document.getElementById("push-button");
  const selectAll = document.getElementById("select-all");
  const configOutput = document.getElementById("shop-config");
  const copyConfigButton = document.getElementById("copy-config");
  const uploadProgressPanel = document.getElementById("release-upload-progress");
  const uploadProgressBar = document.getElementById("release-upload-bar");
  const uploadProgressMessage = document.getElementById("release-upload-message");
  const uploadProgressPercent = document.getElementById("release-upload-percent");
  const uploadProgressSpeed = document.getElementById("release-upload-speed");
  const uploadProgressEta = document.getElementById("release-upload-eta");
  let releases = [];
  let lastShopConfig = null;

  tokenInput.value = sessionStorage.getItem("adminToken") || "";

  function showNotice(message, isError = false) {
    notice.textContent = message || "";
    notice.className = `notice ${message ? (isError ? "error" : "success") : ""}`;
  }

  async function api(url, options = {}) {
    const token = tokenInput.value.trim();
    if (!token) throw new Error("Enter the dashboard admin API token.");
    const headers = new Headers(options.headers || {});
    headers.set("Authorization", `Bearer ${token}`);
    if (options.body && !(options.body instanceof FormData)) headers.set("Content-Type", "application/json");
    const response = await fetch(url, { ...options, headers, cache: "no-store" });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || `Request failed (${response.status}).`);
    return data;
  }

  function formatEta(seconds) {
    if (!Number.isFinite(seconds)) return "--";
    const remaining = Math.max(0, Math.ceil(seconds));
    const minutes = Math.floor(remaining / 60);
    const secondsPart = remaining % 60;
    return minutes ? `${minutes}m ${secondsPart}s` : `${secondsPart}s`;
  }

  function renderUploadProgress(percent, message, speedBytesPerSecond, etaSeconds) {
    const boundedPercent = Math.max(0, Math.min(100, Math.round(percent)));
    uploadProgressPanel.hidden = false;
    uploadProgressBar.value = boundedPercent;
    uploadProgressPercent.textContent = `${boundedPercent}%`;
    uploadProgressMessage.textContent = message;
    uploadProgressSpeed.textContent = speedBytesPerSecond > 0
      ? `Speed: ${(speedBytesPerSecond / (1024 * 1024)).toFixed(2)} MB/s`
      : "Speed: --";
    uploadProgressEta.textContent = etaSeconds !== null && etaSeconds !== undefined
      ? `ETA: ${formatEta(etaSeconds)}`
      : "ETA: --";
  }

  function createUploadId() {
    if (window.crypto && typeof window.crypto.randomUUID === "function") {
      return window.crypto.randomUUID();
    }
    const bytes = new Uint8Array(24);
    window.crypto.getRandomValues(bytes);
    return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  }

  function uploadRelease(formData, uploadId, onProgress) {
    return new Promise((resolve, reject) => {
      const token = tokenInput.value.trim();
      if (!token) {
        reject(new Error("Enter the dashboard admin API token."));
        return;
      }
      const xhr = new XMLHttpRequest();
      xhr.open("POST", "/api/admin/releases");
      xhr.setRequestHeader("Authorization", `Bearer ${token}`);
      xhr.setRequestHeader("X-Upload-Id", uploadId);
      xhr.upload.addEventListener("progress", onProgress);
      xhr.addEventListener("load", () => {
        let data = {};
        try {
          data = JSON.parse(xhr.responseText || "{}");
        } catch (_error) {
          data = {};
        }
        if (xhr.status >= 200 && xhr.status < 300) {
          resolve(data);
        } else {
          reject(new Error(data.error || `Request failed (${xhr.status}).`));
        }
      });
      xhr.addEventListener("error", () => reject(new Error("Network error while uploading the release.")));
      xhr.addEventListener("abort", () => reject(new Error("Release upload was cancelled.")));
      xhr.send(formData);
    });
  }

  async function pollUploadProgress(uploadId, signal) {
    while (!signal.aborted) {
      try {
        const response = await fetch(`/api/admin/releases/progress/${encodeURIComponent(uploadId)}`, {
          headers: { Authorization: `Bearer ${tokenInput.value.trim()}` },
          cache: "no-store",
          signal,
        });
        const progress = await response.json();
        if (!response.ok) throw new Error(progress.error || `Progress check failed (${response.status}).`);
        if (progress.phase !== "waiting") {
          renderUploadProgress(
            progress.percent,
            progress.message,
            progress.speedBytesPerSecond,
            progress.etaSeconds,
          );
        }
      } catch (error) {
        if (signal.aborted) return;
        if (error.name !== "AbortError") {
          renderUploadProgress(0, error.message || "Unable to read upload progress.", 0, null);
          return;
        }
      }
      await new Promise((resolve) => window.setTimeout(resolve, 400));
    }
  }

  function selectedShopIds() {
    return [...document.querySelectorAll(".shop-select:checked")].map((checkbox) => checkbox.value);
  }

  function updatePushButton() {
    pushButton.disabled = selectedShopIds().length === 0 || !document.querySelector(".release-select:checked");
  }

  async function loadShops() {
    const data = await api("/api/admin/shops");
    document.getElementById("total-count").textContent = data.total;
    document.getElementById("online-count").textContent = data.online;
    document.getElementById("offline-count").textContent = data.offline;
    document.getElementById("online-window").textContent = `${Math.round(data.onlineWindowSeconds / 60)} min`;
    shopsBody.replaceChildren();
    if (!data.shops.length) {
      shopsBody.innerHTML = '<tr><td colspan="8" class="empty">No shops registered yet.</td></tr>';
      updatePushButton();
      return;
    }
    for (const shop of data.shops) {
      const row = document.createElement("tr");
      row.innerHTML = `
        <td><input class="shop-select" type="checkbox" value="${escapeHtml(shop.shopId)}" aria-label="Select ${escapeHtml(shop.shopName)}"></td>
        <td>${escapeHtml(shop.shopId)}</td><td>${escapeHtml(shop.shopName)}</td>
        <td>${escapeHtml(shop.currentVersion || "—")}</td>
        <td><span class="badge ${shop.online ? "online" : "offline"}">${shop.online ? "Online" : "Offline"}</span></td>
        <td>${escapeHtml(formatDate(shop.lastSeen))}</td>
        <td>${escapeHtml(shop.assignedVersion || "—")}</td>
        <td><button class="button secondary rotate-token" data-shop-id="${escapeHtml(shop.shopId)}" type="button">Rotate token</button></td>`;
      shopsBody.append(row);
    }
    document.querySelectorAll(".shop-select").forEach((checkbox) => checkbox.addEventListener("change", updatePushButton));
    selectAll.checked = false;
    updatePushButton();
  }

  async function loadReleases() {
    const data = await api("/api/admin/releases");
    releases = data.releases;
    releasesBody.replaceChildren();
    if (!releases.length) {
      releasesBody.innerHTML = '<tr><td colspan="6" class="empty">No releases published yet.</td></tr>';
      updatePushButton();
      return;
    }
    for (const release of releases) {
      const row = document.createElement("tr");
      row.innerHTML = `
        <td><input class="release-select" type="radio" name="release" value="${release.id}" aria-label="Select release ${escapeHtml(release.version)}"></td>
        <td>${escapeHtml(release.version)}</td><td>${escapeHtml(release.tag_name)}</td>
        <td><a href="${escapeHtml(release.github_html_url)}" target="_blank" rel="noopener noreferrer">Open</a></td>
        <td>${escapeHtml(formatDate(release.published_at))}</td><td>${release.target_count}</td>`;
      releasesBody.append(row);
    }
    document.querySelectorAll(".release-select").forEach((radio) => radio.addEventListener("change", updatePushButton));
    updatePushButton();
  }

  function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, (character) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    })[character]);
  }

  function formatDate(value) {
    if (!value) return "Never";
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? "Unknown" : date.toLocaleString();
  }

  async function refresh() {
    sessionStorage.setItem("adminToken", tokenInput.value.trim());
    await Promise.all([loadShops(), loadReleases()]);
  }

  document.getElementById("connect-button").addEventListener("click", async () => {
    try {
      await refresh();
      showNotice("Connected. Shop status refreshes every 30 seconds.");
    } catch (error) {
      showNotice(error.message, true);
    }
  });
  document.getElementById("refresh-button").addEventListener("click", async () => {
    try {
      await refresh();
      showNotice("Dashboard refreshed.");
    } catch (error) {
      showNotice(error.message, true);
    }
  });
  selectAll.addEventListener("change", () => {
    document.querySelectorAll(".shop-select").forEach((checkbox) => { checkbox.checked = selectAll.checked; });
    updatePushButton();
  });
  document.getElementById("shop-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const body = Object.fromEntries(new FormData(event.currentTarget).entries());
    try {
      const created = await api("/api/admin/shops", { method: "POST", body: JSON.stringify(body) });
      showShopConfig(created.clientConfig);
      event.currentTarget.reset();
      await loadShops();
      showNotice(`${created.shopName} registered. Copy the token now; it is only shown once.`);
    } catch (error) {
      showNotice(error.message, true);
    }
  });
  copyConfigButton.addEventListener("click", async () => {
    if (!lastShopConfig) return;
    try {
      await navigator.clipboard.writeText(JSON.stringify(lastShopConfig, null, 2));
      showNotice("Shop config copied. Store it securely.");
    } catch (error) {
      showNotice(`Could not access clipboard: ${error.message}`, true);
    }
  });
  shopsBody.addEventListener("click", async (event) => {
    const target = event.target instanceof Element ? event.target : event.target.parentElement;
    const button = target && target.closest(".rotate-token");
    if (!button) return;
    if (!window.confirm(`Rotate the heartbeat/update token for ${button.dataset.shopId}? The old token stops working immediately.`)) return;
    button.disabled = true;
    try {
      const result = await api(`/api/admin/shops/${encodeURIComponent(button.dataset.shopId)}/rotate-token`, {
        method: "POST",
        body: JSON.stringify({}),
      });
      showShopConfig(result.clientConfig);
      showNotice(`${result.warning} Replace the config on that shop before its next heartbeat.`);
    } catch (error) {
      showNotice(error.message, true);
    } finally {
      button.disabled = false;
    }
  });
  document.getElementById("release-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = event.currentTarget.querySelector('button[type="submit"]');
    const uploadId = createUploadId();
    const progressController = new AbortController();
    let previousLoaded = 0;
    let previousSampleTime = performance.now();
    button.disabled = true;
    renderUploadProgress(0, "Sending installer to dashboard.", 0, null);
    const progressPolling = pollUploadProgress(uploadId, progressController.signal);
    try {
      const data = await uploadRelease(new FormData(event.currentTarget), uploadId, (progressEvent) => {
        if (!progressEvent.lengthComputable) return;
        const currentTime = performance.now();
        const elapsed = (currentTime - previousSampleTime) / 1000;
        const speed = elapsed > 0 ? (progressEvent.loaded - previousLoaded) / elapsed : 0;
        const remainingBytes = progressEvent.total - progressEvent.loaded;
        renderUploadProgress(
          progressEvent.loaded * 100 / progressEvent.total,
          "Sending installer to dashboard.",
          speed,
          speed > 0 ? remainingBytes / speed : null,
        );
        previousLoaded = progressEvent.loaded;
        previousSampleTime = currentTime;
      });
      event.currentTarget.reset();
      await loadReleases();
      const radio = document.querySelector(`.release-select[value="${CSS.escape(String(data.releaseId))}"]`);
      if (radio) radio.checked = true;
      updatePushButton();
      renderUploadProgress(100, "Release published successfully.", 0, 0);
      showNotice(`${data.message} ${data.githubUrl}`);
    } catch (error) {
      uploadProgressMessage.textContent = error.message;
      showNotice(error.message, true);
    } finally {
      progressController.abort();
      await progressPolling;
      button.disabled = false;
    }
  });
  pushButton.addEventListener("click", async () => {
    const releaseId = document.querySelector(".release-select:checked")?.value;
    const shopIds = selectedShopIds();
    if (!releaseId || !shopIds.length) return;
    if (!window.confirm(`Assign this update to ${shopIds.length} selected shop(s)?`)) return;
    pushButton.disabled = true;
    try {
      const data = await api("/api/admin/push", {
        method: "POST",
        body: JSON.stringify({ releaseId, shopIds }),
      });
      await Promise.all([loadShops(), loadReleases()]);
      showNotice(`Update assigned to ${data.assigned} selected shop(s). They will receive it on their next heartbeat.`);
    } catch (error) {
      showNotice(error.message, true);
    } finally {
      updatePushButton();
    }
  });

  if (tokenInput.value) {
    refresh().then(() => showNotice("Connected. Shop status refreshes every 10 seconds."))
      .catch((error) => showNotice(error.message, true));
  }

  function showShopConfig(config) {
    lastShopConfig = config;
    configOutput.textContent = JSON.stringify(config, null, 2);
    configOutput.hidden = false;
    copyConfigButton.hidden = false;
  }
  window.setInterval(() => {
    if (!tokenInput.value.trim()) return;
    Promise.all([loadShops(), loadReleases()]).catch((error) => showNotice(error.message, true));
  }, 10000);
})();
