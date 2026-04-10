(function () {
  "use strict";

  const PAGE_SIZE = 50;
  let currentPage = 1;
  let totalPages = 1;
  let totalItems = 0;
  let debounceTimer = null;
  let lastItems = [];

  const $ = (id) => document.getElementById(id);

  function truncate(str, n) {
    if (!str) return "—";
    const s = String(str);
    return s.length <= n ? s : s.slice(0, n - 1) + "…";
  }

  function formatMaybeJson(value) {
    if (value === null || value === undefined) return "—";
    if (typeof value === "object") {
      try {
        return JSON.stringify(value, null, 2);
      } catch {
        return String(value);
      }
    }
    if (typeof value === "string") {
      const t = value.trim();
      if ((t.startsWith("{") && t.endsWith("}")) || (t.startsWith("[") && t.endsWith("]"))) {
        try {
          return JSON.stringify(JSON.parse(t), null, 2);
        } catch {
          return value;
        }
      }
      return value;
    }
    return String(value);
  }

  function escHtml(s) {
    if (s === null || s === undefined) return "";
    const d = document.createElement("div");
    d.textContent = s;
    return d.innerHTML;
  }

  function buildQueryParams() {
    const params = new URLSearchParams();
    params.set("page", String(currentPage));
    const fromEl = $("filter-from");
    const toEl = $("filter-to");
    if (fromEl && fromEl.value) {
      const d = new Date(fromEl.value);
      if (!Number.isNaN(d.getTime())) params.set("from_date", d.toISOString());
    }
    if (toEl && toEl.value) {
      const d = new Date(toEl.value);
      if (!Number.isNaN(d.getTime())) params.set("to_date", d.toISOString());
    }
    const method = $("filter-method")?.value?.trim();
    if (method) params.set("method", method);
    const search = $("filter-search")?.value?.trim();
    if (search) params.set("search", search);
    return params;
  }

  async function fetchLogs() {
    const errEl = $("filter-error");
    if (errEl) {
      errEl.classList.add("hidden");
      errEl.textContent = "";
    }
    const params = buildQueryParams();
    const res = await fetch("/api/logs?" + params.toString(), {
      credentials: "same-origin",
      headers: { Accept: "application/json" },
    });
    if (res.status === 401) {
      window.location.href = "/login";
      return null;
    }
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      let msg = data.detail || data.message || res.statusText || "Ошибка запроса";
      if (Array.isArray(msg)) {
        msg = msg.map((x) => (typeof x === "object" && x.msg ? x.msg : JSON.stringify(x))).join("; ");
      } else if (typeof msg === "object") {
        msg = JSON.stringify(msg);
      }
      if (errEl) {
        errEl.textContent = String(msg);
        errEl.classList.remove("hidden");
      }
      return null;
    }
    return data;
  }

  function renderTable(items) {
    const tbody = $("log-rows");
    const empty = $("empty-state");
    if (!tbody) return;
    tbody.innerHTML = "";
    if (!items || items.length === 0) {
      empty?.classList.remove("hidden");
      return;
    }
    empty?.classList.add("hidden");
    items.forEach((row, idx) => {
      const tr = document.createElement("tr");
      tr.className = "hover:bg-white/5";
      const ts = row.timestamp
        ? new Date(row.timestamp).toLocaleString("ru-RU", { dateStyle: "short", timeStyle: "medium" })
        : "—";
      tr.innerHTML = `
        <td class="whitespace-nowrap px-4 py-2 text-slate-300">${escHtml(ts)}</td>
        <td class="px-4 py-2 font-mono text-xs text-accent">${escHtml(row.method || "—")}</td>
        <td class="max-w-md px-4 py-2 text-slate-300" title="${escHtml(row.url || "")}">${escHtml(truncate(row.url, 72))}</td>
        <td class="px-4 py-2 font-mono">${escHtml(row.response_status != null ? String(row.response_status) : "—")}</td>
        <td class="px-4 py-2 font-mono text-xs text-slate-400">${escHtml(row.client_ip || "—")}</td>
        <td class="px-4 py-2 text-slate-400">${row.duration_ms != null ? Number(row.duration_ms).toFixed(1) + " мс" : "—"}</td>
        <td class="px-4 py-2">
          <button type="button" class="view-btn rounded bg-accent/80 px-2 py-1 text-xs font-medium text-white hover:bg-accent" data-i="${idx}">Просмотр</button>
        </td>
      `;
      tbody.appendChild(tr);
    });
    tbody.querySelectorAll(".view-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        const i = parseInt(btn.getAttribute("data-i"), 10);
        openModal(lastItems[i]);
      });
    });
  }

  function updatePagination() {
    const info = $("page-info");
    if (info) {
      info.textContent = `Стр. ${currentPage} из ${totalPages} · всего ${totalItems}`;
    }
    const first = $("btn-first");
    const prev = $("btn-prev");
    const next = $("btn-next");
    const last = $("btn-last");
    const onFirst = currentPage <= 1;
    const onLast = currentPage >= totalPages;
    if (first) first.disabled = onFirst;
    if (prev) prev.disabled = onFirst;
    if (next) next.disabled = onLast;
    if (last) last.disabled = onLast;
  }

  function section(title, content) {
    return `
      <section>
        <h3 class="mb-2 text-xs font-semibold uppercase tracking-wide text-accent">${escHtml(title)}</h3>
        <pre class="max-h-48 overflow-auto rounded-lg border border-white/10 bg-black/40 p-3 font-mono text-xs text-slate-300 whitespace-pre-wrap break-all">${content}</pre>
      </section>
    `;
  }

  function openModal(item) {
    if (!item) return;
    const body = $("modal-body");
    const modal = $("modal");
    const backdrop = $("modal-backdrop");
    if (!body || !modal || !backdrop) return;

    const blocks = [];
    blocks.push(section("Запрос — метод", escHtml(item.method || "—")));
    blocks.push(section("Запрос — URL", escHtml(item.url || "—")));
    blocks.push(section("Запрос — заголовки", escHtml(formatMaybeJson(item.request_headers))));
    blocks.push(section("Запрос — cookies", escHtml(formatMaybeJson(item.request_cookies))));
    if (item.request_query_params) {
      blocks.push(section("Запрос — параметры запроса", escHtml(formatMaybeJson(item.request_query_params))));
    }
    blocks.push(section("Запрос — тело", escHtml(formatMaybeJson(item.request_body))));
    blocks.push(section("Ответ — код", escHtml(item.response_status != null ? String(item.response_status) : "—")));
    blocks.push(section("Ответ — заголовки", escHtml(formatMaybeJson(item.response_headers))));
    blocks.push(section("Ответ — тело", escHtml(formatMaybeJson(item.response_body))));
    blocks.push(
      section(
        "Мета",
        escHtml(
          formatMaybeJson({
            id: item.id,
            client_ip: item.client_ip,
            duration_ms: item.duration_ms,
            timestamp: item.timestamp,
            user_agent: item.user_agent,
            is_https: item.is_https,
            tunnel_host: item.tunnel_host,
            tunnel_port: item.tunnel_port,
            proxy_note: item.proxy_note,
          })
        )
      )
    );

    body.innerHTML = blocks.join("");
    modal.style.display = "flex";
    backdrop.style.display = "block";
    document.body.style.overflow = "hidden";
  }

  function closeModal() {
    const modal = $("modal");
    const backdrop = $("modal-backdrop");
    if (modal) modal.style.display = "none";
    if (backdrop) backdrop.style.display = "none";
    document.body.style.overflow = "";
  }

  async function load() {
    const data = await fetchLogs();
    if (!data) return;
    lastItems = data.items || [];
    totalItems = data.total ?? 0;
    totalPages = Math.max(1, data.pages ?? 1);
    currentPage = Math.min(Math.max(1, data.page ?? 1), totalPages);
    const src = $("data-source");
    if (src) {
      src.textContent =
        data.source === "postgresql"
          ? "Источник: PostgreSQL"
          : "Источник: " + (data.source || "—");
    }
    renderTable(lastItems);
    updatePagination();
  }

  function scheduleSearch() {
    if (debounceTimer) clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
      currentPage = 1;
      load();
    }, 300);
  }

  document.addEventListener("DOMContentLoaded", () => {
    load();

    ["filter-from", "filter-to", "filter-method"].forEach((id) => {
      $(id)?.addEventListener("change", () => {
        currentPage = 1;
        load();
      });
    });

    $("filter-search")?.addEventListener("input", scheduleSearch);

    $("btn-first")?.addEventListener("click", () => {
      if (currentPage > 1) {
        currentPage = 1;
        load();
      }
    });
    $("btn-prev")?.addEventListener("click", () => {
      if (currentPage > 1) {
        currentPage--;
        load();
      }
    });
    $("btn-next")?.addEventListener("click", () => {
      if (currentPage < totalPages) {
        currentPage++;
        load();
      }
    });
    $("btn-last")?.addEventListener("click", () => {
      if (currentPage < totalPages) {
        currentPage = totalPages;
        load();
      }
    });

    $("modal-close")?.addEventListener("click", closeModal);
    $("modal-backdrop")?.addEventListener("click", closeModal);
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape") closeModal();
    });
  });
})();
