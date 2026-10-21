"use strict";

const MAX_BYTES = 8 * 1024 * 1024;
const COLORS = [
  "#4c9c87",
  "#8aa6c9",
  "#d1ac77",
  "#b3bcca",
  "#c2d5ce",
  "#a998b8",
];
let report = null;
let sortKey = "packets";
let sortDirection = -1;
let loading = false;
const $ = (id) => document.getElementById(id);
const count = (value) => Number(value || 0).toLocaleString("en-US");
const text = (element, value) => {
  element.textContent = value;
};

function formatBytes(value) {
  const bytes = Number(value || 0);
  if (bytes < 1024) return `${count(bytes)} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MiB`;
}

function formatDuration(value) {
  const seconds = Number(value || 0);
  return seconds < 60
    ? `${seconds.toFixed(2)} s`
    : `${Math.floor(seconds / 60)}m ${(seconds % 60).toFixed(1)}s`;
}

function timestamp(value, short = false) {
  const date = new Date(typeof value === "number" ? value * 1000 : value);
  if (Number.isNaN(date.getTime())) return "Timestamp unavailable";
  return short
    ? `${date.toISOString().slice(11, 19)} UTC`
    : date
        .toISOString()
        .replace("T", " ")
        .replace(".000Z", " UTC")
        .replace("Z", " UTC");
}

function setStatus(message, type = "") {
  const status = $("status-message");
  status.hidden = !message;
  status.className = `status-message ${type}`;
  text(status, message);
  status.setAttribute("role", type === "error" ? "alert" : "status");
}

function setLoading(value) {
  loading = value;
  document.querySelectorAll("[data-sample], #start-demo").forEach((button) => {
    button.disabled = value;
  });
  $("capture-file").disabled = value;
  $("main").setAttribute("aria-busy", String(value));
}

async function analyze(url, options = {}) {
  if (loading) return;
  setLoading(true);
  setStatus("Reading capture and building the evidence report…", "loading");
  try {
    const response = await fetch(url, options);
    const data = await response.json();
    if (!response.ok) {
      const detail =
        typeof data.detail === "string"
          ? data.detail
          : "This capture could not be analyzed. Check that it is a valid classic PCAP file.";
      throw new Error(detail);
    }
    if (!data.summary || !Array.isArray(data.conversations))
      throw new Error("The server returned an incomplete report.");
    report = data;
    sortKey = "packets";
    sortDirection = -1;
    renderReport();
    setStatus("");
  } catch (error) {
    setStatus(
      error instanceof TypeError
        ? "Unable to reach the local analyzer. Check that the Packet Trail server is running, then try again."
        : error.message,
      "error",
    );
  } finally {
    setLoading(false);
    $("capture-file").value = "";
  }
}

function analyzeFile(file) {
  if (!file || loading) return;
  if (file.size > MAX_BYTES)
    return setStatus(
      "This file exceeds the 8 MiB capture limit. Choose a smaller classic PCAP capture.",
      "error",
    );
  if (!file.name.toLowerCase().endsWith(".pcap"))
    return setStatus(
      "Choose a classic .pcap file. PCAPNG and compressed captures are not supported.",
      "error",
    );
  const body = new FormData();
  body.append("file", file);
  analyze("/api/analyze", { method: "POST", body });
}

function renderReport() {
  const summary = report.summary;
  const flags = report.flags || [];
  $("empty-state").hidden = true;
  $("report").hidden = false;
  $("export-json").disabled = false;
  text($("capture-name"), report.name || "Untitled capture");
  text(
    $("capture-meta"),
    `${timestamp(summary.first_seen)} · Classic PCAP · ${count(summary.packet_count)} packets`,
  );
  text($("metric-packets"), count(summary.packet_count));
  text($("metric-ipv4"), `${count(summary.ipv4_packets)} IPv4 packets`);
  text($("metric-bytes"), formatBytes(summary.captured_bytes));
  text($("metric-wire"), `${formatBytes(summary.wire_bytes)} reported on wire`);
  text($("metric-duration"), formatDuration(summary.duration_seconds));
  text(
    $("metric-rate"),
    summary.duration_seconds > 0
      ? `${(summary.packet_count / summary.duration_seconds).toFixed(1)} packets / second on average`
      : "Single timestamp capture",
  );
  text($("metric-flags"), count(flags.length));
  text($("signal-count"), count(flags.length));
  renderTimeline(report.series || []);
  renderProtocols(report.protocols || []);
  renderFlags(flags);
  renderConversations();
  renderIssues();
}

function renderTimeline(series) {
  const container = $("timeline");
  container.replaceChildren();
  if (!series.length) {
    text(container, "No timestamped traffic is available.");
    return;
  }
  const svgNS = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(svgNS, "svg");
  svg.setAttribute("viewBox", "0 0 560 160");
  svg.setAttribute("preserveAspectRatio", "none");
  const max = Math.max(...series.map((point) => Number(point.packets)), 1);
  const baseline = 143;
  const left = 30;
  const width = 519;
  const height = 119;
  for (let step = 0; step <= 3; step++) {
    const y = baseline - (height * step) / 3;
    const line = document.createElementNS(svgNS, "line");
    Object.entries({
      x1: left,
      y1: y,
      x2: 555,
      y2: y,
      stroke: "#eaf0ed",
      "stroke-width": ".7",
      "stroke-dasharray": "3 4",
    }).forEach(([key, value]) => line.setAttribute(key, value));
    svg.append(line);
    const label = document.createElementNS(svgNS, "text");
    Object.entries({
      x: 0,
      y: y + 2,
      fill: "#a3b3b0",
      "font-size": "7",
      "font-family": "sans-serif",
    }).forEach(([key, value]) => label.setAttribute(key, value));
    text(label, Math.round((max * step) / 3));
    svg.append(label);
  }
  const xAt = (index) =>
    left +
    (series.length === 1 ? width / 2 : (index * width) / (series.length - 1));
  const pathFor = (key) =>
    series
      .map(
        (point, index) =>
          `${index ? "L" : "M"}${xAt(index).toFixed(2)},${(baseline - (Number(point[key] || 0) / max) * height).toFixed(2)}`,
      )
      .join(" ");
  const area = document.createElementNS(svgNS, "path");
  area.setAttribute(
    "d",
    `${pathFor("packets")} L${xAt(series.length - 1)},${baseline} L${xAt(0)},${baseline} Z`,
  );
  area.setAttribute("fill", "#e9f3ee");
  svg.append(area);
  [
    ["packets", "#5a9e89"],
    ["syn_packets", "#d4a363"],
  ].forEach(([key, color]) => {
    const path = document.createElementNS(svgNS, "path");
    Object.entries({
      d: pathFor(key),
      fill: "none",
      stroke: color,
      "stroke-width": "1.8",
      "stroke-linejoin": "round",
      "stroke-linecap": "round",
    }).forEach(([attribute, value]) => path.setAttribute(attribute, value));
    svg.append(path);
    if (series.length === 1) {
      const circle = document.createElementNS(svgNS, "circle");
      Object.entries({
        cx: xAt(0),
        cy: baseline - (Number(series[0][key] || 0) / max) * height,
        r: 3,
        fill: color,
      }).forEach(([attribute, value]) => circle.setAttribute(attribute, value));
      svg.append(circle);
    }
  });
  container.append(svg);
  container.setAttribute(
    "aria-label",
    `${series.length} time buckets. Peak ${count(max)} packets per bucket. Green shows all packets; amber shows TCP SYN packets.`,
  );
  text($("chart-start"), timestamp(series[0].timestamp, true));
  text($("chart-end"), timestamp(series[series.length - 1].timestamp, true));
}

function renderProtocols(protocols) {
  const total = protocols.reduce((sum, item) => sum + Number(item.packets), 0);
  const container = $("protocol-chart");
  container.replaceChildren();
  let cursor = 0;
  const segments = protocols.map((item, index) => {
    const start = cursor;
    cursor += total ? (Number(item.packets) / total) * 100 : 0;
    return `${COLORS[index % COLORS.length]} ${start}% ${cursor}%`;
  });
  const donut = document.createElement("div");
  donut.className = "donut";
  donut.style.background = segments.length
    ? `conic-gradient(${segments.join(",")})`
    : "#edf2ef";
  const center = document.createElement("span");
  center.className = "donut-center";
  const strong = document.createElement("strong");
  text(strong, count(protocols.length));
  const small = document.createElement("small");
  text(small, "PROTOCOLS");
  center.append(strong, small);
  container.append(donut, center);
  container.setAttribute(
    "aria-label",
    protocols
      .map((item) => `${item.name}: ${count(item.packets)} packets`)
      .join(". ") || "No protocols available",
  );
  const list = $("protocol-list");
  list.replaceChildren();
  protocols.forEach((item, index) => {
    const row = document.createElement("div");
    row.className = "protocol-row";
    const dot = document.createElement("i");
    dot.style.backgroundColor = COLORS[index % COLORS.length];
    const name = document.createElement("strong");
    text(name, item.name);
    const packets = document.createElement("span");
    text(packets, `${count(item.packets)} packets`);
    const percent = document.createElement("b");
    text(percent, `${total ? ((item.packets / total) * 100).toFixed(0) : 0}%`);
    row.append(dot, name, packets, percent);
    list.append(row);
  });
}

function readableKey(key) {
  return key.replaceAll("_", " ");
}

function renderFlags(flags) {
  const list = $("flag-list");
  list.replaceChildren();
  if (!flags.length) {
    const empty = document.createElement("div");
    empty.className = "no-flags";
    empty.innerHTML =
      '<span aria-hidden="true">✓</span><div>No configured heuristic thresholds were crossed.<small>This does not establish that the traffic is benign.</small></div>';
    list.append(empty);
  }
  flags.forEach((flag) => {
    const card = document.createElement("article");
    card.className = "flag";
    const icon = document.createElement("span");
    icon.className = "flag-icon";
    icon.setAttribute("aria-hidden", "true");
    icon.innerHTML =
      '<svg viewBox="0 0 24 24" fill="none"><path d="m12 3 10 17H2L12 3Z"/><path d="M12 9v5m0 3v.1"/></svg>';
    const body = document.createElement("div");
    const heading = document.createElement("h3");
    text(heading, flag.title);
    const detail = document.createElement("p");
    text(detail, flag.detail);
    body.append(heading, detail);
    if (flag.evidence) {
      const evidence = document.createElement("div");
      evidence.className = "flag-evidence";
      const entries =
        typeof flag.evidence === "object"
          ? Object.entries(flag.evidence).map(
              ([key, value]) =>
                `${readableKey(key)}: ${typeof value === "object" ? JSON.stringify(value) : value}`,
            )
          : [String(flag.evidence)];
      entries.forEach((entry) => {
        const chip = document.createElement("span");
        chip.className = "evidence-chip";
        text(chip, entry);
        evidence.append(chip);
      });
      body.append(evidence);
    }
    const level = document.createElement("span");
    level.className = "flag-level";
    text(level, (flag.severity || "REVIEW").toUpperCase());
    card.append(icon, body, level);
    list.append(card);
  });
}

function endpointCell(address, port) {
  const cell = document.createElement("td");
  cell.className = "endpoint";
  text(cell, address || "—");
  if (port !== null && port !== undefined) {
    const label = document.createElement("span");
    label.className = "endpoint-port";
    text(label, `:${port}`);
    cell.append(label);
  }
  return cell;
}

function sortedConversations() {
  return [...report.conversations].sort((a, b) => {
    const left = a[sortKey];
    const right = b[sortKey];
    return (
      (typeof left === "number"
        ? left - right
        : String(left || "").localeCompare(String(right || ""), undefined, {
            numeric: true,
          })) * sortDirection
    );
  });
}

function renderConversations() {
  const rows = $("conversation-rows");
  rows.replaceChildren();
  const query = $("conversation-search").value.trim().toLowerCase();
  const visible = sortedConversations().filter((row) =>
    [
      row.source,
      row.destination,
      row.source_port,
      row.destination_port,
      row.protocol,
    ].some((value) =>
      String(value ?? "")
        .toLowerCase()
        .includes(query),
    ),
  );
  visible.forEach((conversation) => {
    const row = document.createElement("tr");
    row.append(
      endpointCell(conversation.source, conversation.source_port),
      endpointCell(conversation.destination, conversation.destination_port),
    );
    const protocolCell = document.createElement("td");
    const tag = document.createElement("span");
    tag.className = `protocol-tag ${String(conversation.protocol).toLowerCase() === "udp" ? "udp" : ""}`;
    text(tag, conversation.protocol);
    protocolCell.append(tag);
    row.append(protocolCell);
    ["packets", "bytes", "syn_packets"].forEach((key) => {
      const cell = document.createElement("td");
      cell.className = `numeric ${key === "syn_packets" && conversation[key] ? "syn-value" : ""}`;
      text(
        cell,
        key === "bytes"
          ? formatBytes(conversation[key])
          : count(conversation[key]),
      );
      row.append(cell);
    });
    rows.append(row);
  });
  if (!visible.length) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 6;
    text(
      cell,
      query
        ? "No conversations match this filter."
        : "No supported IPv4 conversations were found in this capture.",
    );
    row.append(cell);
    rows.append(row);
  }
  text($("conversation-count"), count(report.conversations.length));
  text(
    $("table-count"),
    `${count(visible.length)} of ${count(report.conversations.length)} shown · ${count(report.conversation_count)} total directional conversations`,
  );
  document.querySelectorAll("[data-sort]").forEach((button) => {
    const active = button.dataset.sort === sortKey;
    if (active)
      button
        .closest("th")
        .setAttribute(
          "aria-sort",
          sortDirection === 1 ? "ascending" : "descending",
        );
    else button.closest("th").removeAttribute("aria-sort");
    text(
      button.querySelector("span"),
      active ? (sortDirection === 1 ? "↑" : "↓") : "↕",
    );
  });
}

function renderIssues() {
  const summary = report.summary;
  const issues = report.issues || [];
  const hasNotes =
    issues.length ||
    summary.malformed_packets ||
    summary.truncated_packets ||
    summary.unsupported_packets;
  $("parsing-notes").hidden = !hasNotes;
  text(
    $("parsing-summary"),
    `${count(summary.unsupported_packets)} unsupported · ${count(summary.malformed_packets)} malformed · ${count(summary.truncated_packets)} truncated packets. Counts can overlap. Supported header evidence is retained where safely available.`,
  );
  const list = $("issue-list");
  list.replaceChildren();
  issues.forEach((issue) => {
    const item = document.createElement("li");
    text(item, `Packet ${issue.packet_index}: ${issue.reason}`);
    list.append(item);
  });
}

function download(contents, type, extension) {
  const blob = new Blob([contents], { type });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `${String(report.name || "capture")
    .replace(/\.[^.]+$/, "")
    .replace(/[^a-zA-Z0-9_-]/g, "_")}-report.${extension}`;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

document.querySelectorAll("[data-sample]").forEach((button) => {
  button.addEventListener("click", () =>
    analyze(
      `/api/samples/${encodeURIComponent(button.dataset.sample)}/analyze`,
    ),
  );
});
$("start-demo").addEventListener("click", () =>
  analyze("/api/samples/normal/analyze"),
);
$("capture-file").addEventListener("change", (event) =>
  analyzeFile(event.target.files[0]),
);
const dropzone = $("dropzone");
["dragenter", "dragover"].forEach((name) =>
  dropzone.addEventListener(name, (event) => {
    event.preventDefault();
    if (!loading) dropzone.classList.add("dragging");
  }),
);
["dragleave", "drop"].forEach((name) =>
  dropzone.addEventListener(name, (event) => {
    event.preventDefault();
    dropzone.classList.remove("dragging");
  }),
);
dropzone.addEventListener("drop", (event) => {
  if (event.dataTransfer.files.length !== 1)
    return setStatus("Choose one PCAP capture at a time.", "error");
  analyzeFile(event.dataTransfer.files[0]);
});
$("export-json").addEventListener("click", () => {
  if (report)
    download(JSON.stringify(report, null, 2), "application/json", "json");
});
$("export-csv").addEventListener("click", () => {
  if (!report) return;
  const keys = [
    "source",
    "source_port",
    "destination",
    "destination_port",
    "protocol",
    "packets",
    "bytes",
    "syn_packets",
  ];
  const quote = (value) => `"${String(value ?? "").replaceAll('"', '""')}"`;
  const csv = [
    keys.join(","),
    ...sortedConversations().map((row) =>
      keys.map((key) => quote(row[key])).join(","),
    ),
  ].join("\r\n");
  download(csv, "text/csv;charset=utf-8", "csv");
});
document.querySelectorAll("[data-sort]").forEach((button) =>
  button.addEventListener("click", () => {
    if (!report) return;
    const key = button.dataset.sort;
    sortDirection =
      sortKey === key
        ? -sortDirection
        : ["packets", "bytes", "syn_packets"].includes(key)
          ? -1
          : 1;
    sortKey = key;
    renderConversations();
  }),
);
document.querySelectorAll(".nav-item").forEach((link) =>
  link.addEventListener("click", () => {
    document
      .querySelectorAll(".nav-item")
      .forEach((item) => item.classList.toggle("active", item === link));
  }),
);

$("conversation-search").addEventListener("input", () => {
  if (report) renderConversations();
});
