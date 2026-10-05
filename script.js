const $ = (id) => document.getElementById(id);

function show(el, on) { el.hidden = !on; }

async function analyze() {
  const text = $("input").value.trim();
  show($("error"), false);
  if (!text) { $("error").textContent = "Please enter a URL or message."; show($("error"), true); return; }
  $("analyze").disabled = true; $("analyze").textContent = "Analyzing...";
  try {
    const res = await fetch("/api/analyze", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ text })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Request failed");
    renderResult(data);
    loadHistory();
  } catch (e) {
    $("error").textContent = e.message; show($("error"), true);
  } finally {
    $("analyze").disabled = false; $("analyze").textContent = "Analyze";
  }
}

function renderResult(r) {
  $("verdict").className = "verdict " + r.label;
  $("r-label").textContent = r.label;
  $("r-risk").textContent = r.risk.toUpperCase();
  $("r-conf").textContent = r.confidence + "%";
  $("r-bar").style.width = "0";
  setTimeout(() => ($("r-bar").style.width = r.confidence + "%"), 50);
  const ul = $("r-reasons"); ul.innerHTML = "";
  r.reasons.forEach((t) => { const li = document.createElement("li"); li.textContent = t; ul.appendChild(li); });
  $("r-rec").textContent = r.recommendation;
  show($("result"), true);
  $("result").scrollIntoView({ behavior: "smooth", block: "nearest" });
}

async function loadHistory() {
  const data = await (await fetch("/api/history")).json();
  $("s-total").textContent = data.stats.total;
  $("s-safe").textContent = data.stats.SAFE;
  $("s-susp").textContent = data.stats.SUSPICIOUS;
  $("s-phish").textContent = data.stats.PHISHING;
  const body = $("history"); body.innerHTML = "";
  if (!data.items.length) {
    body.innerHTML = '<tr><td colspan="6" class="muted">No scans yet.</td></tr>'; return;
  }
  data.items.forEach((it) => {
    const tr = document.createElement("tr");
    const cells = [it.id, it.time, it.input.length > 90 ? it.input.slice(0, 90) + "..." : it.input, null, it.risk, it.confidence + "%"];
    cells.forEach((c, i) => {
      const td = document.createElement("td");
      if (i === 2) td.className = "input";
      if (i === 3) { const s = document.createElement("span"); s.className = "tag " + it.label; s.textContent = it.label; td.appendChild(s); }
      else td.textContent = c;
      tr.appendChild(td);
    });
    body.appendChild(tr);
  });
}

$("analyze").addEventListener("click", analyze);
$("input").addEventListener("keydown", (e) => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) analyze(); });
document.querySelectorAll(".chip").forEach((b) => b.addEventListener("click", () => { $("input").value = b.dataset.s; $("input").focus(); }));
$("clear").addEventListener("click", async () => {
  if (confirm("Clear all analysis history?")) { await fetch("/api/clear", { method: "POST" }); loadHistory(); }
});
loadHistory();
