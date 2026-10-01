const rows = document.getElementById("answer-rows");
const MAX_ROW = 12;

function addRow(answer, weight) {
  if (rows.children.length >= MAX_ROW) return;
  const div = document.createElement("div");
  div.className = "answer-row";
  const idx = rows.children.length + 1;
  div.innerHTML =
    '<span class="idx">Q' + idx + '</span>' +
    '<input class="input" name="answer" placeholder="Model answer text" value="' + esc(answer) + '" required />' +
    '<input class="input answer-weight" name="weight" type="number" min="0" step="0.5" placeholder="marks" value="' + esc(weight) + '" required />' +
    '<button type="button" class="iconbtn" title="Remove this answer" aria-label="Remove this answer">' +
    '<svg viewBox="0 0 24 24" width="16" height="16" aria-hidden="true"><path d="M6 6l12 12M18 6L6 18" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>' +
    '</button>';
  div.querySelector(".iconbtn").addEventListener("click", function () {
    div.remove();
    renumber();
  });
  rows.appendChild(div);
  renumber();
}

function renumber() {
  Array.from(rows.children).forEach(function (r, i) {
    r.querySelector(".idx").textContent = "Q" + (i + 1);
  });
}

function esc(s) {
  const d = document.createElement("div");
  d.textContent = s == null ? "" : String(s);
  return d.innerHTML;
}

addRow("", "");

document.getElementById("add-answer").addEventListener("click", function () {
  addRow("", "");
});

const fileInput = document.getElementById("file");
const chosen = document.getElementById("chosen");
const filezone = document.getElementById("filezone");

function showFile() {
  const f = fileInput.files[0];
  if (!f) return;
  chosen.hidden = false;
  chosen.textContent = f.name + "  /  " + (f.size / 1024).toFixed(1) + " KB";
}

document.getElementById("pick-file").addEventListener("click", function () {
  fileInput.click();
});
fileInput.addEventListener("change", showFile);

["dragenter", "dragover"].forEach(function (e) {
  filezone.addEventListener(e, function (ev) {
    ev.preventDefault();
    filezone.classList.add("filezone--dragover");
  });
});
["dragleave", "drop"].forEach(function (e) {
  filezone.addEventListener(e, function (ev) {
    ev.preventDefault();
    filezone.classList.remove("filezone--dragover");
  });
});
filezone.addEventListener("drop", function (ev) {
  if (ev.dataTransfer.files.length) {
    fileInput.files = ev.dataTransfer.files;
    showFile();
  }
});

const form = document.getElementById("grade-form");
const resultsBox = document.getElementById("results");
const statusPanel = document.getElementById("status-panel");
const statusRows = Array.from(document.querySelectorAll(".status-row"));
const statusNote = document.getElementById("status-note");
const errtop = document.getElementById("errtop");
const runBtn = document.getElementById("run-grade");

function setStep(i, state) {
  statusRows[i].dataset.state = state;
}

function stepLabel(i) {
  const prefix = [">> ", ".. ", ".. ", ".. "][i];
  const base = statusRows[i].querySelector("span:last-child").textContent.trim();
  return prefix + base;
}

async function advance() {
  await delay(260);
  setStep(0, "done");
  await delay(320);
  setStep(1, "active");
  statusNote.textContent = stepLabel(1) + " (OCR can take a while here)";
  await delay(420);
  setStep(1, "done");
  setStep(2, "active");
  statusNote.textContent = stepLabel(2);
  await delay(420);
  setStep(2, "done");
  setStep(3, "active");
  statusNote.textContent = stepLabel(3);
}

function delay(ms) {
  return new Promise(function (r) { setTimeout(r, ms); });
}

form.addEventListener("submit", async function (e) {
  e.preventDefault();
  errtop.hidden = true;
  errtop.textContent = "";
  resultsBox.hidden = true;
  resultsBox.innerHTML = "";

  const answers = Array.from(document.querySelectorAll('input[name="answer"]'))
    .map(function (i) { return i.value.trim(); })
    .filter(Boolean);
  const weights = Array.from(document.querySelectorAll('input[name="weight"]'))
    .map(function (i) { return parseFloat(i.value); });

  if (!fileInput.files[0]) {
    errtop.textContent = "Choose a sheet file first.";
    errtop.hidden = false;
    return;
  }
  if (!answers.length || answers.length !== weights.length) {
    errtop.textContent = "Give every model answer a weight.";
    errtop.hidden = false;
    return;
  }

  statusPanel.hidden = false;
  statusRows.forEach(function (r) { r.dataset.state = "pending"; });
  runBtn.disabled = true;
  setStep(0, "active");
  statusNote.textContent = stepLabel(0);
  (function () { advance(); })();

  const fd = new FormData();
  fd.append("file", fileInput.files[0]);
  answers.forEach(function (a) { fd.append("answers", a); });
  weights.forEach(function (w) { fd.append("weights", w); });
  const force = document.querySelector('input[name="force_ocr"]');
  if (force && force.checked) fd.append("force_ocr", "true");

  try {
    const res = await fetch("/upload", { method: "POST", body: fd });
    const body = await res.json();
    if (!res.ok) {
      setStep(0, "error");
      statusNote.textContent = body.error || "Grading failed.";
      return;
    }
    statusRows.forEach(function (r) { r.dataset.state = "done"; });
    statusPanel.hidden = true;
    renderResults(body);
    resultsBox.hidden = false;
  } catch (err) {
    setStep(0, "error");
    statusNote.textContent = "Request failed. Is the app running?";
  } finally {
    runBtn.disabled = false;
  }
});

function bandLabel(sim) {
  if (sim >= 80) return ["full mark", "band--full"];
  if (sim >= 70) return ["partial", "band--partial"];
  return ["below threshold", "band--low"];
}

function renderResults(body) {
  const maxTotal = body.results.reduce(function (s, r) { return s + r.max_score; }, 0);
  const html =
    '<div class="results-summary">' +
      '<span class="total">' + body.total_score + '</span>' +
      '<span class="of">of ' + maxTotal + ' marks · ' + body.page_count + ' page' + (body.page_count === 1 ? "" : "s") + '</span>' +
    '</div>' +
    '<div class="meta-chips">' +
      (body.page_details || []).map(function (p) {
        return '<span class="chip' + (p.method === "ocr" ? " chip--ocr" : "") + '">page ' + p.page_number + ' / ' + p.method + '</span>';
      }).join("") +
    '</div>' +
    '<div style="margin-top: 1.1rem;">' +
      body.results.map(function (r, i) {
        const band = bandLabel(r.similarity);
        return '<div class="result-row">' +
          '<div class="result-row__top">' +
            '<span class="result-row__q">Q' + (i + 1) + '</span>' +
            '<span class="band ' + band[1] + '">' + band[0] + '</span>' +
          '</div>' +
          '<div class="result-row__answer"><span class="mono">model:</span> ' + esc(r.model_answer) + '</div>' +
          '<div class="result-row__score">' + r.similarity + '% similar · ' + r.score + ' / ' + r.max_score + '</div>' +
        '</div>';
      }).join("") +
    '</div>' +
    (body.extracted_text
      ? '<div style="margin-top: 1.8rem;">' +
          '<div class="step-head"><span class="step-label">Extracted text</span></div>' +
          '<div class="text-block">' + esc(body.extracted_text) + '</div>' +
        '</div>'
      : '<p class="muted" style="margin-top: 1.4rem;">No text was extracted from this sheet. Check the file and try again.</p>') +
    '<p class="ledger__mono" style="margin-top: 1.4rem;">run saved to local history / dashboard</p>';
  resultsBox.innerHTML = html;
}
