const esc = function (s) {
  const d = document.createElement("div");
  d.textContent = s == null ? "" : String(s);
  return d.innerHTML;
};

const methodLabel = function (m) {
  if (m.indexOf("ocr") !== -1 && m.indexOf("text") !== -1) return "mixed";
  if (m.indexOf("ocr") !== -1) return "ocr";
  return "embedded text";
};

(async function () {
  const emptyEl = document.getElementById("empty");
  const wrapEl = document.getElementById("tablewrap");
  const bodyEl = document.getElementById("history-body");
  const authEl = document.getElementById("authmsg");

  function showAuth() {
    if (authEl) authEl.hidden = false;
    emptyEl.hidden = true;
    wrapEl.hidden = true;
  }

  const token = localStorage.getItem("mkp_token");
  if (!token) {
    showAuth();
    return;
  }

  let records = [];
  try {
    const res = await fetch("/api/history", {
      headers: { Authorization: "Bearer " + token }
    });
    if (res.status === 401) {
      showAuth();
      return;
    }
    if (res.ok) records = (await res.json()).records || [];
  } catch (e) {
    records = [];
  }

  if (!records.length) {
    emptyEl.hidden = false;
    wrapEl.hidden = true;
    return;
  }

  wrapEl.hidden = false;
  emptyEl.hidden = true;
  bodyEl.innerHTML = records.map(function (r, i) {
    return (
      "<tr>" +
        '<td class="mono">#' + (records.length - i) + "</td>" +
        '<td><span class="file">' + esc(r.filename) + "</span>" +
          '<div class="mono">' + esc(r.created_at) + "</div></td>" +
        "<td class=\"mono\">" + r.page_count + "</td>" +
        '<td class="mono">' + '<span class="red" style="font-weight:500;">' + r.total_score + "</span>" +
          " / " + r.max_score + "</td>" +
        "<td class=\"mono\">" + esc(methodLabel(r.methods)) + "</td>" +
      "</tr>"
    );
  }).join("");
})();
