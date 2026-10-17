// Run button: POST /proof/run, then reload to show the server-rendered result.
(function () {
  var btn = document.getElementById("run");
  var status = document.getElementById("run-status");
  if (!btn) return;
  btn.addEventListener("click", function () {
    btn.disabled = true;
    status.textContent = "Running real API calls for each signed-in user…";
    fetch("/proof/run", { method: "POST", headers: { "X-Proof-Run": "1" } })
      .then(function (r) {
        if (!r.ok) return r.json().then(function (b) { throw new Error(b.detail || ("HTTP " + r.status)); });
        location.reload();
      })
      .catch(function (e) {
        status.textContent = "Run failed: " + e.message;
        btn.disabled = false;
      });
  });
})();
