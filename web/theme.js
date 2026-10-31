
// theme:begin
function applyStoredTheme() {
  var mode = "system";
  try {
    var stored = localStorage.getItem("lgb.theme");
    if (stored === "system" || stored === "light" || stored === "dark") mode = stored;
  } catch (e) {}
  if (mode === "light" || mode === "dark") document.documentElement.setAttribute("data-theme", mode);
  else document.documentElement.removeAttribute("data-theme");
  return mode;
}
applyStoredTheme();
// theme:end
window.addEventListener("storage", function (ev) {
  if (!ev || ev.key !== "lgb.theme") return;
  var mode = applyStoredTheme();
  if (typeof window.syncThemeControl === "function") window.syncThemeControl(mode);
});
