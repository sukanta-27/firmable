// Swap server errors into the target so the error notice shows where the content would be;
// htmx's default drops every 4xx and 5xx body.
htmx.config.responseHandling = [
  { code: "204", swap: false },
  { code: "[23]..", swap: true },
  { code: "5..", swap: true, error: true },
  { code: "[4]..", swap: false, error: true },
];

document.addEventListener("click", (event) => {
  const button = event.target.closest("[data-copy]");
  if (!button) return;
  navigator.clipboard.writeText(button.dataset.copy).then(() => {
    const label = button.textContent;
    button.textContent = "Copied";
    setTimeout(() => { button.textContent = label; }, 2000);
  });
});
