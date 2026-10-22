/**
 * Trigger a client-side download of a text file.
 *
 * Lives in its own module because react-refresh requires a component file to
 * export only components — a component file that also exports a helper makes
 * every edit to it do a full reload instead of a hot update.
 */
export function downloadFile(filename: string, content: string) {
  const blob = new Blob([content], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  // Revoke on the next tick so the download has started.
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
