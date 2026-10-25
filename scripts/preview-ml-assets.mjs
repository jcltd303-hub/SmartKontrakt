import { createReadStream } from "node:fs";
import { realpath, stat } from "node:fs/promises";
import { resolve, sep, extname } from "node:path";

/** Nitro's preview loader recompresses these large files at Brotli's default
 * quality on every request. Serve the real build assets before that loader.
 * Production Vercel continues to serve its ordinary static CDN assets.
 */
export function previewMlAssets(directory) {
  const root = realpath(directory).catch(() => null);
  return (req, res, next) => {
    const pathname = new URL(req.url ?? "/", "http://preview.invalid").pathname;
    if (
      !["GET", "HEAD"].includes(req.method) ||
      !(
        /^\/models\/[a-zA-Z0-9][a-zA-Z0-9._-]*\.(?:bin|json)$/.test(pathname) ||
        /^\/assets\/ort-wasm-[a-zA-Z0-9_-]+\.(?:wasm|mjs)$/.test(pathname)
      )
    )
      return next();
    void (async () => {
      const base = await root;
      if (!base) return next();
      let file, info;
      try {
        file = await realpath(resolve(base, "." + pathname));
        if (!file.startsWith(base + sep)) return next();
        info = await stat(file);
      } catch (error) {
        if (["ENOENT", "ENOTDIR"].includes(error.code)) return next();
        throw error;
      }
      if (!info.isFile()) return next();
      const mime = {
        ".wasm": "application/wasm",
        ".mjs": "text/javascript",
        ".json": "application/json",
      };
      res.setHeader("Content-Type", mime[extname(file)] ?? "application/octet-stream");
      res.setHeader("Content-Length", info.size);
      if (req.method === "HEAD") {
        res.end();
        return;
      }
      const stream = createReadStream(file);
      stream.on("error", (error) => res.destroy(error));
      res.once("close", () => stream.destroy());
      stream.pipe(res);
    })().catch(next);
  };
}
