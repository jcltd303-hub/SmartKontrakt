import assert from 'node:assert/strict';
import test from 'node:test';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { createServer } from 'vite';

test('evidence badges render their stage and explanation for assistive and visual readers', async () => {
  const server = await createServer({ configFile: false, optimizeDeps: { noDiscovery: true }, server: { middlewareMode: true }, appType: 'custom' });
  try {
    const { PocEvidenceBadge } = await server.ssrLoadModule('/src/components/poc-evidence-badge.tsx');
    for (const [stage, label] of [['template', 'Template'], ['generated', 'Generated PoC'], ['reproduced', 'Reproduced']]) {
      const html = renderToStaticMarkup(createElement(PocEvidenceBadge, { evidence: { stage, label, description: 'Evidence explanation <untrusted>' } }));
      assert.ok(html.includes(`data-poc-evidence="${stage}"`));
      assert.ok(html.includes(label));
      assert.ok(html.includes('Evidence explanation &lt;untrusted&gt;'));
    }
  } finally { await server.close(); }
});
