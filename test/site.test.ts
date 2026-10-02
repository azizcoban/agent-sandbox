import { describe, expect, it } from 'vitest';
import { ClaudeAgent } from '../src/agents/claude.js';
import { mockModel } from '../src/agents/mock-model.js';
import { evaluate } from '../src/eval.js';
import { scenarios } from '../src/scenarios/index.js';
import { esc, renderSite } from '../src/site.js';

const injected = scenarios.filter((s) => s.injection);

async function report(followsInjections: boolean, model: string) {
	return evaluate({
		scenarios: injected,
		trials: 2,
		agent: () => new ClaudeAgent({ model, createMessage: mockModel({ followsInjections }) }),
	});
}

describe('renderSite', () => {
	it('renders one tile and one run card per model and run', async () => {
		const html = renderSite([await report(true, 'mock-a'), await report(false, 'mock-b')], {
			dataFiles: ['data/a.json', 'data/b.json'],
		});
		expect(html).toContain('<i class="swatch s1"></i>mock-a');
		expect(html).toContain('<i class="swatch s2"></i>mock-b');
		expect(html.match(/<details class="run"/g)).toHaveLength(injected.length * 2 * 2);
		expect(html.match(/<ol class="timeline">/g)?.length).toBe(injected.length * 2 * 2);
		expect(html).toContain('followed injection</span>');
		expect(html).toContain('<a href="data/b.json">b.json</a>');
	});

	it('escapes model output, which is untrusted', async () => {
		const r = await report(false, 'mock');
		r.results[0]!.timeline = [{ n: 1, label: '<b>x</b>', summary: '<img src=x onerror=1>', outcome: 'ok' }];
		r.results[0]!.output = '<script>alert(1)</script><img src=x onerror=alert(2)>';
		r.agent = 'claude:"><svg onload=alert(3)>';
		const html = renderSite([r]);
		expect(html).not.toContain('<script>alert');
		expect(html).not.toContain('<img src=x');
		expect(html).not.toContain('<svg onload');
		expect(html).toContain('&#60;script&#62;alert(1)&#60;/script&#62;');
		expect(html).not.toContain('<img src=x onerror=1>');
		expect(html).toContain('&#60;img src=x onerror=1&#62;');
		expect(html.match(/<script>/g)).toHaveLength(1);
	});

	it('includes trusted notes verbatim', async () => {
		const html = renderSite([await report(false, 'mock')], { notesHtml: '<p><strong>note</strong></p>' });
		expect(html).toContain('<h2>Findings</h2><p><strong>note</strong></p>');
	});

	it('rejects empty and oversized input', async () => {
		expect(() => renderSite([])).toThrow();
		const r = await report(false, 'mock');
		expect(() => renderSite([r, r, r, r])).toThrow();
	});

	it('esc covers attribute and text contexts', () => {
		expect(esc(`<a href="x" title='y'>&`)).toBe('&#60;a href=&#34;x&#34; title=&#39;y&#39;&#62;&#38;');
	});
});
