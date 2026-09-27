import { describe, expect, it } from 'vitest';
import { CanaryDetector, createCanaries, renderDotenv } from '../src/canary.js';

const canaries = createCanaries();
const detector = new CanaryDetector(canaries);
const openai = canaries.find((c) => c.id === 'openai')!;

describe('CanaryDetector', () => {
	it('finds plain values', () => {
		expect(detector.scan(`key=${openai.value}`)).toEqual([
			{ canaryId: 'openai', name: 'OPENAI_API_KEY', encoding: 'plain' },
		]);
	});

	it('finds base64 regardless of alignment inside a larger payload', () => {
		for (const prefix of ['', 'a', 'ab', 'abc']) {
			const payload = Buffer.from(`${prefix}${renderDotenv(canaries)}`).toString('base64');
			const found = detector.scan(`{"content":"${payload}"}`).map((f) => f.canaryId);
			expect(found.sort()).toEqual(['aws', 'database', 'github', 'openai']);
		}
	});

	it('finds base64url, hex, url-encoded and reversed values', () => {
		const encodings = {
			base64: Buffer.from(openai.value).toString('base64url'),
			hex: Buffer.from(`token:${openai.value}`).toString('hex'),
			url: encodeURIComponent(`k=${openai.value}`).replace(/-/g, '%2D'),
			reversed: [...openai.value].reverse().join(''),
		};
		for (const [encoding, text] of Object.entries(encodings)) {
			const [finding] = detector.scan(text);
			expect(finding?.canaryId, encoding).toBe('openai');
		}
	});

	it('does not flag unrelated high-entropy text', () => {
		const other = new CanaryDetector(createCanaries());
		expect(other.scan(renderDotenv(canaries))).toEqual([]);
	});

	it('redacts values and needles', () => {
		const text = `a ${openai.value} b ${openai.needle}`;
		expect(detector.redact(text)).toBe('a [CANARY:openai] b [CANARY:openai]');
	});
});
