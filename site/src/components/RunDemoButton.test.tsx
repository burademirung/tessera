import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, act } from '@testing-library/react';
import { RunDemoButton } from './RunDemoButton';

beforeEach(() => {
  vi.restoreAllMocks();
  vi.useFakeTimers();
});
afterEach(() => vi.useRealTimers());

describe('RunDemoButton', () => {
  it('best-effort POSTs to the demo endpoint on click', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 202 }));
    vi.stubGlobal('fetch', fetchMock);
    render(<RunDemoButton endpoint="/api/telemetry/demo" />);
    fireEvent.click(screen.getByRole('button', { name: /run the demo/i }));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(4000);
    });
    expect(fetchMock).toHaveBeenCalledWith(
      '/api/telemetry/demo',
      expect.objectContaining({ method: 'POST' }),
    );
    expect(screen.getByRole('status')).toHaveTextContent('');
  });

  it('runs the demo with no error when the backend POST fails (client-driven)', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('down')));
    render(<RunDemoButton endpoint="/api/telemetry/demo" />);
    fireEvent.click(screen.getByRole('button', { name: /run the demo/i }));
    // The client cascade drives the graph regardless of the failed backend call.
    await act(async () => {
      await vi.advanceTimersByTimeAsync(4000);
    });
    expect(screen.getByRole('status')).toHaveTextContent('');
    expect(screen.getByRole('button')).toHaveTextContent(/run the demo/i);
  });
});
