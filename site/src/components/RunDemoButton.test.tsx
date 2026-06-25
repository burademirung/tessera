import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { RunDemoButton } from './RunDemoButton';

beforeEach(() => vi.restoreAllMocks());

describe('RunDemoButton', () => {
  it('POSTs to the demo endpoint on click', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 202 }));
    vi.stubGlobal('fetch', fetchMock);
    render(<RunDemoButton endpoint="/api/telemetry/demo" />);
    fireEvent.click(screen.getByRole('button', { name: /run the demo/i }));
    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        '/api/telemetry/demo',
        expect.objectContaining({ method: 'POST' }),
      ),
    );
  });
  it('reports an error without throwing when the request fails', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('down')));
    render(<RunDemoButton endpoint="/api/telemetry/demo" />);
    fireEvent.click(screen.getByRole('button', { name: /run the demo/i }));
    await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent(/could not/i));
  });
});
