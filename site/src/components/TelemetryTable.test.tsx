import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { act } from 'react';
import { TelemetryTable } from './TelemetryTable';
import { useTelemetryStore } from '../lib/telemetry-store';

beforeEach(() => useTelemetryStore.getState().reset());

describe('TelemetryTable', () => {
  it('renders an aria-live region announcing the latest event', () => {
    act(() => {
      useTelemetryStore.getState().ingest({
        v: 1, id: '1', ts: 1, node: 'aws', edge: 'edge-aws', phase: 'federation', label: 'STS exchange',
      });
    });
    render(<TelemetryTable />);
    const live = document.querySelector('[aria-live="polite"]');
    expect(live?.textContent).toMatch(/STS exchange/i);
  });
  it('renders a row per logged event (source-of-truth data surface)', () => {
    act(() => {
      useTelemetryStore.getState().ingest({
        v: 1, id: '1', ts: 1, node: 'aws', edge: 'edge-aws', phase: 'federation', label: 'STS exchange',
      });
    });
    render(<TelemetryTable />);
    expect(screen.getByRole('cell', { name: /STS exchange/i })).toBeInTheDocument();
  });
});
