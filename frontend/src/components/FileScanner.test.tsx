import React from 'react';
import { render, screen } from '@testing-library/react';
import FileScanner from './FileScanner';

describe('FileScanner', () => {
  it('renders title and setup step', () => {
    render(<FileScanner />);
    const title = screen.queryByText(/VirusTotal File Scanner/i);
    expect(title).not.toBeNull();
  });
});
