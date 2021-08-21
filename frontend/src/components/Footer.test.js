import { render, screen } from '@testing-library/react';
import Footer from './Footer.js';

test('renders copyright text', () => {
  render(<Footer />);
  const copyrightElement = screen.getByText(/mesto russia/i);
  expect(copyrightElement).toBeInTheDocument();
});
