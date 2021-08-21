import { render, screen } from '@testing-library/react';
import Header from './Header.js';

test('renders header logo alt', () => {
  render(<Header />);
  const logoElement = screen.getByAltText(/на главную/i);
  expect(logoElement).toBeInTheDocument();
});
